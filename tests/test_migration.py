"""Upgrade of a DEDV 0.1 vault (JSON index, JSON key stores, plaintext key file) to 0.2."""
import json
from pathlib import Path

import pytest

from conftest import PASSWORD, db_bytes
from legacy import write_legacy_vault
from paths import key_dir
from services import migration_service
from services.auth_service import AuthError
from services.migration_service import MigrationVerifyError
from services.storage_service import KEYS_DB, VAULT_DB, StorageError
from services.vault_service import OperationError, VaultService

CONTENT = b"legacy contents\n" * 50
LEVELS = ("Low", "Standard", "Enhanced", "High", "Critical", None)   # None = pre-algorithm entry
JSON_FILES = ("metadata/files.json", "config/wrapped_keys.json", "config/dev_keys.json")


@pytest.fixture
def legacy(tmp_path):
    vault_dir = tmp_path / "DEDV"
    entries = [(f"{lv or 'old'}.txt", lv, CONTENT + (lv or "old").encode()) for lv in LEVELS]
    return vault_dir, write_legacy_vault(vault_dir, key_dir(), entries)


def snapshot(vault_dir):
    return {p: p.read_bytes() for p in Path(vault_dir).rglob("*") if p.is_file() and p.name != "vault.lock"}


def key_file():
    return key_dir() / "DEDV_key.txt"


def test_old_vault_is_detected_and_nothing_happens_before_a_password_is_given(legacy):
    vault_dir, _ = legacy
    before = snapshot(vault_dir)
    vault = VaultService(vault_dir)
    assert vault.needs_migration and vault.session is None
    with pytest.raises(AuthError, match="at least 12"):
        vault.migrate("short")
    assert snapshot(vault_dir) == before


def test_full_upgrade_keeps_every_file_readable(legacy):
    vault_dir, index = legacy
    old_wrapped = (vault_dir / "config/wrapped_keys.json").read_bytes()
    plain_keys = [v.encode() for v in json.loads((vault_dir / "config/dev_keys.json").read_text()).values()]
    ciphertext = snapshot(vault_dir / "encrypted_files")
    old_key_text = key_file().read_text()

    vault = VaultService(vault_dir)
    result = vault.migrate(PASSWORD)
    assert result.files == len(LEVELS) and result.unverified == []
    assert not vault.needs_migration and vault.session.is_unlocked
    files = vault.list_files()
    assert [m.file_id for m in files] == [d["file_id"] for d in index]
    for m, d in zip(files, index):
        assert vault.read_file(m.file_id)[1] == CONTENT + Path(m.original_name).stem.encode()
        assert m.token and m.token != d["file_id"]                     # a new opaque token
        assert (m.security_level, m.algorithm) == (d["security_level"], d.get("algorithm") or "AES-256-GCM")
    assert snapshot(vault_dir / "encrypted_files") == ciphertext       # ciphertext never touched

    # Originals: index and wrapped store kept as .bak, plaintext keys wiped, key file left for the user.
    assert json.loads((vault_dir / "metadata/files.json.migrated.bak").read_text()) == index
    assert (vault_dir / "config/wrapped_keys.json.migrated.bak").read_bytes() == old_wrapped
    assert not list(vault_dir.rglob("dev_keys.json*"))
    stored = b"".join(snapshot(vault_dir).values())
    assert all(k not in stored for k in plain_keys)                    # no plaintext key anywhere in the vault
    assert not any((vault_dir / n).exists() for n in JSON_FILES)
    assert key_file().read_text() == old_key_text                      # never deleted automatically
    assert (result.backup_dir / "metadata/files.json").exists() and result.backup_dir.parent.name == "backup"
    assert ("migration", "OK") in [(r["action"], r["result"]) for r in vault.audit.entries()]
    assert vault.audit.verify()[0]

    # The password, not the old key file, now protects the vault.
    vault.close()
    key_file().unlink()
    vault = VaultService(vault_dir)
    assert not vault.needs_migration
    with pytest.raises(AuthError, match="Wrong password"):
        vault.session.unlock("not the password")
    vault.session.unlock(PASSWORD)
    assert all(vault.read_file(m.file_id)[1].startswith(CONTENT) for m in vault.list_files())
    vault.lock()
    vault.session.reset_with_recovery_key(result.recovery_key, "the next password!")
    assert vault.read_file(files[0].file_id)[1].startswith(CONTENT)


def test_upgraded_files_can_be_reencrypted(legacy):
    vault_dir, index = legacy
    vault = VaultService(vault_dir)
    vault.migrate(PASSWORD)
    old = vault.list_files()[-1]                                       # the pre-algorithm entry
    assert old.predicted_level == "" and old.algorithm == "AES-256-GCM"
    new = vault.reencrypt(old.file_id, "High", "Enterprise")
    assert new.algorithm == "CHACHA20-POLY1305" and vault.read_file(old.file_id)[1] == CONTENT + b"old"


def test_upgraded_files_keep_the_upward_only_rule(legacy):
    """0.1 let the Edit page lower a level. Such a file keeps its prediction as the floor; a file
    without a stored prediction keeps its current level as the floor."""
    vault_dir, index = legacy
    index[0]["predicted_level"] = "High/Critical"                      # Low.txt: lowered in 0.1
    (vault_dir / "metadata/files.json").write_text(json.dumps(index), encoding="utf-8")
    vault = VaultService(vault_dir)
    vault.migrate(PASSWORD)
    lowered, old = vault.list_files()[0], vault.list_files()[-1]
    assert (lowered.security_level, lowered.override, lowered.confidence, lowered.model_inputs) == (
        "Low", True, None, {})                                         # nothing invented for 0.1 files
    with pytest.raises(OperationError, match="below the predicted level High/Critical"):
        vault.reencrypt(lowered.file_id, "Enhanced", "Enterprise")
    assert not vault.reencrypt(lowered.file_id, "High", "Enterprise").override
    with pytest.raises(OperationError, match="current level Standard"):
        vault.reencrypt(old.file_id, "Low", "Enterprise")


@pytest.mark.parametrize("fail_at", ["store_key", "release_key", "rename"])
def test_forced_failure_half_way_rolls_back_cleanly(legacy, monkeypatch, fail_at):
    vault_dir, _ = legacy
    before = snapshot(vault_dir)
    calls = {"n": 0}

    def boom_after_two(real):
        def wrapper(*a, **k):
            calls["n"] += 1
            if calls["n"] > 2:
                raise RuntimeError("simulated crash")
            return real(*a, **k)
        return wrapper

    from services.key_management_service import KeyManagementService
    vault = VaultService(vault_dir)
    expected = MigrationVerifyError if fail_at == "release_key" else StorageError
    with monkeypatch.context() as m:                                   # the fault exists only in this block
        if fail_at == "rename":
            m.setattr(migration_service.os, "replace",
                      lambda *a: (_ for _ in ()).throw(OSError("simulated rename failure")))
        else:
            m.setattr(KeyManagementService, fail_at, boom_after_two(getattr(KeyManagementService, fail_at)))
        with pytest.raises(expected, match="left unchanged"):
            vault.migrate(PASSWORD)
    assert snapshot(vault_dir) == before                               # no databases, .tmp, backup or renames
    assert not (vault_dir / "backup").exists() or not list((vault_dir / "backup").iterdir())
    assert vault.needs_migration and key_file().exists()
    vault.migrate(PASSWORD)                                            # and it can simply be retried
    assert len(vault.list_files()) == len(LEVELS)


def test_unverifiable_file_stops_the_upgrade_unless_the_user_accepts_a_partial_one(legacy):
    vault_dir, index = legacy
    victim = vault_dir / "encrypted_files" / index[3]["encrypted_name"]
    victim.write_bytes(victim.read_bytes()[:-4] + b"XXXX")             # already corrupt in the old vault
    before = snapshot(vault_dir)
    vault = VaultService(vault_dir)
    with pytest.raises(MigrationVerifyError) as e:
        vault.migrate(PASSWORD)
    assert [name for name, _ in e.value.failed] == ["High.txt"] and "corrupted" in e.value.failed[0][1]
    assert snapshot(vault_dir) == before and vault.needs_migration

    result = vault.migrate(PASSWORD, allow_unverified=True)
    assert [name for name, _ in result.unverified] == ["High.txt"]
    files = vault.list_files()
    assert len(files) == len(LEVELS)                                   # still listed
    with pytest.raises(OperationError, match="corrupted"):
        vault.read_file(files[3].file_id)
    assert vault.read_file(files[0].file_id)[1].startswith(CONTENT)
    # Partial upgrade: nothing old is wiped.
    assert (vault_dir / "config/dev_keys.json.migrated.bak").exists()
    assert (result.backup_dir / "config/dev_keys.json").exists() and key_file().exists()
    assert ("migration", "PARTIAL") in [(r["action"], r["result"]) for r in vault.audit.entries()]


@pytest.mark.parametrize("damage", ["missing", "wrong", "malformed"])
def test_unusable_old_key_file_is_reported_not_guessed(legacy, damage):
    vault_dir, _ = legacy
    if damage == "missing":
        key_file().unlink()
    elif damage == "wrong":
        from legacy import write_key_file
        write_key_file(key_dir())                                      # a different key
    else:
        key_file().write_text("garbage")
    before = snapshot(vault_dir)
    vault = VaultService(vault_dir)
    with pytest.raises(MigrationVerifyError) as e:
        vault.migrate(PASSWORD)
    assert len(e.value.failed) == 5                                    # every wrapped entry; not the plaintext one
    assert snapshot(vault_dir) == before
    assert (not key_file().exists()) if damage == "missing" else key_file().exists()   # none minted, none replaced


def test_old_key_file_is_deleted_only_on_request(legacy):
    vault_dir, _ = legacy
    VaultService(vault_dir).migrate(PASSWORD)
    assert migration_service.old_key_file() == key_file() and key_file().exists()
    migration_service.delete_old_key_file()
    assert not key_file().exists()
    migration_service.delete_old_key_file()                            # already gone: no error


def test_new_and_already_upgraded_vaults_do_not_need_migration(tmp_path, legacy):
    (tmp_path / "fresh").mkdir()
    assert not VaultService(tmp_path / "fresh" / "DEDV").needs_migration
    vault_dir, _ = legacy
    vault = VaultService(vault_dir)
    vault.migrate(PASSWORD)
    with pytest.raises(StorageError, match="does not need"):
        migration_service.migrate(vault_dir, PASSWORD)
    assert (vault_dir / VAULT_DB).exists() and (vault_dir / KEYS_DB).exists()
    assert PASSWORD.encode() not in db_bytes(vault_dir)
