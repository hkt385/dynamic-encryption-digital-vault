import base64
import dataclasses
import hashlib

import pytest

from conftest import db_bytes, new_vault
from services.key_management_service import KeyStoreError
from services.security_decision_service import FINAL, SecurityDecision
from services.vault_service import OperationError, VaultService

CONTENT = b"Confidential contents\n" * 200


def decision(level, account="Enterprise", **kw):
    kw.setdefault("acknowledged", True)
    return SecurityDecision(FINAL, account, predicted=level if level not in ("High", "Critical")
                            else "High/Critical", level=level, **kw)


@pytest.fixture
def vault(tmp_path):
    return new_vault(tmp_path / "DEDV")


@pytest.fixture
def src(tmp_path):
    p = tmp_path / "report.txt"
    p.write_bytes(CONTENT)
    return p


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def store(vault, src, level, account="Enterprise"):
    res = vault.store_files([(src, decision(level, account))], account)
    assert res.stored == [src.name], res.failed
    return vault.list_files()[-1]


def tokens(vault):
    with vault.db as conn:
        return [r[0] for r in conn.execute("SELECT token FROM keys.wrapped_keys")]


@pytest.mark.parametrize("level,algo", [
    ("Low", "AES-128-GCM"), ("Standard", "AES-256-GCM"), ("High", "CHACHA20-POLY1305"),
    ("Critical", "AES-256-GCM+ML-KEM-1024"), ("Enhanced", "AES-256-GCM+RSA-4096-OAEP")])
def test_store_uses_the_selected_level_and_can_be_read_back(vault, src, level, algo):
    before = sha(src)
    meta = store(vault, src, level)
    assert (meta.security_level, meta.algorithm) == (level, algo)
    assert sha(src) == before                                     # source untouched
    enc = vault.encrypted_dir / meta.encrypted_name
    assert CONTENT[:30] not in enc.read_bytes()
    enc_hash = sha(enc)
    _, data = vault.read_file(meta.file_id)
    assert data == CONTENT
    assert sha(enc) == enc_hash                                   # opening never modifies the file


@pytest.mark.parametrize("level", ["Standard", "Enhanced", "Critical"])
def test_metadata_holds_only_a_token_and_no_key_material_is_stored_in_clear(vault, src, level):
    meta = store(vault, src, level)
    key = vault.keys.release_key(meta.token, meta.file_id, vault.session)
    assert set(dataclasses.asdict(meta)) == {
        "file_id", "original_name", "file_type", "size_bytes", "date_added", "security_level",
        "encrypted_name", "predicted_level", "algorithm", "token", "confidence", "override",
        "model_inputs"}
    assert meta.token not in (meta.file_id, "") and meta.file_id not in meta.token
    stored = db_bytes(vault.vault_dir)
    for secret in list(key.secrets.values()) + [base64.b64decode(v) for v in key.params.values()]:
        # data key / RSA private key / ML-KEM seed, and the RSA-wrapped key / KEM ciphertext
        assert secret not in stored and base64.b64encode(secret) not in stored
    # The key record is in keys.db only; vault.db never mentions it beyond the token.
    assert not list(vault.vault_dir.rglob("*.json")) and not list(vault.vault_dir.rglob("*_key.txt"))


def test_enterprise_only_levels_rejected_for_personal(vault, src):
    for level in ("High", "Critical"):
        res = vault.store_files([(src, decision(level, "Personal"))], "Personal")
        assert res.stored == [] and res.failed
    assert vault.list_files() == [] and tokens(vault) == []


def test_tampered_metadata_level_or_algorithm_is_refused(vault, src):
    """vault.db says something else than the sealed key record: the record wins, the read fails."""
    meta = store(vault, src, "Standard")
    with vault.db as conn:
        conn.execute("UPDATE files SET security_level='Critical' WHERE file_id=?", (meta.file_id,))
    with pytest.raises(OperationError, match="does not match its key record"):
        vault.read_file(meta.file_id)


def test_corrupted_and_missing_files_give_clear_errors(vault, src):
    meta = store(vault, src, "High")
    path = vault.encrypted_dir / meta.encrypted_name
    path.write_bytes(path.read_bytes()[:-5] + b"xxxxx")
    with pytest.raises(OperationError, match="corrupted"):
        vault.read_file(meta.file_id)
    path.unlink()
    with pytest.raises(OperationError, match="missing from the vault"):
        vault.read_file(meta.file_id)
    with pytest.raises(OperationError, match="no longer in the vault"):
        vault.read_file("does-not-exist")


# ---- re-encryption ---------------------------------------------------------------------------
@pytest.mark.parametrize("start,target", [("Standard", "High"), ("High", "Critical"), ("Enhanced", "Critical"),
                                          ("Low", "Enhanced")])
def test_reencrypt_really_changes_algorithm_and_keeps_content(vault, src, start, target):
    meta = store(vault, src, start)
    old_path = vault.encrypted_dir / meta.encrypted_name
    old_bytes = old_path.read_bytes()
    new = vault.reencrypt(meta.file_id, target, "Enterprise")
    assert new.security_level == target and new.algorithm != meta.algorithm
    assert new.file_id == meta.file_id and new.original_name == meta.original_name
    new_path = vault.encrypted_dir / new.encrypted_name
    assert new_path.read_bytes() != old_bytes and not old_path.exists()
    assert vault.read_file(meta.file_id)[1] == CONTENT
    listed = vault.list_files()
    assert len(listed) == 1 and listed[0].algorithm == new.algorithm
    assert new.token != meta.token and tokens(vault) == [new.token]      # new token; old record removed
    with pytest.raises(KeyStoreError, match="No key is stored"):
        vault.keys.release_key(meta.token, meta.file_id, vault.session)
    assert not [p for p in vault.encrypted_dir.iterdir() if p.suffix != ".enc"]   # no .part leftovers
    assert sorted(p.name for p in vault.encrypted_dir.iterdir()) == [new.encrypted_name]


def test_reencrypt_to_same_level_or_forbidden_level_is_refused(vault, src):
    meta = store(vault, src, "Standard")
    with pytest.raises(OperationError, match="already"):
        vault.reencrypt(meta.file_id, "Standard", "Enterprise")
    with pytest.raises(OperationError, match="not an allowed"):
        vault.reencrypt(meta.file_id, "High", "Personal")
    with pytest.raises(OperationError, match="not an allowed"):
        vault.reencrypt(meta.file_id, "Critical", "Personal")
    with pytest.raises(OperationError, match="not an allowed"):
        vault.reencrypt(meta.file_id, "High/Critical", "Enterprise")
    assert vault.list_files()[0].algorithm == "AES-256-GCM"


# ---- upward-only override (enforced here, not only in the UI) --------------------------------
def test_store_records_the_decision(vault, src):
    inputs = {"Sensitivity": "High", "Who Should Access": "Only me"}
    d = decision("Standard", confidence=0.83, params=inputs)
    d.raise_level("Critical")
    vault.store_files([(src, d)], "Enterprise")
    vault.close()
    m = VaultService(vault.vault_dir).list_files()[0]                # read back from vault.db
    assert (m.predicted_level, m.confidence, m.security_level, m.override, m.model_inputs) == (
        "Standard", 0.83, "Critical", True, inputs)
    assert list(m.model_inputs) == list(inputs)                      # input order kept


@pytest.mark.parametrize("kw", [dict(predicted="Enhanced", level="Enhanced"),
                                dict(predicted="Low", level="Low", confidence=0.69)])
def test_store_refuses_an_unacknowledged_review(vault, src, kw):
    d = SecurityDecision(FINAL, "Enterprise", **kw)
    res = vault.store_files([(src, d)], "Enterprise")
    assert res.stored == [] and "Acknowledge" in res.failed[0][1]
    d.acknowledged = True
    assert vault.store_files([(src, d)], "Enterprise").stored == [src.name]


@pytest.mark.parametrize("account,predicted,level", [
    ("Enterprise", "Standard", "Low"), ("Enterprise", "High/Critical", "Enhanced"),
    ("Personal", "Enhanced", "Standard")])
def test_store_refuses_a_level_below_the_prediction(vault, src, account, predicted, level):
    d = SecurityDecision(FINAL, account, predicted=predicted, level=level, acknowledged=True)
    res = vault.store_files([(src, d)], account)
    assert res.stored == [] and "raised but not lowered" in res.failed[0][1]
    assert vault.list_files() == [] and tokens(vault) == []


def test_reencrypt_never_goes_below_the_prediction(vault, src):
    meta = store(vault, src, "Standard")
    with pytest.raises(OperationError, match="below the predicted level Standard"):
        vault.reencrypt(meta.file_id, "Low", "Enterprise")
    assert vault.reencrypt(meta.file_id, "Critical", "Enterprise").override
    back = vault.reencrypt(meta.file_id, "Standard", "Enterprise")   # back to the prediction is allowed
    assert not back.override and vault.read_file(meta.file_id)[1] == CONTENT


def test_high_critical_prediction_floor_is_high(vault, src):
    meta = store(vault, src, "Critical")
    with pytest.raises(OperationError, match="below the predicted level High/Critical"):
        vault.reencrypt(meta.file_id, "Enhanced", "Enterprise")
    new = vault.reencrypt(meta.file_id, "High", "Enterprise")
    assert new.security_level == "High" and not new.override


def test_file_without_a_prediction_keeps_its_current_level_as_floor(vault, src):
    meta = store(vault, src, "Standard")
    with vault.db as conn:                                    # as an upgraded 0.1 entry may be
        conn.execute("UPDATE files SET predicted_level='' WHERE file_id=?", (meta.file_id,))
    with pytest.raises(OperationError, match="current level Standard"):
        vault.reencrypt(meta.file_id, "Low", "Enterprise")
    assert vault.reencrypt(meta.file_id, "Enhanced", "Enterprise").security_level == "Enhanced"


def _assert_untouched(vault, meta, old_bytes):
    cur = vault.list_files()
    assert len(cur) == 1 and cur[0] == meta
    assert (vault.encrypted_dir / meta.encrypted_name).read_bytes() == old_bytes
    assert vault.read_file(meta.file_id)[1] == CONTENT
    assert [p.name for p in vault.encrypted_dir.iterdir()] == [meta.encrypted_name]   # no orphans
    assert tokens(vault) == [meta.token]                                              # no orphan key record


def test_failure_during_encryption_preserves_original(vault, src, monkeypatch):
    meta = store(vault, src, "Standard")
    old = (vault.encrypted_dir / meta.encrypted_name).read_bytes()
    from services import encryption_service as es
    monkeypatch.setattr(es.chacha, "encrypt_bytes", lambda *a: (_ for _ in ()).throw(OSError("disk full")))
    with pytest.raises(Exception):
        vault.reencrypt(meta.file_id, "High", "Enterprise")
    _assert_untouched(vault, meta, old)


def test_failure_of_metadata_update_rolls_back_files_and_keys(vault, src, monkeypatch):
    meta = store(vault, src, "Standard")
    old = (vault.encrypted_dir / meta.encrypted_name).read_bytes()
    from services.storage_service import StorageError

    def boom(_):
        raise StorageError("Could not update the vault index: disk full")
    monkeypatch.setattr(vault.repo, "update_file", boom)
    with pytest.raises(OperationError, match="original file is unchanged"):
        vault.reencrypt(meta.file_id, "High", "Enterprise")
    _assert_untouched(vault, meta, old)


def test_failure_storing_new_key_rolls_back(vault, src, monkeypatch):
    meta = store(vault, src, "Standard")
    old = (vault.encrypted_dir / meta.encrypted_name).read_bytes()

    def boom(*a):
        raise KeyStoreError("The key store could not be written: denied")
    with monkeypatch.context() as m:
        m.setattr(vault.keys, "store_key", boom)
        with pytest.raises(OperationError, match="original file is unchanged"):
            vault.reencrypt(meta.file_id, "Enhanced", "Enterprise")
    _assert_untouched(vault, meta, old)


def test_failure_after_the_new_key_was_stored_rolls_the_key_back_too(vault, src, monkeypatch):
    """The swap is one transaction: a failure in its last step undoes the first ones."""
    meta = store(vault, src, "Standard")
    old = (vault.encrypted_dir / meta.encrypted_name).read_bytes()
    with monkeypatch.context() as m:
        m.setattr(vault.keys, "delete", lambda t: (_ for _ in ()).throw(KeyStoreError("denied")))
        with pytest.raises(OperationError, match="original file is unchanged"):
            vault.reencrypt(meta.file_id, "High", "Enterprise")
    _assert_untouched(vault, meta, old)


def test_failed_verification_preserves_original(vault, src, monkeypatch):
    meta = store(vault, src, "Low")
    old = (vault.encrypted_dir / meta.encrypted_name).read_bytes()
    with monkeypatch.context() as m:
        m.setattr(vault.encryption, "decrypt_bytes",
                  lambda path, *a: CONTENT if path.name == meta.encrypted_name else b"wrong")
        with pytest.raises(OperationError, match="Verification"):
            vault.reencrypt(meta.file_id, "High", "Enterprise")
    _assert_untouched(vault, meta, old)


def test_unreadable_original_never_reencrypts(vault, src):
    meta = store(vault, src, "Standard")
    (vault.encrypted_dir / meta.encrypted_name).write_bytes(b"garbage" * 10)
    with pytest.raises(OperationError):
        vault.reencrypt(meta.file_id, "High", "Enterprise")
    assert vault.list_files()[0] == meta


def test_no_plaintext_on_disk_during_reencrypt(vault, src, tmp_path):
    meta = store(vault, src, "Standard")
    vault.reencrypt(meta.file_id, "Critical", "Enterprise")
    for p in tmp_path.rglob("*"):
        if p.is_file() and p != src and p.name != "vault.lock":      # the lock file is locked, and empty
            assert CONTENT[:30] not in p.read_bytes(), p
