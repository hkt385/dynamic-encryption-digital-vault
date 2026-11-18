import pytest

from conftest import PASSWORD, db_bytes, new_vault
from services.security_decision_service import FINAL, SecurityDecision
from services.vault_service import OperationError

CONTENT = b"UNIQUE-PLAINTEXT-MARKER " * 40


@pytest.fixture
def vault(tmp_path):
    return new_vault(tmp_path / "DEDV")


def store(vault, tmp_path, level="Standard"):
    src = tmp_path / "doc.txt"
    src.write_bytes(CONTENT)
    assert vault.store_files([(src, SecurityDecision(FINAL, "Enterprise", predicted=level, level=level))],
                             "Enterprise").stored
    return vault.list_files()[-1]


def rows(vault):
    return [(r["action"], r["result"], r["file_id"], r["level"]) for r in vault.audit.entries()]


def test_every_operation_is_logged_with_utc_time(vault, tmp_path):
    meta = store(vault, tmp_path)
    vault.read_file(meta.file_id)
    vault.log_external_open(meta.file_id)
    vault.reencrypt(meta.file_id, "High", "Enterprise")
    vault.lock()
    with pytest.raises(OperationError):
        vault.read_file(meta.file_id)
    vault.session.unlock(PASSWORD)
    f = meta.file_id
    assert rows(vault) == [
        ("password_set", "OK", "", ""), ("session_start", "OK", "", ""),
        ("store", "OK", f, "Standard"),
        ("key_release", "OK", f, "Standard"), ("read", "OK", f, "Standard"),
        ("open_external", "OK", f, "Standard"),
        ("key_release", "OK", f, "Standard"), ("reencrypt", "OK", f, "High"),
        ("lock", "OK", "", ""),
        ("key_release", "DENIED", f, ""), ("read", "FAILED", f, "High"),
        ("unlock", "OK", "", ""), ("session_start", "OK", "", ""),
    ]
    entries = vault.audit.entries()
    assert all(e["ts"].endswith("+00:00") for e in entries)             # UTC
    assert entries[7]["detail"] == "Standard -> High"
    assert vault.audit.verify() == (True, len(entries), None)


def test_log_never_contains_content_keys_or_passwords(vault, tmp_path):
    meta = store(vault, tmp_path)
    vault.read_file(meta.file_id)
    key = vault.keys.release_key(meta.token, meta.file_id, vault.session).secrets["key"]
    text = repr(vault.audit.entries()).encode()
    for secret in (b"UNIQUE-PLAINTEXT-MARKER", PASSWORD.encode(), key, key.hex().encode(), vault.session.vmk()):
        assert secret not in text
    assert b"UNIQUE-PLAINTEXT-MARKER" not in db_bytes(vault.vault_dir)


def test_failed_operations_are_logged_even_though_their_changes_roll_back(vault, tmp_path, monkeypatch):
    meta = store(vault, tmp_path)
    from services.storage_service import StorageError
    monkeypatch.setattr(vault.repo, "update_file", lambda m: (_ for _ in ()).throw(StorageError("disk full")))
    with pytest.raises(OperationError):
        vault.reencrypt(meta.file_id, "High", "Enterprise")
    assert rows(vault)[-2:] == [("key_release", "OK", meta.file_id, "Standard"),
                                ("reencrypt", "FAILED", meta.file_id, "Standard")]
    assert vault.audit.verify()[0]


@pytest.mark.parametrize("tamper", [
    "UPDATE audit_log SET detail='edited' WHERE id=3",
    "UPDATE audit_log SET result='DENIED' WHERE id=3",
    "UPDATE audit_log SET ts='2020-01-01T00:00:00.000+00:00' WHERE id=3",
    "UPDATE audit_log SET file_id='someone-else' WHERE id=3",
    "DELETE FROM audit_log WHERE id=3",
    "UPDATE audit_log SET hash=prev_hash WHERE id=3",
])
def test_tampering_breaks_the_chain_at_the_changed_row(vault, tmp_path, tamper):
    meta = store(vault, tmp_path)
    for _ in range(3):
        vault.read_file(meta.file_id)
    count = len(vault.audit.entries())
    assert vault.audit.verify() == (True, count, None)
    with vault.db as conn:
        conn.execute(tamper)
    ok, n, bad = vault.audit.verify()
    assert not ok and bad == (4 if tamper.startswith("DELETE") else 3)
    assert n == (count - 1 if tamper.startswith("DELETE") else count)


def test_inserted_row_is_detected(vault, tmp_path):
    store(vault, tmp_path)
    with vault.db as conn:
        conn.execute("INSERT INTO audit_log (ts, action, result, prev_hash, hash) "
                     "VALUES ('2026-01-01T00:00:00.000+00:00', 'read', 'OK', 'x', 'y')")
    ok, _, bad = vault.audit.verify()
    assert not ok and bad == len(vault.audit.entries())


def test_empty_log_verifies(tmp_path):
    from services.vault_service import VaultService
    assert VaultService(tmp_path / "DEDV").audit.verify() == (True, 0, None)
