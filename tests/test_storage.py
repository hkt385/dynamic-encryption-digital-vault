import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from models.file_metadata import FileMetadata
from services.storage_service import (KEYS_DB, VAULT_DB, SqliteVaultRepository, StorageError,
                                      VaultDb, VaultLock)
from services.vault_service import VaultService

DEDV = str(Path(__file__).resolve().parent.parent / "dedv")


def meta(file_id="f1", **kw):
    return FileMetadata.new("a.txt", "TXT", 3, "Low", f"{file_id}.enc", file_id, algorithm="AES-128-GCM", **kw)


# ---- repository --------------------------------------------------------------------------------
def test_repository_round_trip_and_order(tmp_path):
    repo = SqliteVaultRepository(VaultDb(tmp_path))
    assert repo.list_files() == [] and repo.get_file("f1") is None
    a, b = meta("f1", token="tok-1"), meta("f2", predicted_level="Low")
    repo.add_file(a)
    repo.add_file(b)
    assert repo.list_files() == [a, b] and repo.get_file("f1") == a      # insertion order kept
    import dataclasses
    a2 = dataclasses.replace(a, security_level="High", encrypted_name="f1.x.enc")
    repo.update_file(a2)
    assert repo.list_files() == [a2, b]
    with pytest.raises(StorageError, match="no longer"):
        repo.update_file(meta("missing"))
    # "restart": a new connection reads the same data
    assert SqliteVaultRepository(VaultDb(tmp_path)).list_files() == [a2, b]


def test_two_database_files_keep_keys_apart_from_metadata(tmp_path):
    db = VaultDb(tmp_path)
    db.close()
    tables = lambda p: {r[0] for r in sqlite3.connect(tmp_path / p).execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"files", "audit_log", "schema_version"} <= tables(VAULT_DB)
    assert tables(KEYS_DB) == {"wrapped_keys", "vault_keys", "unlock_state", "sessions"}
    assert not tables(VAULT_DB) & tables(KEYS_DB)                 # no key table beside the metadata
    columns = {r[1] for r in sqlite3.connect(tmp_path / VAULT_DB).execute("PRAGMA table_info(files)")}
    assert "token" in columns and not {"key", "key_ref", "enc_params", "secrets"} & columns


def test_schema_version_recorded_once_and_wal_enabled(tmp_path):
    VaultDb(tmp_path).close()
    db = VaultDb(tmp_path)                                    # reopening must not re-run steps
    with db as conn:
        assert [r[0] for r in conn.execute("SELECT version FROM schema_version")] == [1, 2]
        assert conn.execute("PRAGMA main.journal_mode").fetchone()[0] == "wal"
        assert conn.execute("PRAGMA keys.journal_mode").fetchone()[0] == "wal"


def test_new_schema_steps_are_applied_to_an_existing_database(tmp_path, monkeypatch):
    from services import storage_service as ss
    VaultDb(tmp_path).close()
    monkeypatch.setattr(ss, "MIGRATIONS", ss.MIGRATIONS + [(99, ["ALTER TABLE files ADD COLUMN extra TEXT"])])
    with VaultDb(tmp_path) as conn:
        assert [r[0] for r in conn.execute("SELECT version FROM schema_version")] == [1, 2, 99]
        conn.execute("SELECT extra FROM files")


def test_nested_blocks_are_one_transaction_and_roll_back_together(tmp_path):
    db = VaultDb(tmp_path)
    repo = SqliteVaultRepository(db)
    with pytest.raises(RuntimeError):
        with db as conn:
            repo.add_file(meta("f1"))
            conn.execute("INSERT INTO keys.wrapped_keys VALUES ('tok', 'f1', 'AES-128-GCM', 'Low', x'00', x'00')")
            raise RuntimeError("boom")
    with db as conn:
        assert repo.list_files() == []
        assert conn.execute("SELECT COUNT(*) FROM keys.wrapped_keys").fetchone()[0] == 0
    with pytest.raises(StorageError):                         # SQLite errors surface as StorageError
        with db as conn:
            conn.execute("SELECT * FROM no_such_table")


# ---- cross-process lock ----------------------------------------------------------------------
def _other_process_tries(vault_dir) -> subprocess.CompletedProcess:
    code = ("import sys; sys.path.insert(0, sys.argv[1])\n"
            "from services.storage_service import VaultLock, StorageError\n"
            "try:\n    VaultLock(sys.argv[2])\nexcept StorageError as e:\n    print(e); sys.exit(3)\n")
    return subprocess.run([sys.executable, "-c", code, DEDV, str(vault_dir)], capture_output=True, text=True)


def test_second_process_is_refused_until_the_vault_is_closed(tmp_path):
    vault = VaultService(tmp_path / "DEDV")
    again = VaultService(tmp_path / "DEDV")                   # same process may reopen its vault
    r = _other_process_tries(vault.vault_dir)
    assert r.returncode == 3 and "already open in another DEDV window" in r.stdout
    vault.close()
    assert _other_process_tries(vault.vault_dir).returncode == 3     # still held by `again`
    again.close()
    again.close()                                             # closing twice is harmless
    assert _other_process_tries(vault.vault_dir).returncode == 0


def test_lock_is_dropped_when_opening_fails(tmp_path, monkeypatch):
    from services import vault_service as vs
    monkeypatch.setattr(vs, "VaultDb", lambda *a, **k: (_ for _ in ()).throw(StorageError("nope")))
    with pytest.raises(StorageError):
        VaultService(tmp_path / "DEDV")
    assert not VaultLock._held or all("test_lock_is_dropped" not in p for p in VaultLock._held)
