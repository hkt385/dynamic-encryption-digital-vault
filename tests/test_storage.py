import json
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from legacy import write_legacy_vault
from models.file_metadata import FileMetadata
from paths import key_dir
from services.storage_service import (KEYS_DB, VAULT_DB, SqliteVaultRepository, StorageError,
                                      VaultDb, VaultLock)
from services.vault_service import VaultService

DEDV = str(Path(__file__).resolve().parent.parent / "dedv")
CONTENT = b"legacy contents\n" * 50


def meta(file_id="f1", **kw):
    return FileMetadata.new("a.txt", "TXT", 3, "Low", f"{file_id}.enc", file_id, **kw)


# ---- repository --------------------------------------------------------------------------------
def test_repository_round_trip_and_order(tmp_path):
    repo = SqliteVaultRepository(VaultDb(tmp_path))
    assert repo.list_files() == [] and repo.get_file("f1") is None
    a, b = meta("f1", enc_params={"wrapped_key": "abc"}), meta("f2", predicted_level="Low")
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
    assert "files" in tables(VAULT_DB) and "wrapped_keys" not in tables(VAULT_DB)
    assert "wrapped_keys" in tables(KEYS_DB) and "files" not in tables(KEYS_DB)


def test_schema_version_recorded_once_and_wal_enabled(tmp_path):
    VaultDb(tmp_path).close()
    db = VaultDb(tmp_path)                                    # reopening must not re-run steps
    with db as conn:
        assert [r[0] for r in conn.execute("SELECT version FROM schema_version")] == [1]
        assert conn.execute("PRAGMA main.journal_mode").fetchone()[0] == "wal"
        assert conn.execute("PRAGMA keys.journal_mode").fetchone()[0] == "wal"


def test_new_schema_steps_are_applied_to_an_existing_database(tmp_path, monkeypatch):
    from services import storage_service as ss
    VaultDb(tmp_path).close()
    monkeypatch.setattr(ss, "MIGRATIONS", ss.MIGRATIONS + [(99, ["ALTER TABLE files ADD COLUMN extra TEXT"])])
    with VaultDb(tmp_path) as conn:
        assert [r[0] for r in conn.execute("SELECT version FROM schema_version")] == [1, 99]
        conn.execute("SELECT extra FROM files")


def test_nested_blocks_are_one_transaction_and_roll_back_together(tmp_path):
    db = VaultDb(tmp_path)
    repo = SqliteVaultRepository(db)
    with pytest.raises(RuntimeError):
        with db as conn:
            repo.add_file(meta("f1"))
            conn.execute("INSERT INTO keys.wrapped_keys VALUES ('f1', 'DEDV', x'00', x'00')")
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


# ---- import of a DEDV 0.1 (JSON) vault -------------------------------------------------------------
LEVELS = ("Low", "Standard", "Enhanced", "High", "Critical", None)   # None = pre-algorithm entry


def _legacy(tmp_path):
    vault_dir = tmp_path / "DEDV"
    entries = [(f"{lv or 'old'}.txt", lv, CONTENT + (lv or "old").encode()) for lv in LEVELS]
    return vault_dir, write_legacy_vault(vault_dir, key_dir(), entries)


def test_json_vault_is_imported_and_every_file_still_opens(tmp_path):
    vault_dir, index = _legacy(tmp_path)
    vault = VaultService(vault_dir)
    files = vault.list_files()
    assert [m.file_id for m in files] == [d["file_id"] for d in index]
    for m in files:
        assert vault.read_file(m.file_id)[1] == CONTENT + Path(m.original_name).stem.encode()
    for name in ("metadata/files.json", "config/wrapped_keys.json", "config/dev_keys.json"):
        assert not (vault_dir / name).exists() and (vault_dir / (name + ".migrated.bak")).exists()
    assert json.loads((vault_dir / "metadata/files.json.migrated.bak").read_text()) == index   # originals kept
    vault.close()
    assert len(VaultService(vault_dir).list_files()) == len(LEVELS)        # second start: no re-import


def test_failed_import_leaves_the_json_vault_untouched(tmp_path):
    vault_dir, index = _legacy(tmp_path)
    before = {p: p.read_bytes() for p in vault_dir.rglob("*") if p.is_file()}
    victim = vault_dir / "encrypted_files" / index[3]["encrypted_name"]
    good = victim.read_bytes()
    victim.write_bytes(good[:-4] + b"XXXX")                    # fails half-way through verification
    with pytest.raises(StorageError, match="left unchanged.*High.txt"):
        VaultService(vault_dir)
    victim.write_bytes(good)
    after = {p: p.read_bytes() for p in vault_dir.rglob("*") if p.is_file() and p.name != "vault.lock"}
    assert after == before                                     # no databases, no .tmp, no renames
    assert len(VaultService(vault_dir).list_files()) == len(LEVELS)        # and it can be retried


def test_import_without_the_key_file_is_refused_not_guessed(tmp_path):
    vault_dir, _ = _legacy(tmp_path)
    (key_dir() / "DEDV_key.txt").unlink()
    with pytest.raises(StorageError, match="left unchanged"):
        VaultService(vault_dir)
    assert (vault_dir / "metadata" / "files.json").exists() and not (vault_dir / VAULT_DB).exists()
    assert not (key_dir() / "DEDV_key.txt").exists()            # no replacement key was minted
