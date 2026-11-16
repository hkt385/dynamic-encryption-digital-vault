"""Upgrade of a vault written by DEDV 0.1 (JSON index and JSON key stores) to the SQLite databases.

Nothing in the old vault is changed until every file has been decrypted successfully through the
new databases: they are built under temporary names, verified, and only then renamed into place.
The JSON originals are kept, renamed to *.migrated.bak. Any failure removes the temporary
databases and leaves the vault exactly as it was.
"""
import base64
import json
import os
from pathlib import Path

from models.file_metadata import FileMetadata
from services.encryption_service import LEGACY_ALGORITHM, EncryptionService
from services.key_management_service import DevKeyFile, KeyManagementService
from services.storage_service import KEYS_DB, VAULT_DB, SqliteVaultRepository, StorageError, VaultDb

LEGACY_INDEX = Path("metadata") / "files.json"
LEGACY_WRAPPED = Path("config") / "wrapped_keys.json"
LEGACY_PLAIN = Path("config") / "dev_keys.json"
LEGACY_FILES = (LEGACY_INDEX, LEGACY_WRAPPED, LEGACY_PLAIN)
BACKUP_SUFFIX = ".migrated.bak"


def needs_import(vault_dir: Path) -> bool:
    vault_dir = Path(vault_dir)
    return not (vault_dir / VAULT_DB).exists() and any((vault_dir / p).exists() for p in LEGACY_FILES)


def _load(path: Path, default):
    if not path.exists():
        return default
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, type(default)):
        raise ValueError(f"{path.name} has an unexpected format")
    return data


def import_json_vault(vault_dir: Path, key_file: DevKeyFile | None = None) -> int:
    """Import the JSON vault into SQLite. Returns the number of files imported (0 = nothing to do)."""
    vault_dir = Path(vault_dir)
    if not needs_import(vault_dir):
        return 0
    tmp = None
    try:
        files = [FileMetadata.from_dict(d) for d in _load(vault_dir / LEGACY_INDEX, [])]
        wrapped = _load(vault_dir / LEGACY_WRAPPED, {})
        plain = _load(vault_dir / LEGACY_PLAIN, {})
        for suffix in (".tmp", ".tmp-journal"):          # leftovers of an interrupted attempt
            for p in (VAULT_DB, KEYS_DB):
                Path(str(vault_dir / p) + suffix).unlink(missing_ok=True)
        tmp = VaultDb(vault_dir, suffix=".tmp", wal=False)   # no WAL: the file is renamed below
        repo = SqliteVaultRepository(tmp)
        with tmp as conn:
            for meta in files:
                repo.add_file(meta)
            for ref, rec in wrapped.items():
                conn.execute("INSERT INTO keys.wrapped_keys VALUES (?, ?, ?, ?)",
                             (ref, rec["kek_id"], base64.b64decode(rec["nonce"]), base64.b64decode(rec["ct"])))
            for file_id, key in plain.items():
                conn.execute("INSERT INTO keys.legacy_keys VALUES (?, ?)", (file_id, base64.b64decode(key)))
        # Decrypt-verify every file through the new databases before anything is switched.
        keys, enc = KeyManagementService(vault_dir, key_file, db=tmp), EncryptionService()
        for meta in files:
            if meta.algorithm:
                algorithm, secrets = meta.algorithm, keys.get_secrets(meta.key_ref or meta.file_id)
            else:
                algorithm, secrets = LEGACY_ALGORITHM, {"key": keys.get_legacy_key(meta.file_id)}
            try:
                enc.decrypt_bytes(vault_dir / "encrypted_files" / meta.encrypted_name,
                                  algorithm, meta.enc_params, secrets)
            except Exception as e:
                raise StorageError(f"{meta.original_name}: {e}")
        tmp.close()
        os.replace(tmp.keys_path, vault_dir / KEYS_DB)
        os.replace(tmp.vault_path, vault_dir / VAULT_DB)      # commit point: needs_import() is now False
    except Exception as e:
        if tmp is not None:
            tmp.close()
            tmp.vault_path.unlink(missing_ok=True)
            tmp.keys_path.unlink(missing_ok=True)
        raise StorageError(f"This vault could not be upgraded and was left unchanged. {e}")
    for p in LEGACY_FILES:                 # keep the originals, out of the way
        src = vault_dir / p
        if src.exists():
            try:
                os.replace(src, Path(str(src) + BACKUP_SUFFIX))
            except OSError:
                pass                       # harmless: the databases are already current
    return len(files)
