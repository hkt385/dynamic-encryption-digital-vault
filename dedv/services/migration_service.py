"""Upgrade of a vault written by DEDV 0.1 to the 0.2 format.

DEDV 0.1 kept metadata in metadata/files.json, wrapped per-file keys in config/wrapped_keys.json
(sealed under a PLAINTEXT key file, DEDV_key.txt, in a per-user folder), and the keys of its oldest
entries in the clear in config/dev_keys.json. The upgrade asks for a new vault password and:

  1. copies the JSON files to <vault>/backup/pre-0.2-<UTC time>/ ;
  2. builds vault.db / keys.db under temporary names: a new Vault Master Key wrapped under the
     password, every file's key unwrapped with the old key file and re-sealed under the VMK with
     a new token;
  3. decrypt-verifies EVERY file through the new databases;
  4. only then renames the databases into place, renames files.json and wrapped_keys.json to
     *.migrated.bak and wipes dev_keys.json (plaintext keys) and its backup copy.

Ciphertext files are never touched. Any failure before step 4 removes the temporary databases and
the backup copy and leaves the vault exactly as it was.

If some files cannot be verified (already corrupt or missing in the old vault) the upgrade stops
with MigrationVerifyError. The caller may repeat it with allow_unverified=True; then everything
that can be imported is imported, and NOTHING old is wiped or deleted.

The old key file is shared by every 0.1 vault of this Windows user, so it is never deleted here:
the UI asks, and calls delete_old_key_file() only on a clear yes.
"""
import base64
import json
import os
import shutil
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from models.file_metadata import FileMetadata
from paths import key_dir, wipe_and_delete
from services.audit_service import OK, AuditLog
from services.auth_service import AuthError, AuthSession, check_password
from services.encryption_service import LEGACY_ALGORITHM, EncryptionService
from services.key_management_service import KeyManagementService
from services.storage_service import KEYS_DB, VAULT_DB, SqliteVaultRepository, StorageError, VaultDb

LEGACY_INDEX = Path("metadata") / "files.json"
LEGACY_WRAPPED = Path("config") / "wrapped_keys.json"
LEGACY_PLAIN = Path("config") / "dev_keys.json"
LEGACY_FILES = (LEGACY_INDEX, LEGACY_WRAPPED, LEGACY_PLAIN)
BACKUP_SUFFIX = ".migrated.bak"
KEY_FILE_NAME = "DEDV_key.txt"
KEK_ID = "DEDV"
PARTIAL = "PARTIAL"


class MigrationVerifyError(StorageError):
    """Some files could not be verified; nothing was changed. failed: [(file name, reason)]."""

    def __init__(self, failed: list[tuple[str, str]]):
        super().__init__(f"{len(failed)} file(s) could not be verified; the vault was left unchanged.")
        self.failed = failed


@dataclass
class MigrationResult:
    recovery_key: str
    files: int
    backup_dir: Path
    unverified: list = field(default_factory=list)      # [(file name, reason)]; empty = full upgrade


# ---- the DEDV 0.1 key file -------------------------------------------------------------------
def old_key_file(directory: Path | None = None) -> Path:
    return (Path(directory) if directory else key_dir()) / KEY_FILE_NAME


def load_old_key(directory: Path | None = None) -> bytes:
    path = old_key_file(directory)
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise StorageError(f"The old DEDV key file is missing: {path}. Restore it from a backup; "
                           "files encrypted with it cannot be opened without it.")
    except OSError as e:
        raise StorageError(f"The old DEDV key file could not be read ({e.strerror or e}): {path}")
    fields = {}
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith("#") and ":" in line:
            k, v = line.split(":", 1)
            fields[k.strip().lower()] = v.strip()
    try:
        key = base64.b64decode(fields.get("key", ""), validate=True)
    except ValueError:
        key = b""
    if fields.get("key_id") != KEK_ID or len(key) != 32:
        raise StorageError(f"The old DEDV key file is malformed: {path}")
    return key


def delete_old_key_file(directory: Path | None = None) -> None:
    """Overwrite (best effort) and delete DEDV_key.txt. Only call after the user confirmed that no
    other DEDV 0.1 vault still depends on it. Raises OSError if it cannot be deleted."""
    wipe_and_delete(old_key_file(directory))


# ---- upgrade -----------------------------------------------------------------------------------
def needs_migration(vault_dir: Path) -> bool:
    vault_dir = Path(vault_dir)
    return not (vault_dir / VAULT_DB).exists() and any((vault_dir / p).exists() for p in LEGACY_FILES)


def _load(path: Path, default):
    if not path.exists():
        return default
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, type(default)):
        raise ValueError(f"{path.name} has an unexpected format")
    return data


def _old_secrets(entry: dict, wrapped: dict, plain: dict, kek: bytes | None, kek_error: str) -> dict:
    """The secrets of one 0.1 entry. Raises ValueError with a user-safe reason."""
    if not entry.get("algorithm"):                       # oldest entries: plaintext AES-256 key
        if entry["file_id"] not in plain:
            raise ValueError("its key is not in the old key store")
        return {"key": base64.b64decode(plain[entry["file_id"]])}
    ref = entry.get("key_ref") or entry["file_id"]
    if ref not in wrapped:
        raise ValueError("its key is not in the old key store")
    if kek is None:
        raise ValueError(kek_error)
    try:
        rec = wrapped[ref]
        payload = AESGCM(kek).decrypt(base64.b64decode(rec["nonce"]), base64.b64decode(rec["ct"]), ref.encode())
        return {k: base64.b64decode(v) for k, v in json.loads(payload).items()}
    except (InvalidTag, KeyError, ValueError, TypeError):
        raise ValueError("its key could not be unwrapped with the old DEDV key file")


def migrate(vault_dir: Path, password: str, allow_unverified: bool = False,
            key_directory: Path | None = None) -> MigrationResult:
    vault_dir = Path(vault_dir)
    check_password(password)                              # AuthError before any work
    if not needs_migration(vault_dir):
        raise StorageError("This vault does not need to be upgraded.")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup_dir = vault_dir / "backup" / f"pre-0.2-{stamp}"
    tmp = None
    try:
        index = _load(vault_dir / LEGACY_INDEX, [])
        wrapped = _load(vault_dir / LEGACY_WRAPPED, {})
        plain = _load(vault_dir / LEGACY_PLAIN, {})
        kek, kek_error = None, ""
        if wrapped:
            try:
                kek = load_old_key(key_directory)
            except StorageError as e:
                kek_error = str(e)

        for p in LEGACY_FILES:                            # 1. backup
            if (vault_dir / p).exists():
                (backup_dir / p).parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(vault_dir / p, backup_dir / p)

        for suffix in (".tmp", ".tmp-journal"):           # leftovers of an interrupted attempt
            for p in (VAULT_DB, KEYS_DB):
                Path(str(vault_dir / p) + suffix).unlink(missing_ok=True)
        tmp = VaultDb(vault_dir, suffix=".tmp", wal=False)    # 2. build (no WAL: renamed below)
        audit = AuditLog(tmp)
        session, keys = AuthSession(tmp, audit), KeyManagementService(tmp, audit)
        repo, enc = SqliteVaultRepository(tmp), EncryptionService()
        recovery_key = session.initialize(password)
        unverified, imported = [], []
        with tmp:
            for entry in index:
                algorithm = entry.get("algorithm") or LEGACY_ALGORITHM
                token = ""
                try:
                    token = keys.store_key(entry["file_id"], algorithm, entry["security_level"],
                                           _old_secrets(entry, wrapped, plain, kek, kek_error),
                                           entry.get("enc_params") or {}, session)
                except ValueError as e:
                    unverified.append((entry["original_name"], str(e)))
                meta = FileMetadata(
                    file_id=entry["file_id"], original_name=entry["original_name"],
                    file_type=entry["file_type"], size_bytes=entry["size_bytes"],
                    date_added=entry["date_added"], security_level=entry["security_level"],
                    encrypted_name=entry["encrypted_name"],
                    predicted_level=entry.get("predicted_level", ""), algorithm=algorithm, token=token)
                repo.add_file(meta)
                imported.append(meta)

        for meta in imported:                             # 3. decrypt-verify every file
            if not meta.token:
                continue
            try:
                key = keys.release_key(meta.token, meta.file_id, session, "migration")
                enc.decrypt_bytes(vault_dir / "encrypted_files" / meta.encrypted_name,
                                  key.algorithm, key.params, key.secrets)
            except Exception as e:
                unverified.append((meta.original_name, str(e)))
        if unverified and not allow_unverified:
            raise MigrationVerifyError(unverified)

        audit.append("migration", PARTIAL if unverified else OK,
                     detail=f"{len(imported)} file(s) imported from DEDV 0.1, {len(unverified)} not verified")
        session.lock()
        tmp.close()
        os.replace(tmp.keys_path, vault_dir / KEYS_DB)        # 4. switch
        os.replace(tmp.vault_path, vault_dir / VAULT_DB)      # commit point: needs_migration() is now False
    except Exception as e:
        if tmp is not None:
            tmp.close()
            tmp.vault_path.unlink(missing_ok=True)
            tmp.keys_path.unlink(missing_ok=True)
        shutil.rmtree(backup_dir, ignore_errors=True)
        if isinstance(e, (MigrationVerifyError, AuthError)):
            raise
        raise StorageError(f"This vault could not be upgraded and was left unchanged. {e}")

    for p in LEGACY_FILES:                 # the databases are current; tidy the originals (best effort)
        src = vault_dir / p
        try:
            if p == LEGACY_PLAIN and not unverified:
                wipe_and_delete(src)               # plaintext keys: no copy is kept after a full upgrade
                wipe_and_delete(backup_dir / p)
            elif src.exists():
                os.replace(src, Path(str(src) + BACKUP_SUFFIX))
        except OSError:
            pass
    return MigrationResult(recovery_key, len(imported), backup_dir, unverified)
