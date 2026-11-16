"""Facade the UI talks to. Orchestrates:
file + SecurityDecision -> EncryptionService -> KeyManagementService -> encrypted_files/ + metadata

The level is decided beforehand by SecurityDecisionEngine; the level in the decision is the level
that is actually used for encryption. Operations that change the vault take a lock so a store and a
re-encryption can never interleave.

Authorization: the vault must be unlocked (self.session, see auth_service). Every decryption goes
through KeyManagementService.release_key(), which refuses while the vault is locked and writes an
audit entry either way. Stores, reads, external opens and re-encryptions are also logged.
"""
import dataclasses
import threading
import uuid
from dataclasses import dataclass
from pathlib import Path

from models.file_metadata import FileMetadata
from services import migration_service
from services.audit_service import FAILED, OK, AuditLog
from services.auth_service import AuthError, AuthSession
from services.encryption_service import EncryptionError, EncryptionService
from services.key_management_service import KeyManagementService, KeyStoreError
from services.security_decision_service import SecurityDecision, validate_final_level
from services.storage_service import (SqliteVaultRepository, StorageError, VaultDb, VaultLock,
                                      VaultRepository, create_vault)

LOCKED_MESSAGE = "The vault is locked."


class OperationError(Exception):
    """A vault operation failed; the message is safe to show to the user."""


@dataclass
class StoreResult:
    stored: list[str]
    failed: list[tuple[str, str]]   # (name, reason)
    notice: str = ""


class VaultService:
    """After construction the vault is in one of three states:
      * needs_migration        - written by DEDV 0.1; call migrate(password) first
      * not session.is_initialized - new vault; call session.initialize(password)
      * otherwise              - call session.unlock(password)
    """

    def __init__(self, vault_dir: Path):
        self.vault_dir = Path(vault_dir)
        create_vault(self.vault_dir.parent)           # ensures folders exist
        self._vault_lock = VaultLock(self.vault_dir)  # one DEDV process per vault
        self.encryption = EncryptionService()
        self._op_lock = threading.Lock()
        self.db: VaultDb | None = None
        self.repo: VaultRepository | None = None
        self.audit: AuditLog | None = None
        self.session: AuthSession | None = None
        self.keys: KeyManagementService | None = None
        try:
            if not migration_service.needs_migration(self.vault_dir):
                self._open()
        except Exception:
            self._vault_lock.release()
            raise

    def _open(self) -> None:
        self.db = VaultDb(self.vault_dir)
        self.repo = SqliteVaultRepository(self.db)
        self.audit = AuditLog(self.db)
        self.session = AuthSession(self.db, self.audit)
        self.keys = KeyManagementService(self.db, self.audit)

    @property
    def needs_migration(self) -> bool:
        return self.db is None

    def migrate(self, password: str, allow_unverified: bool = False) -> migration_service.MigrationResult:
        """Upgrade a DEDV 0.1 vault (see migration_service) and leave it unlocked."""
        result = migration_service.migrate(self.vault_dir, password, allow_unverified)
        self._open()
        self.session.unlock(password)
        return result

    def lock(self) -> None:
        if self.session is not None:
            self.session.lock()

    def close(self) -> None:
        """Lock, close the databases and release the cross-process lock. Safe to call twice."""
        if self.db is not None:
            try:
                self.lock()
            except StorageError:
                pass
            self.db.close()
            self.db = None
        self._vault_lock.release()

    @property
    def encrypted_dir(self) -> Path:
        return self.vault_dir / "encrypted_files"

    def list_files(self) -> list[FileMetadata]:
        return self.repo.list_files()

    # ---- store ---------------------------------------------------------------------------------
    def store_files(self, items: list[tuple[Path, SecurityDecision]], account_type: str) -> StoreResult:
        """items: (path, decision) pairs; only files with a final, account-valid level are stored.
        The source file is only read, never modified."""
        result = StoreResult([], [])
        with self._op_lock:
            if not self.session.is_unlocked:     # fail before any work
                result.failed.extend((Path(p).name, LOCKED_MESSAGE) for p, _ in items)
                return result
            for p, decision in items:
                p = Path(p)
                try:
                    self._store_one(p, decision, account_type)
                    result.stored.append(p.name)
                except PermissionError:
                    result.failed.append((p.name, "Permission denied."))
                except (OperationError, EncryptionError, KeyStoreError, StorageError, AuthError, ValueError) as e:
                    result.failed.append((p.name, str(e)))
                except OSError as e:
                    result.failed.append((p.name, str(e.strerror or e)))
        return result

    def _store_one(self, p: Path, decision: SecurityDecision, account_type: str) -> None:
        if not p.is_file():
            raise OperationError("File not found.")
        if not decision.is_final:
            raise OperationError(decision.message or "No final security level.")
        validate_final_level(account_type, decision.level)       # re-checked outside the UI
        file_id = uuid.uuid4().hex
        enc_name = f"{file_id}.enc"
        dest = self.encrypted_dir / enc_name
        enc = self.encryption.encrypt_file(p, dest, decision.level)
        try:
            with self.db:                        # key, metadata and audit row: all or nothing
                token = self.keys.store_key(file_id, enc.algorithm, decision.level,
                                            enc.secrets, enc.params, self.session)
                self.repo.add_file(FileMetadata.new(
                    p.name, (p.suffix.lstrip(".") or "file").upper(), p.stat().st_size,
                    decision.level, enc_name, file_id, decision.predicted or "", enc.algorithm, token))
                self.audit.append("store", OK, file_id, decision.level)
        except Exception:
            dest.unlink(missing_ok=True)         # no ciphertext is left without its key and metadata
            raise

    # ---- open ----------------------------------------------------------------------------------
    def _decrypt(self, meta: FileMetadata, purpose: str) -> bytes:
        """Must not be called inside a `with self.db` block: release_key's audit entry has to be
        committed even when the surrounding operation fails."""
        try:
            key = self.keys.release_key(meta.token, meta.file_id, self.session, purpose)
            if (key.algorithm, key.level) != (meta.algorithm, meta.security_level):
                raise OperationError("This file's metadata does not match its key record.")
            return self.encryption.decrypt_bytes(self.encrypted_dir / meta.encrypted_name,
                                                 key.algorithm, key.params, key.secrets)
        except (EncryptionError, KeyStoreError) as e:
            raise OperationError(str(e))

    def read_file(self, file_id: str) -> tuple[FileMetadata, bytes]:
        """Decrypt a file into memory. The encrypted file is only read."""
        meta = self.repo.get_file(file_id)
        if meta is None:
            raise OperationError("This file is no longer in the vault index.")
        try:
            data = self._decrypt(meta, "read")
        except OperationError as e:
            self.audit.append("read", FAILED, file_id, meta.security_level, str(e))
            raise
        self.audit.append("read", OK, file_id, meta.security_level)
        return meta, data

    def log_external_open(self, file_id: str) -> None:
        """Record that a decrypted copy was handed to another program."""
        meta = self.repo.get_file(file_id)
        self.audit.append("open_external", OK, file_id, meta.security_level if meta else "")

    # ---- re-encrypt ----------------------------------------------------------------------------
    def reencrypt(self, file_id: str, new_level: str, account_type: str) -> FileMetadata:
        """Decrypt in memory, encrypt with the algorithm of `new_level`, then switch metadata.

        Order is chosen so a failure at any point leaves the original file, key and metadata
        intact: the new ciphertext is written under a NEW name and verified by decrypting it.
        Then one database transaction stores the new key record, switches the metadata to the new
        ciphertext and token, and removes the old key record; it commits or rolls back as a whole.
        The old ciphertext is deleted only after the commit (best effort; a leftover is a harmless
        orphan)."""
        try:
            validate_final_level(account_type, new_level)
        except ValueError as e:
            raise OperationError(str(e))
        with self._op_lock:
            meta = self.repo.get_file(file_id)
            if meta is None:
                raise OperationError("This file is no longer in the vault index.")
            if meta.security_level == new_level:
                raise OperationError(f"The file is already at security level {new_level}.")
            change = f"{meta.security_level} -> {new_level}"
            new_name = f"{file_id}.{uuid.uuid4().hex[:8]}.enc"
            new_path = self.encrypted_dir / new_name
            try:
                plaintext = self._decrypt(meta, "reencrypt")
                try:
                    enc = self.encryption.encrypt_data(plaintext, new_path, new_level)
                    if self.encryption.decrypt_bytes(new_path, enc.algorithm, enc.params, enc.secrets) != plaintext:
                        raise OperationError("Verification of the new encryption failed.")
                    with self.db:                    # the swap: all of it or none
                        token = self.keys.store_key(file_id, enc.algorithm, new_level,
                                                    enc.secrets, enc.params, self.session)
                        new_meta = dataclasses.replace(
                            meta, security_level=new_level, algorithm=enc.algorithm, token=token,
                            encrypted_name=new_name)
                        self.repo.update_file(new_meta)
                        self.keys.delete(meta.token)
                        self.audit.append("reencrypt", OK, file_id, new_level, change)
                finally:
                    del plaintext
            except Exception as e:
                new_path.unlink(missing_ok=True)
                self.audit.append("reencrypt", FAILED, file_id, meta.security_level,
                                  f"{change}: {type(e).__name__}")
                if isinstance(e, OperationError):
                    raise
                if isinstance(e, (EncryptionError, KeyStoreError, StorageError, AuthError, OSError)):
                    raise OperationError(f"Re-encryption failed; the original file is unchanged. "
                                         f"{getattr(e, 'strerror', None) or e}")
                raise
            try:
                (self.encrypted_dir / meta.encrypted_name).unlink(missing_ok=True)
            except OSError:
                pass     # orphaned old ciphertext; the new version is already current
            return new_meta
