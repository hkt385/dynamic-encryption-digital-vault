"""Facade the UI talks to. Orchestrates:
file + SecurityDecision -> EncryptionService -> KeyManagementService -> encrypted_files/ + metadata

The level is decided beforehand by SecurityDecisionEngine; the level in the decision is the level
that is actually used for encryption. Operations that change the vault take a lock so a store and a
re-encryption can never interleave.
"""
import dataclasses
import threading
import uuid
from dataclasses import dataclass
from pathlib import Path

from models.file_metadata import FileMetadata
from services.encryption_service import LEGACY_ALGORITHM, EncryptionError, EncryptionService
from services.key_management_service import KeyManagementService, KeyStoreError
from services.security_decision_service import SecurityDecision, validate_final_level
from services.storage_service import (JsonVaultRepository, StorageError,
                                      VaultRepository, create_vault)


class OperationError(Exception):
    """A vault operation failed; the message is safe to show to the user."""


@dataclass
class StoreResult:
    stored: list[str]
    failed: list[tuple[str, str]]   # (name, reason)
    notice: str = ""


class VaultService:
    def __init__(self, vault_dir: Path, keys: KeyManagementService | None = None):
        self.vault_dir = Path(vault_dir)
        create_vault(self.vault_dir.parent)           # ensures folders exist
        self.repo: VaultRepository = JsonVaultRepository(self.vault_dir)
        self.encryption = EncryptionService()
        self.keys = keys or KeyManagementService(self.vault_dir)
        self._op_lock = threading.Lock()

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
            try:
                self.keys.check_ready()          # fail before any work if the DEDV key is unusable
            except KeyStoreError as e:
                result.failed.extend((Path(p).name, str(e)) for p, _ in items)
                return result
            for p, decision in items:
                p = Path(p)
                try:
                    self._store_one(p, decision, account_type)
                    result.stored.append(p.name)
                except PermissionError:
                    result.failed.append((p.name, "Permission denied."))
                except (OperationError, EncryptionError, KeyStoreError, StorageError, ValueError) as e:
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
            self.keys.store_secrets(file_id, enc.secrets)
            self.repo.add_file(FileMetadata.new(
                p.name, (p.suffix.lstrip(".") or "file").upper(), p.stat().st_size,
                decision.level, enc_name, file_id, decision.predicted or "",
                enc.algorithm, file_id, enc.params))
        except Exception:
            dest.unlink(missing_ok=True)         # no file, key or metadata is left half-written
            self.keys.delete(file_id)
            raise

    # ---- open ----------------------------------------------------------------------------------
    def _secrets_for(self, meta: FileMetadata) -> tuple[str, dict]:
        if not meta.algorithm:       # stored before algorithm ids: plaintext key in dev_keys.json
            return LEGACY_ALGORITHM, {"key": self.keys.get_legacy_key(meta.file_id)}
        return meta.algorithm, self.keys.get_secrets(meta.key_ref or meta.file_id)

    def _decrypt(self, meta: FileMetadata) -> bytes:
        try:
            algorithm, secrets = self._secrets_for(meta)
            return self.encryption.decrypt_bytes(self.encrypted_dir / meta.encrypted_name,
                                                 algorithm, meta.enc_params, secrets)
        except (EncryptionError, KeyStoreError) as e:
            raise OperationError(str(e))

    def read_file(self, file_id: str) -> tuple[FileMetadata, bytes]:
        """Decrypt a file into memory. The encrypted file is only read."""
        meta = self.repo.get_file(file_id)
        if meta is None:
            raise OperationError("This file is no longer in the vault index.")
        return meta, self._decrypt(meta)

    # ---- re-encrypt ----------------------------------------------------------------------------
    def reencrypt(self, file_id: str, new_level: str, account_type: str) -> FileMetadata:
        """Decrypt in memory, encrypt with the algorithm of `new_level`, then switch metadata.

        Order is chosen so a failure at any point leaves the original file, key and metadata
        intact: new ciphertext and new key are written under NEW names, verified by decrypting,
        and only then does the atomic metadata update make them current. The old ciphertext and
        key are removed last (best effort; leftovers are harmless orphans)."""
        try:
            validate_final_level(account_type, new_level)
        except ValueError as e:
            raise OperationError(str(e))
        with self._op_lock:
            meta = self.repo.get_file(file_id)
            if meta is None:
                raise OperationError("This file is no longer in the vault index.")
            if meta.security_level == new_level and meta.algorithm:
                raise OperationError(f"The file is already at security level {new_level}.")
            try:
                self.keys.check_ready()
            except KeyStoreError as e:
                raise OperationError(str(e))
            plaintext = self._decrypt(meta)

            tag = uuid.uuid4().hex[:8]
            new_ref = f"{file_id}.{tag}"
            new_name = f"{file_id}.{tag}.enc"
            new_path = self.encrypted_dir / new_name
            try:
                enc = self.encryption.encrypt_data(plaintext, new_path, new_level)
                if self.encryption.decrypt_bytes(new_path, enc.algorithm, enc.params, enc.secrets) != plaintext:
                    raise OperationError("Verification of the new encryption failed.")
                self.keys.store_secrets(new_ref, enc.secrets)
                new_meta = dataclasses.replace(
                    meta, security_level=new_level, algorithm=enc.algorithm, key_ref=new_ref,
                    enc_params=enc.params, encrypted_name=new_name)
                self.repo.update_file(new_meta)
            except (OperationError, EncryptionError, KeyStoreError, StorageError, OSError) as e:
                new_path.unlink(missing_ok=True)
                self.keys.delete(new_ref)
                if isinstance(e, OperationError):
                    raise
                raise OperationError(f"Re-encryption failed; the original file is unchanged. "
                                     f"{getattr(e, 'strerror', None) or e}")
            except Exception:
                new_path.unlink(missing_ok=True)
                self.keys.delete(new_ref)
                raise
            finally:
                del plaintext
            self._discard_old(meta)
            return new_meta

    def _discard_old(self, old: FileMetadata) -> None:
        try:
            (self.encrypted_dir / old.encrypted_name).unlink(missing_ok=True)
            if old.algorithm:
                self.keys.delete(old.key_ref or old.file_id)
            else:
                self.keys.delete_legacy_key(old.file_id)
        except (OSError, KeyStoreError):
            pass     # orphaned old ciphertext/key; the new version is already current
