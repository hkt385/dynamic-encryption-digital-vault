"""Facade the UI talks to. Orchestrates:
file -> SecurityDecisionEngine -> EncryptionService -> KeyManagementService -> encrypted_files/
"""
import uuid
from dataclasses import dataclass
from pathlib import Path

from models.file_metadata import FileMetadata
from services.encryption_service import EncryptionService
from services.key_management_service import KeyManagementService
from services.security_decision_service import SecurityDecisionEngine
from services.storage_service import (JsonVaultRepository, StorageError,
                                      VaultRepository, create_vault)

UNASSIGNED = "Unassigned"


@dataclass
class StoreResult:
    stored: list[str]
    failed: list[tuple[str, str]]   # (name, reason)
    notice: str = ""


class VaultService:
    def __init__(self, vault_dir: Path):
        self.vault_dir = Path(vault_dir)
        create_vault(self.vault_dir.parent)           # ensures folders exist
        self.repo: VaultRepository = JsonVaultRepository(self.vault_dir)
        self.decision = SecurityDecisionEngine()
        self.encryption = EncryptionService()
        self.keys = KeyManagementService(self.vault_dir)

    def list_files(self) -> list[FileMetadata]:
        return self.repo.list_files()

    def store_files(self, paths: list[Path], account_type: str) -> StoreResult:
        result = StoreResult([], [])
        for p in paths:
            p = Path(p)
            if not p.is_file():
                result.failed.append((p.name, "File not found."))
                continue
            try:
                decision = self.decision.decide(p, account_type)
                if decision.message:
                    result.notice = decision.message
                level = decision.level or UNASSIGNED
                file_id = uuid.uuid4().hex
                enc_name = f"{file_id}.enc"
                key = self.encryption.encrypt_file(p, self.vault_dir / "encrypted_files" / enc_name)
                self.keys.store_key(file_id, key)
                self.repo.add_file(FileMetadata.new(
                    p.name, (p.suffix.lstrip(".") or "file").upper(),
                    p.stat().st_size, level, enc_name, file_id))
                result.stored.append(p.name)
            except PermissionError:
                result.failed.append((p.name, "Permission denied."))
            except (OSError, StorageError) as e:
                result.failed.append((p.name, str(getattr(e, "strerror", None) or e)))
        return result

    def open_file(self, file_id: str):
        # TODO: authorization -> key retrieval -> decrypt to temp -> open -> cleanup.
        raise NotImplementedError
