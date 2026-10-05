"""Vault folder layout + metadata repository.

The UI talks to `VaultRepository`; `JsonVaultRepository` is the first-version
implementation and can be swapped for a SQLite one later.
"""
import json
from abc import ABC, abstractmethod
from pathlib import Path

from models.file_metadata import FileMetadata

VAULT_FOLDER = "DEDV"
SUBFOLDERS = ("encrypted_files", "metadata", "config")


class StorageError(Exception):
    """Message is safe to show to the user."""


def create_vault(parent: Path) -> Path:
    """Create <parent>/DEDV and its subfolders. Reuses an existing DEDV untouched."""
    parent = Path(parent)
    if not parent.is_dir():
        raise StorageError("The selected folder is not available.")
    vault = parent / VAULT_FOLDER
    try:
        for sub in SUBFOLDERS:
            (vault / sub).mkdir(parents=True, exist_ok=True)
    except PermissionError:
        raise StorageError("Permission denied. Please choose a folder you can write to.")
    except OSError as e:
        raise StorageError(f"Could not create the vault folder: {e.strerror or e}")
    return vault


class VaultRepository(ABC):
    @abstractmethod
    def list_files(self) -> list[FileMetadata]: ...

    @abstractmethod
    def add_file(self, meta: FileMetadata) -> None: ...

    @abstractmethod
    def get_file(self, file_id: str) -> FileMetadata | None: ...


class JsonVaultRepository(VaultRepository):
    def __init__(self, vault_dir: Path):
        self.index = Path(vault_dir) / "metadata" / "files.json"

    def _read(self) -> list[FileMetadata]:
        if not self.index.is_file():
            return []
        try:
            raw = json.loads(self.index.read_text(encoding="utf-8"))
            return [FileMetadata.from_dict(d) for d in raw]
        except (OSError, ValueError, KeyError, TypeError):
            raise StorageError("The vault index could not be read.")

    def _write(self, items: list[FileMetadata]) -> None:
        try:
            tmp = self.index.with_suffix(".tmp")
            tmp.write_text(json.dumps([m.to_dict() for m in items], indent=2), encoding="utf-8")
            tmp.replace(self.index)
        except OSError as e:
            raise StorageError(f"Could not update the vault index: {e.strerror or e}")

    def list_files(self) -> list[FileMetadata]:
        return self._read()

    def add_file(self, meta: FileMetadata) -> None:
        items = self._read()
        items.append(meta)
        self._write(items)

    def get_file(self, file_id: str) -> FileMetadata | None:
        return next((m for m in self._read() if m.file_id == file_id), None)
