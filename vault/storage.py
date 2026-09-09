import os
import stat
from pathlib import Path
from uuid import UUID

from vault.encryption_service import MAX_FILE_BYTES
from vault.errors import VaultError


class EncryptedStorage:
    def __init__(self, root: Path):
        root = Path(root)
        if root.is_symlink():
            raise VaultError("INVALID_STORAGE")
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        if not root.is_dir():
            raise VaultError("INVALID_STORAGE")
        if hasattr(os, "getuid") and root.stat().st_uid != os.getuid():
            raise VaultError("INVALID_STORAGE")
        os.chmod(root, 0o700)
        self.root = root.resolve()

    @staticmethod
    def reference(document: UUID) -> str:
        return f"{document.hex}.vault"

    def write(self, document: UUID, encrypted: bytes) -> str:
        reference = self.reference(document)
        path = self.root / reference
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(encrypted)
            handle.flush()
            os.fsync(handle.fileno())
        if hasattr(os, "O_DIRECTORY"):
            directory = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        return reference

    def read(self, document: UUID, reference: str) -> bytes:
        if reference != self.reference(document):
            raise ValueError("Invalid storage reference")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(self.root / reference, flags)
        with os.fdopen(descriptor, "rb") as handle:
            if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                raise ValueError("Invalid storage object")
            encrypted = handle.read(MAX_FILE_BYTES + 29)
        if not 28 <= len(encrypted) <= MAX_FILE_BYTES + 28:
            raise ValueError("Invalid storage size")
        return encrypted
