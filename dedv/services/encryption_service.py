"""Thin wrapper over the project's `encryption/` modules (aes.py, rsa.py, ecc.py).

Only AES-GCM file encryption is wired in for now. Wrapping the data key with
RSA/ECC (levels 3+) belongs to the existing key-management system and is not
invented here.
"""
import sys
from pathlib import Path

from paths import encryption_dir

_enc = str(encryption_dir())
if _enc not in sys.path:          # the encryption modules use flat imports
    sys.path.insert(0, _enc)

import aes  # noqa: E402  (encryption/aes.py)


class EncryptionService:
    def encrypt_file(self, src: Path, dest: Path) -> bytes:
        """Encrypt src -> dest with AES-256-GCM and return the data key."""
        # TODO: choose AES-128/256 (and RSA/ECC key wrapping) from the security level.
        key = aes.generate_key(2)
        aes.encrypt_file(str(src), str(dest), key)
        return key

    def decrypt_file(self, src: Path, dest: Path, key: bytes) -> None:
        aes.decrypt_file(str(src), str(dest), key)
