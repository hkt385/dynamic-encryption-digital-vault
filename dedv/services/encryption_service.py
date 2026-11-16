"""Maps final security levels to the implementations in the project's `encryption/` folder.

  Low       AES-128-GCM                  encryption/aes.py   (generate_key(1))
  Standard  AES-256-GCM                  encryption/aes.py   (generate_key(2))
  Enhanced  AES-256-GCM + RSA-4096-OAEP  encryption/aes.py + encryption/rsa.py   (hybrid)
  High      ChaCha20-Poly1305            encryption/chacha.py
  Critical  AES-256-GCM + ML-KEM-1024    encryption/aes.py + encryption/mlkem.py (hybrid)

The ML model only predicts the level; this module only performs the encryption for a level it is
given. Nothing is substituted: an unknown level or algorithm id raises EncryptionError.

Returned/consumed data:
  * params  - non-secret values that must be kept with the file's metadata (RSA-wrapped AES key,
              ML-KEM ciphertext), base64 strings.
  * secrets - values that must go to the key store (data keys, RSA private key, ML-KEM seed).
The nonce is stored inside the encrypted file by aes.py / chacha.py (first 12 bytes).
"""
import base64
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization

from paths import encryption_dir

_enc = str(encryption_dir())
if _enc not in sys.path:          # the encryption modules use flat imports
    sys.path.insert(0, _enc)

import aes  # noqa: E402  (encryption/aes.py)
import chacha  # noqa: E402  (encryption/chacha.py)
import mlkem  # noqa: E402  (encryption/mlkem.py)
import rsa  # noqa: E402  (encryption/rsa.py - not the PyPI "rsa" package)

AES_128 = "AES-128-GCM"
AES_256 = "AES-256-GCM"
AES_256_RSA_4096 = "AES-256-GCM+RSA-4096-OAEP"
CHACHA20 = "CHACHA20-POLY1305"
AES_256_MLKEM = "AES-256-GCM+ML-KEM-1024"

LEVEL_ALGORITHM = {
    "Low": AES_128,
    "Standard": AES_256,
    "Enhanced": AES_256_RSA_4096,
    "High": CHACHA20,
    "Critical": AES_256_MLKEM,
}
ALGORITHM_NAMES = {   # as shown to users
    AES_128: "AES-128",
    AES_256: "AES-256",
    AES_256_RSA_4096: "AES-256 + RSA-4096",
    CHACHA20: "ChaCha20-Poly1305",
    AES_256_MLKEM: "AES-256 + ML-KEM (Kyber)",
}
LEGACY_ALGORITHM = AES_256     # entries stored before algorithm ids existed used AES-256-GCM


class EncryptionError(Exception):
    """Message is safe to show to the user."""


@dataclass
class EncryptionResult:
    algorithm: str
    params: dict = field(default_factory=dict)       # non-secret, goes in metadata
    secrets: dict = field(default_factory=dict)      # goes to the key store only


def algorithm_name(algorithm_id: str) -> str:
    return ALGORITHM_NAMES.get(algorithm_id, algorithm_id or "Unknown")


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


class EncryptionService:
    def encrypt_file(self, src: Path, dest: Path, level: str) -> EncryptionResult:
        """Encrypt the file src -> dest with the algorithm mapped to `level`."""
        try:
            data = Path(src).read_bytes()
        except OSError as e:
            raise EncryptionError(f"The file could not be read: {e.strerror or e}")
        return self.encrypt_data(data, dest, level)

    def encrypt_data(self, data: bytes, dest: Path, level: str) -> EncryptionResult:
        """Encrypt in-memory data to dest (written atomically, so no half-written ciphertext)."""
        algorithm = LEVEL_ALGORITHM.get(level)
        if algorithm is None:
            raise EncryptionError(f"No encryption algorithm is defined for level '{level}'.")
        part = Path(str(dest) + ".part")
        try:
            blob, result = self._encrypt(algorithm, data)
            part.write_bytes(blob)
            os.replace(part, dest)
        except Exception:
            part.unlink(missing_ok=True)
            raise
        return result

    def _encrypt(self, algorithm: str, data: bytes) -> tuple[bytes, EncryptionResult]:
        if algorithm == AES_128:
            key = aes.generate_key(1)
            return aes.encrypt_bytes(data, key), EncryptionResult(algorithm, secrets={"key": key})
        if algorithm == AES_256:
            key = aes.generate_key(2)
            return aes.encrypt_bytes(data, key), EncryptionResult(algorithm, secrets={"key": key})
        if algorithm == CHACHA20:
            key = chacha.generate_key()
            return chacha.encrypt_bytes(data, key), EncryptionResult(algorithm, secrets={"key": key})
        if algorithm == AES_256_RSA_4096:
            private_key, public_key = rsa.generate_rsa_keys()
            key = aes.generate_key(2)
            blob = aes.encrypt_bytes(data, key)
            wrapped = rsa.encrypt_aes_key(key, public_key)   # RSA wraps the random AES key only
            der = private_key.private_bytes(serialization.Encoding.DER,
                                            serialization.PrivateFormat.PKCS8,
                                            serialization.NoEncryption())
            return blob, EncryptionResult(algorithm, params={"wrapped_key": _b64(wrapped)},
                                          secrets={"rsa_private_key": der})
        if algorithm == AES_256_MLKEM:
            private_key, public_key = mlkem.generate_mlkem_keys()
            key, kem_ciphertext = mlkem.encapsulate_key(public_key)
            return aes.encrypt_bytes(data, key), EncryptionResult(
                algorithm, params={"kem_ciphertext": _b64(kem_ciphertext)},
                secrets={"mlkem_seed": mlkem.private_seed(private_key)})
        raise EncryptionError(f"Unsupported encryption algorithm '{algorithm}'.")

    def decrypt_bytes(self, src: Path, algorithm: str, params: dict, secrets: dict) -> bytes:
        """Decrypt in memory. Raises EncryptionError (user-safe message) on any failure."""
        try:
            src = str(src)
            if algorithm in (AES_128, AES_256):
                key = secrets["key"]
                if len(key) != (16 if algorithm == AES_128 else 32):
                    raise EncryptionError("The stored key has the wrong length for this algorithm.")
                return aes.decrypt_bytes(src, key)
            if algorithm == CHACHA20:
                return chacha.decrypt_bytes(src, secrets["key"])
            if algorithm == AES_256_RSA_4096:
                private_key = serialization.load_der_private_key(secrets["rsa_private_key"], None)
                key = rsa.decrypt_aes_key(base64.b64decode(params["wrapped_key"]), private_key)
                return aes.decrypt_bytes(src, key)
            if algorithm == AES_256_MLKEM:
                private_key = mlkem.private_from_seed(secrets["mlkem_seed"])
                key = mlkem.decapsulate_key(private_key, base64.b64decode(params["kem_ciphertext"]))
                return aes.decrypt_bytes(src, key)
        except EncryptionError:
            raise
        except InvalidTag:
            raise EncryptionError("Decryption failed: the file is corrupted or the key does not match.")
        except FileNotFoundError:
            raise EncryptionError("The encrypted file is missing from the vault.")
        except (KeyError, ValueError, TypeError) as e:
            raise EncryptionError(f"Decryption failed: missing or invalid key/metadata ({type(e).__name__}).")
        except OSError as e:
            raise EncryptionError(f"The encrypted file could not be read: {e.strerror or e}")
        raise EncryptionError(f"Unsupported encryption algorithm '{algorithm}'.")
