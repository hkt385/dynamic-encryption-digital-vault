"""No database, filesystem, or authorization dependencies."""
import json
import secrets
from uuid import UUID

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ALGORITHM = "AES-256-GCM"
MAX_FILE_BYTES = 16 * 1024 * 1024


def generate_dek() -> bytes:
    return secrets.token_bytes(32)


def _key(value: bytes):
    if not isinstance(value, bytes) or len(value) != 32:
        raise ValueError("Invalid key size")


def _aad(*parts) -> bytes:
    return json.dumps(parts, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def file_aad(document_id: UUID, owner_id: UUID, key_id: UUID) -> bytes:
    return _aad(
        "vault-file", 1, str(document_id), str(owner_id), str(key_id), ALGORITHM
    )


def key_aad(document_id: UUID, owner_id: UUID, key_id: UUID, version: str) -> bytes:
    return _aad(
        "vault-dek", 1, str(document_id), str(owner_id), str(key_id), ALGORITHM, version
    )


def encrypt_file(plaintext: bytes, dek: bytes, aad: bytes) -> bytes:
    """Caller must supply a freshly generated, single-use DEK."""
    _key(dek)
    if not isinstance(plaintext, bytes) or len(plaintext) > MAX_FILE_BYTES:
        raise ValueError("Invalid plaintext size")
    nonce = secrets.token_bytes(12)
    return nonce + AESGCM(dek).encrypt(nonce, plaintext, aad)


def decrypt_file(encrypted: bytes, dek: bytes, aad: bytes) -> bytes:
    _key(dek)
    if not 28 <= len(encrypted) <= MAX_FILE_BYTES + 28:
        raise ValueError("Invalid ciphertext size")
    return AESGCM(dek).decrypt(encrypted[:12], encrypted[12:], aad)


def wrap_dek(dek: bytes, kek: bytes, nonce: bytes, aad: bytes) -> bytes:
    _key(dek)
    _key(kek)
    if len(nonce) != 12:
        raise ValueError("Invalid nonce size")
    return nonce + AESGCM(kek).encrypt(nonce, dek, aad)


def unwrap_dek(wrapped: bytes, kek: bytes, aad: bytes) -> bytes:
    _key(kek)
    if len(wrapped) != 60:
        raise ValueError("Invalid wrapped key size")
    dek = AESGCM(kek).decrypt(wrapped[:12], wrapped[12:], aad)
    _key(dek)
    return dek
