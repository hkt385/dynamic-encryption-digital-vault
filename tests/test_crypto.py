import secrets
from uuid import uuid4

import pytest
from cryptography.exceptions import InvalidTag

from vault import encryption_service as crypto
from vault.auth import RateLimiter
from vault.token_service import hash_token, new_token


def flip(value):
    return value[:-1] + bytes([value[-1] ^ 1])


def test_dek_length_and_uniqueness():
    values = [crypto.generate_dek() for _ in range(256)]
    assert all(len(value) == 32 for value in values)
    assert len(set(values)) == len(values)


@pytest.mark.parametrize("plaintext", [b"", b"hello", bytes(range(256))])
def test_real_encryption(plaintext):
    dek = crypto.generate_dek()
    aad = crypto.file_aad(uuid4(), uuid4(), uuid4())
    encrypted = crypto.encrypt_file(plaintext, dek, aad)
    assert crypto.decrypt_file(encrypted, dek, aad) == plaintext
    with pytest.raises(InvalidTag):
        crypto.decrypt_file(flip(encrypted), dek, aad)
    with pytest.raises(InvalidTag):
        crypto.decrypt_file(encrypted, dek, b"wrong-context")


def test_real_wrapping():
    dek, kek = crypto.generate_dek(), secrets.token_bytes(32)
    aad = crypto.key_aad(uuid4(), uuid4(), uuid4(), "v1")
    wrapped = crypto.wrap_dek(dek, kek, secrets.token_bytes(12), aad)
    assert crypto.unwrap_dek(wrapped, kek, aad) == dek
    with pytest.raises(InvalidTag):
        crypto.unwrap_dek(flip(wrapped), kek, aad)
    with pytest.raises(InvalidTag):
        crypto.unwrap_dek(wrapped, secrets.token_bytes(32), aad)


def test_tokens():
    token, digest = new_token()
    other, other_digest = new_token()
    assert len(token) == 43
    assert len(digest) == 32
    assert hash_token(token) == digest
    assert token != other
    assert digest != other_digest
    for malformed in ("", "!" * 43, "é" * 43, "A" * 44):
        assert hash_token(malformed) is None


def test_rate_limit():
    limiter = RateLimiter(capacity=2, refill_per_second=1)
    assert limiter.allow("user", now=0)
    assert limiter.allow("user", now=0)
    assert not limiter.allow("user", now=0)
    assert limiter.allow("user", now=1)
