import base64

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

from services import encryption_service as es
from services.encryption_service import EncryptionError, EncryptionService

DATA = b"The quick brown fox " * 500


@pytest.fixture(scope="module")
def svc():
    return EncryptionService()


def enc(svc, tmp_path, level, data=DATA):
    dest = tmp_path / f"{level}.enc"
    return dest, svc.encrypt_data(data, dest, level)


def test_level_to_algorithm_mapping_is_exact():
    assert es.LEVEL_ALGORITHM == {
        "Low": "AES-128-GCM", "Standard": "AES-256-GCM", "Enhanced": "AES-256-GCM+RSA-4096-OAEP",
        "High": "CHACHA20-POLY1305", "Critical": "AES-256-GCM+ML-KEM-1024"}


def test_low_is_aes128_gcm(svc, tmp_path):
    dest, r = enc(svc, tmp_path, "Low")
    key = r.secrets["key"]
    assert len(key) == 16 and r.algorithm == "AES-128-GCM"
    blob = dest.read_bytes()
    assert AESGCM(key).decrypt(blob[:12], blob[12:], None) == DATA      # independent primitive


def test_standard_is_aes256_gcm(svc, tmp_path):
    dest, r = enc(svc, tmp_path, "Standard")
    key = r.secrets["key"]
    assert len(key) == 32
    blob = dest.read_bytes()
    assert AESGCM(key).decrypt(blob[:12], blob[12:], None) == DATA


def test_enhanced_is_hybrid_rsa4096_wrapped_aes256(svc, tmp_path):
    dest, r = enc(svc, tmp_path, "Enhanced")
    private = serialization.load_der_private_key(r.secrets["rsa_private_key"], None)
    assert private.key_size == 4096
    assert "key" not in r.secrets                      # the AES key itself is never stored
    wrapped = base64.b64decode(r.params["wrapped_key"])
    assert len(wrapped) == 512                         # RSA-4096 block wrapping a 32-byte key
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    aes_key = private.decrypt(wrapped, padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None))
    assert len(aes_key) == 32
    blob = dest.read_bytes()
    assert AESGCM(aes_key).decrypt(blob[:12], blob[12:], None) == DATA
    assert len(blob) < len(DATA) + 64                  # file is AES-encrypted, not RSA-encrypted


def test_high_is_chacha20_poly1305(svc, tmp_path):
    dest, r = enc(svc, tmp_path, "High")
    key = r.secrets["key"]
    assert len(key) == 32 and r.algorithm == "CHACHA20-POLY1305"
    blob = dest.read_bytes()
    assert ChaCha20Poly1305(key).decrypt(blob[:12], blob[12:], None) == DATA


def test_critical_is_mlkem1024_encapsulated_aes256(svc, tmp_path):
    dest, r = enc(svc, tmp_path, "Critical")
    assert "key" not in r.secrets and len(r.secrets["mlkem_seed"]) == 64
    assert len(base64.b64decode(r.params["kem_ciphertext"])) == 1568     # ML-KEM-1024 ciphertext
    from cryptography.hazmat.primitives.asymmetric import mlkem
    from services.encryption_service import mlkem as _m   # encryption/mlkem.py
    private = mlkem.MLKEM1024PrivateKey.from_seed_bytes(r.secrets["mlkem_seed"])
    key = _m.decapsulate_key(private, base64.b64decode(r.params["kem_ciphertext"]))
    blob = dest.read_bytes()
    assert AESGCM(key).decrypt(blob[:12], blob[12:], None) == DATA


@pytest.mark.parametrize("level", ["Low", "Standard", "Enhanced", "High", "Critical"])
def test_round_trip_and_tamper_detection(svc, tmp_path, level):
    dest, r = enc(svc, tmp_path, level)
    assert svc.decrypt_bytes(dest, r.algorithm, r.params, r.secrets) == DATA
    assert DATA[:20] not in dest.read_bytes()
    blob = bytearray(dest.read_bytes())
    blob[-1] ^= 1
    dest.write_bytes(bytes(blob))
    with pytest.raises(EncryptionError, match="corrupted"):
        svc.decrypt_bytes(dest, r.algorithm, r.params, r.secrets)


def test_nonce_is_unique_per_encryption(svc, tmp_path):
    nonces = set()
    for i in range(20):
        dest = tmp_path / f"n{i}.enc"
        svc.encrypt_data(DATA, dest, "High")
        nonces.add(dest.read_bytes()[:12])
    assert len(nonces) == 20


def test_wrong_key_and_missing_parts_give_clear_errors(svc, tmp_path):
    dest, r = enc(svc, tmp_path, "Standard")
    with pytest.raises(EncryptionError):
        svc.decrypt_bytes(dest, r.algorithm, r.params, {"key": b"\x00" * 32})
    with pytest.raises(EncryptionError, match="missing or invalid"):
        svc.decrypt_bytes(dest, r.algorithm, r.params, {})
    with pytest.raises(EncryptionError, match="missing from the vault"):
        svc.decrypt_bytes(tmp_path / "nope.enc", r.algorithm, r.params, r.secrets)
    with pytest.raises(EncryptionError, match="Unsupported"):
        svc.decrypt_bytes(dest, "ROT13", {}, r.secrets)


def test_unknown_level_is_not_substituted(svc, tmp_path):
    with pytest.raises(EncryptionError, match="No encryption algorithm"):
        svc.encrypt_data(DATA, tmp_path / "x.enc", "High/Critical")
    assert not (tmp_path / "x.enc").exists()


def test_no_partial_file_left_on_failure(svc, tmp_path, monkeypatch):
    monkeypatch.setattr(es.chacha, "encrypt_bytes", lambda *a: (_ for _ in ()).throw(RuntimeError("boom")))
    with pytest.raises(RuntimeError):
        svc.encrypt_data(DATA, tmp_path / "x.enc", "High")
    assert list(tmp_path.iterdir()) == []
