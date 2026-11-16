from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import mlkem
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# ML-KEM (FIPS 203, CRYSTALS-Kyber) is a key-encapsulation mechanism, not a
# cipher. It is used here only to establish a 256-bit AES key; the file itself
# is encrypted with AES-256-GCM (aes.py).
#
# ML-KEM-1024 is used (the parameter set intended for AES-256).

_HKDF_INFO = b"dynamic-encryption-digital-vault ML-KEM-1024 -> AES-256-GCM"


def generate_mlkem_keys():
    """
    Generate an ML-KEM-1024 key pair.

    Returns (private_key, public_key). The private key can be saved as a
    64-byte seed with private_seed() and restored with private_from_seed().
    """

    private_key = mlkem.MLKEM1024PrivateKey.generate()

    return private_key, private_key.public_key()


def private_seed(private_key):
    """
    Return the 64-byte seed that fully determines an ML-KEM-1024 private key.
    """

    return private_key.private_bytes_raw()


def private_from_seed(seed):
    """
    Rebuild an ML-KEM-1024 private key from its 64-byte seed.
    """

    return mlkem.MLKEM1024PrivateKey.from_seed_bytes(seed)


def _derive_aes_key(shared_secret):
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=_HKDF_INFO
    ).derive(shared_secret)


def encapsulate_key(public_key):
    """
    Create a fresh AES-256 key and its ML-KEM encapsulation.

    Returns (aes_key, kem_ciphertext). Only the ciphertext may be stored
    next to the encrypted file; the AES key must not be.
    """

    shared_secret, kem_ciphertext = public_key.encapsulate()

    return _derive_aes_key(shared_secret), kem_ciphertext


def decapsulate_key(private_key, kem_ciphertext):
    """
    Recover the AES-256 key from an ML-KEM encapsulation.
    """

    return _derive_aes_key(private_key.decapsulate(kem_ciphertext))
