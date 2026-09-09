from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def generate_ecc_keys():
    """
    Generate an ECC private/public key pair.
    Uses the NIST P-256 curve.
    """

    private_key = ec.generate_private_key(
        ec.SECP256R1()
    )

    public_key = private_key.public_key()

    return private_key, public_key


def derive_shared_key(private_key, peer_public_key):
    """
    Derive a shared secret using ECDH.

    Both parties can independently derive
    the same shared secret.
    """

    shared_secret = private_key.exchange(
        ec.ECDH(),
        peer_public_key
    )

    # Convert the shared secret into a usable
    # 256-bit symmetric key using HKDF.
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"dynamic-encryption-digital-vault"
    ).derive(shared_secret)

    return derived_key