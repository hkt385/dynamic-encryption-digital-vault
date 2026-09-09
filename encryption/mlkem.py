from cryptography.hazmat.primitives.asymmetric import mlkem
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os


def generate_mlkem_keys():
    """
    Generate an ML-KEM-768 private/public key pair.
    """

    private_key = mlkem.MLKEM768PrivateKey.generate()
    public_key = private_key.public_key()

    return private_key, public_key


def encrypt_file(input_file, output_file, public_key):
    """
    Encrypt a file using ML-KEM-768 + AES-256-GCM.

    ML-KEM establishes a shared secret.
    AES-256-GCM encrypts the actual file.
    """

    with open(input_file, "rb") as file:
        plaintext = file.read()

    # Generate a shared secret and ML-KEM ciphertext.
    shared_secret, kem_ciphertext = public_key.encapsulate()

    # ML-KEM shared secret is 256 bits.
    aes_key = shared_secret

    # Generate a 12-byte AES-GCM nonce.
    nonce = os.urandom(12)

    aes = AESGCM(aes_key)

    ciphertext = aes.encrypt(
        nonce,
        plaintext,
        None
    )

    # File format:
    # [ML-KEM ciphertext][AES nonce][AES ciphertext + tag]
    with open(output_file, "wb") as file:
        file.write(kem_ciphertext)
        file.write(nonce)
        file.write(ciphertext)


def decrypt_file(input_file, output_file, private_key):
    """
    Decrypt an ML-KEM-768 + AES-256-GCM encrypted file.
    """

    with open(input_file, "rb") as file:
        encrypted_data = file.read()

    # ML-KEM-768 ciphertext is 1088 bytes.
    kem_ciphertext = encrypted_data[:1088]

    # Next 12 bytes are the AES-GCM nonce.
    nonce = encrypted_data[1088:1100]

    # Remaining data is AES ciphertext + authentication tag.
    ciphertext = encrypted_data[1100:]

    # Recover the shared secret using ML-KEM decapsulation.
    shared_secret = private_key.decapsulate(kem_ciphertext)

    aes_key = shared_secret

    aes = AESGCM(aes_key)

    plaintext = aes.decrypt(
        nonce,
        ciphertext,
        None
    )

    with open(output_file, "wb") as file:
        file.write(plaintext)