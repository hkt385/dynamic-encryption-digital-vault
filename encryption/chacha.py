import os
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


def generate_key():
    """
    Generate a 256-bit key for ChaCha20-Poly1305.
    """

    return ChaCha20Poly1305.generate_key()


def encrypt_file(input_file, output_file, key):
    """
    Encrypt a file using ChaCha20-Poly1305.
    """

    if len(key) != 32:
        raise ValueError("ChaCha20-Poly1305 requires a 256-bit key.")

    with open(input_file, "rb") as file:
        plaintext = file.read()

    # ChaCha20-Poly1305 uses a 12-byte nonce.
    nonce = os.urandom(12)

    cipher = ChaCha20Poly1305(key)

    ciphertext = cipher.encrypt(
        nonce,
        plaintext,
        None
    )

    # Store nonce together with ciphertext.
    with open(output_file, "wb") as file:
        file.write(nonce)
        file.write(ciphertext)


def decrypt_file(input_file, output_file, key):
    """
    Decrypt a ChaCha20-Poly1305 encrypted file.
    """

    if len(key) != 32:
        raise ValueError("ChaCha20-Poly1305 requires a 256-bit key.")

    with open(input_file, "rb") as file:
        encrypted_data = file.read()

    # First 12 bytes contain the nonce.
    nonce = encrypted_data[:12]

    # Remaining bytes contain ciphertext + authentication tag.
    ciphertext = encrypted_data[12:]

    cipher = ChaCha20Poly1305(key)

    plaintext = cipher.decrypt(
        nonce,
        ciphertext,
        None
    )

    with open(output_file, "wb") as file:
        file.write(plaintext)