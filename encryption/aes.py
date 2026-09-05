import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def generate_key(key_size=32):
    """Generate a secure AES key."""

    if key_size not in (16, 32):
        raise ValueError("Key size must be 16 or 32 bytes.")

    return AESGCM.generate_key(bit_length=key_size * 8)


def encrypt_file(input_file, output_file, key):
    """Encrypt a file using AES-GCM."""

    with open(input_file, "rb") as file:
        plaintext = file.read()

    nonce = os.urandom(12)

    aes = AESGCM(key)

    ciphertext = aes.encrypt(
        nonce,
        plaintext,
        None
    )

    with open(output_file, "wb") as file:
        file.write(nonce)
        file.write(ciphertext)


def decrypt_file(input_file, output_file, key):
    """Decrypt an AES-GCM encrypted file."""

    with open(input_file, "rb") as file:
        encrypted_data = file.read()

    nonce = encrypted_data[:12]
    ciphertext = encrypted_data[12:]

    aes = AESGCM(key)

    plaintext = aes.decrypt(
        nonce,
        ciphertext,
        None
    )

    with open(output_file, "wb") as file:
        file.write(plaintext)