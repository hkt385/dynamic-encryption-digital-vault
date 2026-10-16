import os
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


def generate_key():
    """
    Generate a random 256-bit ChaCha20-Poly1305 key.
    """

    return ChaCha20Poly1305.generate_key()


def encrypt_bytes(plaintext, key):
    """
    Encrypt data held in memory with ChaCha20-Poly1305.
    Returns nonce (12 bytes) + ciphertext + 16-byte Poly1305 tag.
    A fresh random 96-bit nonce is generated for every call, and every
    file gets its own key, so a (key, nonce) pair is never reused.
    """

    if len(key) != 32:
        raise ValueError("Invalid ChaCha20-Poly1305 key size.")

    nonce = os.urandom(12)

    return nonce + ChaCha20Poly1305(key).encrypt(
        nonce,
        plaintext,
        None
    )


def encrypt_file(input_file, output_file, key):
    """
    Encrypt a file using ChaCha20-Poly1305 (authenticated encryption).

    File layout: 12-byte nonce + ciphertext + 16-byte Poly1305 tag.
    """

    with open(input_file, "rb") as file:
        plaintext = file.read()

    with open(output_file, "wb") as file:
        file.write(encrypt_bytes(plaintext, key))


def decrypt_bytes(input_file, key):
    """
    Decrypt a ChaCha20-Poly1305 file and return the plaintext in memory.
    Raises cryptography.exceptions.InvalidTag on a wrong key or tampering.
    """

    if len(key) != 32:
        raise ValueError("Invalid ChaCha20-Poly1305 key size.")

    with open(input_file, "rb") as file:
        encrypted_data = file.read()

    nonce = encrypted_data[:12]
    ciphertext = encrypted_data[12:]

    return ChaCha20Poly1305(key).decrypt(
        nonce,
        ciphertext,
        None
    )


def decrypt_file(input_file, output_file, key):
    """
    Decrypt a ChaCha20-Poly1305 encrypted file.
    """

    plaintext = decrypt_bytes(input_file, key)

    with open(output_file, "wb") as file:
        file.write(plaintext)
