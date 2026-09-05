import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def generate_key(security_level):
    """
    Generate an AES key based on the security level.

    Level 1 -> AES-128
    Level 2 -> AES-256
    """

    if security_level == 1:
        key_size = 16       # 128 bits

    elif security_level == 2:
        key_size = 32       # 256 bits

    else:
        raise ValueError("AES module supports only Level 1 and Level 2.")

    return AESGCM.generate_key(bit_length=key_size * 8)


def encrypt_file(input_file, output_file, key):
    """
    Encrypt a file using AES-GCM.
    """

    if len(key) not in (16, 32):
        raise ValueError("Invalid AES key size.")

    with open(input_file, "rb") as file:
        plaintext = file.read()

    # Generate a unique nonce for this encryption
    nonce = os.urandom(12)

    aes = AESGCM(key)

    ciphertext = aes.encrypt(
        nonce,
        plaintext,
        None
    )

    # Store nonce + encrypted data
    with open(output_file, "wb") as file:
        file.write(nonce)
        file.write(ciphertext)


def decrypt_file(input_file, output_file, key):
    """
    Decrypt an AES-GCM encrypted file.
    """

    if len(key) not in (16, 32):
        raise ValueError("Invalid AES key size.")

    with open(input_file, "rb") as file:
        encrypted_data = file.read()

    # First 12 bytes contain the nonce
    nonce = encrypted_data[:12]

    # Remaining bytes contain ciphertext + authentication tag
    ciphertext = encrypted_data[12:]

    aes = AESGCM(key)

    plaintext = aes.decrypt(
        nonce,
        ciphertext,
        None
    )

    with open(output_file, "wb") as file:
        file.write(plaintext)