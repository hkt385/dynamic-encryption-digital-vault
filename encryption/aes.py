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


def encrypt_bytes(plaintext, key):
    """
    Encrypt data held in memory with AES-GCM.
    Returns nonce (12 bytes) + ciphertext + authentication tag.
    """

    if len(key) not in (16, 32):
        raise ValueError("Invalid AES key size.")

    # Generate a unique nonce for this encryption
    nonce = os.urandom(12)

    aes = AESGCM(key)

    ciphertext = aes.encrypt(
        nonce,
        plaintext,
        None
    )

    return nonce + ciphertext


def encrypt_file(input_file, output_file, key):
    """
    Encrypt a file using AES-GCM.
    """

    with open(input_file, "rb") as file:
        plaintext = file.read()

    # Store nonce + encrypted data
    with open(output_file, "wb") as file:
        file.write(encrypt_bytes(plaintext, key))


def decrypt_bytes(input_file, key):
    """
    Decrypt an AES-GCM encrypted file and return the plaintext in memory
    (nothing is written to disk). Raises cryptography.exceptions.InvalidTag
    if the key is wrong or the file was modified.
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

    return aes.decrypt(
        nonce,
        ciphertext,
        None
    )


def decrypt_file(input_file, output_file, key):
    """
    Decrypt an AES-GCM encrypted file.
    """

    plaintext = decrypt_bytes(input_file, key)

    with open(output_file, "wb") as file:
        file.write(plaintext)
