from aes import generate_key, encrypt_file, decrypt_file
from ecc import generate_ecc_keys, derive_shared_key
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os


print("\n--- LEVEL 4: AES-256 + ECC ---")


# -------------------------------------------------
# 1. Generate ECC keys
# -------------------------------------------------

print("\nGenerating ECC keys...")

owner_private, owner_public = generate_ecc_keys()
recipient_private, recipient_public = generate_ecc_keys()

print("ECC key pairs generated.")


# -------------------------------------------------
# 2. Derive shared ECC key
# -------------------------------------------------

print("\nDeriving ECC shared key...")

owner_shared_key = derive_shared_key(
    owner_private,
    recipient_public
)

recipient_shared_key = derive_shared_key(
    recipient_private,
    owner_public
)

if owner_shared_key != recipient_shared_key:
    raise ValueError("ECC shared keys do not match!")

print("ECC shared key established.")


# -------------------------------------------------
# 3. Generate AES-256 key
# -------------------------------------------------

print("\nGenerating AES-256 document key...")

aes_key = generate_key(2)

print("AES-256 key generated.")


# -------------------------------------------------
# 4. Encrypt the document using AES-256
# -------------------------------------------------

print("\nEncrypting document using AES-256...")

encrypt_file(
    "test.txt",
    "level4_encrypted.enc",
    aes_key
)

print("Document encrypted successfully.")


# -------------------------------------------------
# 5. Protect AES key using ECC-derived key
# -------------------------------------------------

print("\nProtecting AES key using ECC-derived key...")

key_nonce = os.urandom(12)

key_wrapper = AESGCM(owner_shared_key)

encrypted_aes_key = key_wrapper.encrypt(
    key_nonce,
    aes_key,
    None
)

print("AES-256 key protected successfully.")


# -------------------------------------------------
# 6. Recover AES key using ECC-derived key
# -------------------------------------------------

print("\nRecovering AES-256 key...")

key_unwrapper = AESGCM(recipient_shared_key)

recovered_aes_key = key_unwrapper.decrypt(
    key_nonce,
    encrypted_aes_key,
    None
)

print("AES-256 key recovered successfully.")


# -------------------------------------------------
# 7. Decrypt the document
# -------------------------------------------------

print("\nDecrypting document...")

decrypt_file(
    "level4_encrypted.enc",
    "level4_decrypted.txt",
    recovered_aes_key
)

print("Document decrypted successfully.")


# -------------------------------------------------
# 8. Verify original and decrypted files
# -------------------------------------------------

with open("test.txt", "rb") as original:
    original_data = original.read()

with open("level4_decrypted.txt", "rb") as decrypted:
    decrypted_data = decrypted.read()


if original_data == decrypted_data:

    print("\nSUCCESS!")
    print("Original and decrypted files match.")
    print("Level 4 AES-256 + ECC encryption is working correctly.")

else:

    print("\nERROR!")
    print("Original and decrypted files do not match.")