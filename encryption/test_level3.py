from aes import generate_key, encrypt_file, decrypt_file
from rsa import generate_rsa_keys, encrypt_aes_key, decrypt_aes_key


print("\n--- LEVEL 3: AES-256 + RSA-4096 ---")


# 1. Generate RSA-4096 key pair
print("\nGenerating RSA-4096 keys...")

private_key, public_key = generate_rsa_keys()

print("RSA-4096 keys generated.")


# 2. Generate AES-256 key
print("\nGenerating AES-256 key...")

aes_key = generate_key(2)

print("AES-256 key generated.")


# 3. Encrypt the file using AES-256
print("\nEncrypting file using AES-256...")

encrypt_file(
    "test.txt",
    "level3_encrypted.enc",
    aes_key
)

print("File encrypted successfully.")


# 4. Encrypt the AES key using RSA-4096
print("\nEncrypting AES key using RSA-4096...")

encrypted_aes_key = encrypt_aes_key(
    aes_key,
    public_key
)

print("AES key protected with RSA-4096.")


# 5. Decrypt the AES key using RSA private key
print("\nDecrypting AES key using RSA-4096...")

decrypted_aes_key = decrypt_aes_key(
    encrypted_aes_key,
    private_key
)

print("AES key recovered successfully.")


# 6. Decrypt the file using the recovered AES key
print("\nDecrypting file using AES-256...")

decrypt_file(
    "level3_encrypted.enc",
    "level3_decrypted.txt",
    decrypted_aes_key
)

print("File decrypted successfully.")


# 7. Verify the result
with open("test.txt", "rb") as original:
    original_data = original.read()

with open("level3_decrypted.txt", "rb") as decrypted:
    decrypted_data = decrypted.read()


if original_data == decrypted_data:
    print("\nSUCCESS: Original and decrypted files match!")
    print("Level 3 encryption is working correctly.")
else:
    print("\nERROR: Files do not match!")