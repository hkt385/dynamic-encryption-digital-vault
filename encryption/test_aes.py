from aes import generate_key, encrypt_file, decrypt_file


# Generate AES-256 key
key = generate_key(32)

print("AES-256 key generated.")


# Encrypt
encrypt_file(
    "test.txt",
    "test.enc",
    key
)

print("File encrypted successfully.")


# Decrypt
decrypt_file(
    "test.enc",
    "decrypted.txt",
    key
)

print("File decrypted successfully.")


# Display the key
print("Key:", key.hex())