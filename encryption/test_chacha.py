from chacha import generate_key, encrypt_file, decrypt_file


print("\n--- LEVEL 5: ChaCha20-Poly1305 ---")

# Generate 256-bit key
key = generate_key()

print("ChaCha20-Poly1305 key generated.")
print("Key size:", len(key) * 8, "bits")


# Encrypt the test file
encrypt_file(
    "test.txt",
    "level5_encrypted.enc",
    key
)

print("File encrypted using ChaCha20-Poly1305.")


# Decrypt the file
decrypt_file(
    "level5_encrypted.enc",
    "level5_decrypted.txt",
    key
)

print("File decrypted successfully.")


# Verify the decrypted file
with open("test.txt", "rb") as original:
    original_data = original.read()

with open("level5_decrypted.txt", "rb") as decrypted:
    decrypted_data = decrypted.read()


if original_data == decrypted_data:
    print("SUCCESS! Original and decrypted files match.")
    print("Level 5 encryption is working correctly.")
else:
    print("ERROR! Original and decrypted files do not match.")