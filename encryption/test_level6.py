from mlkem import generate_mlkem_keys, encrypt_file, decrypt_file


print("\n--- LEVEL 6: AES-256 + ML-KEM-768 ---")


# Generate ML-KEM-768 key pair
private_key, public_key = generate_mlkem_keys()

print("ML-KEM-768 key pair generated.")


# Encrypt the test file
encrypt_file(
    "test.txt",
    "level6_encrypted.enc",
    public_key
)

print("File encrypted using AES-256-GCM + ML-KEM-768.")


# Decrypt the file
decrypt_file(
    "level6_encrypted.enc",
    "level6_decrypted.txt",
    private_key
)

print("File decrypted successfully.")


# Verify the decrypted file
with open("test.txt", "rb") as original:
    original_data = original.read()

with open("level6_decrypted.txt", "rb") as decrypted:
    decrypted_data = decrypted.read()


if original_data == decrypted_data:
    print("SUCCESS! Original and decrypted files match.")
    print("Level 6 encryption is working correctly.")
else:
    print("ERROR! Original and decrypted files do not match.")