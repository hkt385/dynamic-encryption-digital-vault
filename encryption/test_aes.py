from aes import generate_key, encrypt_file, decrypt_file


# =========================
# LEVEL 1 - AES-128
# =========================

print("\n--- LEVEL 1: AES-128 ---")

key_128 = generate_key(1)

print("AES-128 key generated.")
print("Key size:", len(key_128) * 8, "bits")

encrypt_file(
    "test.txt",
    "level1.enc",
    key_128
)

print("File encrypted using AES-128.")

decrypt_file(
    "level1.enc",
    "level1_decrypted.txt",
    key_128
)

print("File decrypted successfully.")


# =========================
# LEVEL 2 - AES-256
# =========================

print("\n--- LEVEL 2: AES-256 ---")

key_256 = generate_key(2)

print("AES-256 key generated.")
print("Key size:", len(key_256) * 8, "bits")

encrypt_file(
    "test.txt",
    "level2.enc",
    key_256
)

print("File encrypted using AES-256.")

decrypt_file(
    "level2.enc",
    "level2_decrypted.txt",
    key_256
)

print("File decrypted successfully.")