from rsa import generate_rsa_keys, encrypt_aes_key, decrypt_aes_key
from aes import generate_key


print("Generating RSA-4096 keys...")

private_key, public_key = generate_rsa_keys()

print("RSA-4096 keys generated.")


print("Generating AES-256 key...")

aes_key = generate_key(2)

print("AES-256 key generated.")


print("Encrypting AES key with RSA...")

encrypted_key = encrypt_aes_key(
    aes_key,
    public_key
)

print("AES key encrypted successfully.")


print("Decrypting AES key with RSA...")

decrypted_key = decrypt_aes_key(
    encrypted_key,
    private_key
)

print("AES key decrypted successfully.")


if aes_key == decrypted_key:
    print("SUCCESS: Original and decrypted AES keys match!")
else:
    print("ERROR: Keys do not match!")