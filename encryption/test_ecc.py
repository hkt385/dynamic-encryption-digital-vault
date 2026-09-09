from ecc import generate_ecc_keys, derive_shared_key


print("\n--- ECC KEY ESTABLISHMENT TEST ---")


print("\nGenerating Alice's ECC keys...")

alice_private, alice_public = generate_ecc_keys()

print("Alice's keys generated.")


print("\nGenerating Bob's ECC keys...")

bob_private, bob_public = generate_ecc_keys()

print("Bob's keys generated.")


print("\nDeriving shared key for Alice...")

alice_shared_key = derive_shared_key(
    alice_private,
    bob_public
)

print("Alice derived the shared key.")


print("\nDeriving shared key for Bob...")

bob_shared_key = derive_shared_key(
    bob_private,
    alice_public
)

print("Bob derived the shared key.")


if alice_shared_key == bob_shared_key:
    print("\nSUCCESS: Both parties derived the same shared key!")
    print("ECC key establishment is working correctly.")
else:
    print("\nERROR: Shared keys do not match!")