import os
import binascii

def generate_aes_key():
    return os.urandom(16)

def format_key(key):
    return f"0x{binascii.hexlify(key).decode('utf-8').upper()}h"

def generate_custom_keys():
    return [generate_aes_key() for _ in range(5)]

def print_keys(keys):
    for i, key in enumerate(keys):
        print(f"appKey{i} = {format_key(key)}")
        print(f"APPLICATION_KEY_{i} = Utils.hexStringToByteArray(\"{binascii.hexlify(key).decode('utf-8').upper()}\")")
        print()

def print_personalization_steps(keys):
    print("Personalization steps for NTAG424DNA tag:")
    print("1) Authenticate with the DEFAULT appKey 0 (Master Application Key):")
    print("   0x00000000000000000000000000000000h")
    print("\n2) Change appKeys 1, 2, 3, and 4 to CUSTOM keys:")
    for i in range(1, 5):
        print(f"   appKey{i}: {format_key(keys[i])}")
    print("\n3) Change appKey 0 to CUSTOM key:")
    print(f"   appKey0: {format_key(keys[0])}")
    print("\nNOTE: Do NOT derive application key 3, as it's used for encrypted UID decryption.")
    print("\nOptional: To protect file 02, change its file settings to require authentication with appKey 0.")

if __name__ == "__main__":
    custom_keys = generate_custom_keys()
    print("Generated CUSTOM keys for NTAG424DNA:\n")
    print_keys(custom_keys)
    print_personalization_steps(custom_keys)
