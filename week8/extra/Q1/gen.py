import os

from Cryptodome.Random import get_random_bytes

# AES-128 key size is 16 bytes
ENC_KEY_SIZE = 16
# HMAC-SHA256 key size (using 32 bytes / 256 bits)
MAC_KEY_SIZE = 32

# gen 16-byte key for AES-128 encryption
enc_key = get_random_bytes(ENC_KEY_SIZE)

# gen 32-byte key for HMAC-SHA256
mac_key = get_random_bytes(MAC_KEY_SIZE)

try:
    with open('pw', 'wb') as f:
        f.write(enc_key) # one to be used for encryption
        f.write(mac_key) # the other to be used for message authentication
    print(f"Generated 'pw' with {ENC_KEY_SIZE}-byte ENC key and {MAC_KEY_SIZE}-byte MAC key.")

except IOError as e:
    print(f"Error generating 'pw': {e}")