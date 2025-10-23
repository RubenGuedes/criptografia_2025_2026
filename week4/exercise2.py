import os
import subprocess

def rc4(data: bytes, key: bytes) -> bytes:
    # KSA
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]

    # PRGA
    i = j = 0
    result = bytearray()
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        k = S[(S[i] + S[j]) % 256]
        result.append(byte ^ k)
    return bytes(result)


def main():
    key = bytes.fromhex("539a7f12cd4b08e3a15d369c27fa40b2") # generate 128-bit key 

    input_file = "input.txt"
    encrypted_file = "encrypted.bin"
    decrypted_file = "decrypted.txt"
    
    ssl_encrypted_file = "encrypted_by_ssl.bin"
    ssl_decrypted_from_ssl_by_python = "decrypted_from_ssl_by_python.txt"
    ssl_decrypted_from_python_file = "decrypted_from_python_by_ssl.txt"

    # encrypt
    with open(input_file, "rb") as f:
        plaintext = f.read()
    ciphertext = rc4(plaintext, key)
    with open(encrypted_file, "wb") as f:
        f.write(ciphertext)
    print(f"Encrypted '{input_file}' -> '{encrypted_file}'")

    # decrypt
    with open(encrypted_file, "rb") as f:
        encrypted_data = f.read()
    decrypted = rc4(encrypted_data, key)
    with open(decrypted_file, "wb") as f:
        f.write(decrypted)
    print(f"Decrypted '{encrypted_file}' -> '{decrypted_file}'")

    # verify
    if plaintext == decrypted:
        print("SUCCESS: Files match.")
    else:
        print("ERROR: Files differ.")

    # decrypt file encrypted by OpenSSL 
    if os.path.exists(ssl_encrypted_file):
        with open(ssl_encrypted_file, "rb") as f:
            ssl_encrypted_data = f.read()
        ssl_decrypted = rc4(ssl_encrypted_data, key)
        with open(ssl_decrypted_from_ssl_by_python, "wb") as f:
            f.write(ssl_decrypted)
        print(f"Decrypted '{ssl_encrypted_file}' -> '{ssl_decrypted_from_ssl_by_python}'")

        # verify
        if plaintext == ssl_decrypted:
            print("SUCCESS: Files match.")
        else:
            print("ERROR: Files differ.")
    else:
        print("Note: OpenSSL-encrypted file not found. Create it with the following command:\n"
              "openssl enc -rc4 -in input.txt -out encrypted_by_ssl.bin -K 539a7f12cd4b08e3a15d369c27fa40b2 -nosalt -provider legacy")

if __name__ == "__main__":
    main()
