# Encrypt with openssl
openssl enc -rc4 -in input.txt -out encrypted_by_ssl.bin -K 539a7f12cd4b08e3a15d369c27fa40b2  -nosalt -provider legacy 

# Decrypt Python-encrypted file with OpenSSL s
openssl enc -rc4 -d -in encrypted.bin -out decrypted_from_python_by_ssl.txt -K 539a7f12cd4b08e3a15d369c27fa40b2 -nosalt -provider legacy 