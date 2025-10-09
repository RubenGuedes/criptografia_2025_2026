# Python Module ciphersuite
import os
import random
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Security parameter (fixed)
KEYLEN = 16

# Use crypto random generation to get a key with up to 3 random bytes
def gen(): 
	sysrand = random.SystemRandom()
	offset = sysrand.randint(1,3)
	key = bytearray(b'\x00'*(KEYLEN-offset)) 
	key.extend(os.urandom(offset))
	return bytes(key)

def enc(k, m):
	cipher = Cipher(algorithms.AES(k), modes.ECB())
	encryptor = cipher.encryptor()
	cph = b""
	cph += encryptor.update(m)
	cph += encryptor.finalize()
	return cph

def dec(k, c):
	cipher = Cipher(algorithms.AES(k), modes.ECB())
	decryptor = cipher.decryptor()
	msg = b""
	msg += decryptor.update(c)
	msg += decryptor.finalize()
	return msg
