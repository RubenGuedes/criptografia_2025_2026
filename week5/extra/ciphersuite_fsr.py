# Python Module ciphersuite
import os
import random
from cryptography.hazmat.primitives import hashes

# Internal state of the LFSR
x = 1

# Call the lfsr to update the internal state
def __lfsr():
	global x
	x = (x**5 + x**4 + 1) % 1009

# Use crypto random generation to initialize the LFSR
def gen(): 
	global x
	sysrand = random.SystemRandom()
	x = sysrand.randint(0,1008)

# Bitwise XOR operation.
def enc(m):
	global x
	k = b""
	while (len(k) < len(m)):
		__lfsr()
		digest = hashes.Hash(hashes.SHA256())
		digest.update(x.to_bytes(4, "big"))
		k += digest.finalize()
	return bytearray([a ^ b for a,b in zip(m,k[:len(m)])])

# Reverse operation
def dec(c):
	global x
	k = b""
	while (len(k) < len(c)):
		__lfsr()
		digest = hashes.Hash(hashes.SHA256())
		digest.update(x.to_bytes(4, "big"))
		k += digest.finalize()
	return bytearray([a ^ b for a,b in zip(c, k[:len(m)])])
