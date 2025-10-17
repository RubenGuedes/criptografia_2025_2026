from cryptography.hazmat.primitives import hashes
from binascii import hexlify, unhexlify
import os
import numpy as np

# The most common passwords of 2019.
passwds = ['123456','123456789','qwerty','password','1234567','12345678','12345','iloveyou','111111','123123','abc123','qwerty123','1q2w3e4r','admin','qwertyuiop','654321','555555','lovely','7777777','welcome']

### Non-salt version

# Get their hex versions
hex_passwds = []
for pwd in passwds:
	hex_passwds.append(hexlify(pwd.encode()))

# Hash all the passwords
hlist = []
for pwd in hex_passwds:
	digest = hashes.Hash(hashes.SHA256())
	digest.update(pwd)
	hlist.append(hexlify(digest.finalize()))

#### Salt version

# Random salt of 1 byte
salt_passwds = []
salt = os.urandom(1)

# The same passwords, but now with the random salt prepended
for pwd in hex_passwds:
	salt_passwds.append(salt+pwd)

# Hash all salted passwords
shlist = []
for pwd in salt_passwds:
	digest = hashes.Hash(hashes.SHA256())
	digest.update(pwd)
	shlist.append(hexlify(digest.finalize()))

### Lets mix it up
# numpy 1.5.0 required!
mixed_hlist = np.random.permutation(hlist)
mixed_shlist = np.random.permutation(shlist)

### Exercise 1 - Crack unsalted hashes
# Show that it is trivial to take a set of hashed passwords and know their corresponding passwords, with knowledge of "good" candidates
# Taxe "mixed_hlist" (a shuffled version of password hashes) and "hex_passwds" (the hexlify list of candidates) and produce a list of "cracked_pwds". This should be a decoding of "mixed_hlist": for each hash in "mixed_hlist", "cracked_pwds" should have its original password.
## Important! ## Do not use any other information. That is cheating :-)  

cracked_pwds = []

# --------------------------- START OF EXERCISE 1 ---------------------------

# build a map from hash -> original hex-encoded password bytes
hash_to_pwd = {}
for pwd in hex_passwds:
	digest = hashes.Hash(hashes.SHA256())
	digest.update(pwd)
	phash = hexlify(digest.finalize())
	hash_to_pwd[phash] = pwd

# reconstruct in the shuffled order
for hash in mixed_hlist:
	cracked_pwds.append(hash_to_pwd[hash])

# --------------------------- END OF EXERCISE 1 ---------------------------

# Lets see if your list is correct
i = 0
for pwd in cracked_pwds:
	digest = hashes.Hash(hashes.SHA256())
	digest.update(pwd)
	if (mixed_hlist[i] == hexlify(digest.finalize())):
		print(i, "Check")
	i += 1

### Exercise 2 - Crack salted hashes
# Now we show that salting makes it more challenging, but it is still doable. The scenario is still quite simple: each password was hashed with a small salt (but all of them with the same one!). Can you do the same thing?
# Take "mixed_shlist" (a shuffled version of password salted hashes) and "hex_passwds" (the hexlify list of candidates) and produce a list of "cracked_pwds". This should be a decoding of "mixed_hlist": for each hash in "mixed_hlist", "cracked_pwds" should have its original password.
## Important! ## Do not use any other information. That is still cheating :-)  

cracked_spwds = []

# ------------------------------- START OF EXERCISE 2 -------------------------------

# brute force the 1-byte salt
target_set = set(mixed_shlist.tolist() if hasattr(mixed_shlist, 'tolist') else mixed_shlist)
salt_found = None
hash_to_salted_pwd = None

for s in range(256):
	candidate_salt = bytes([s])
	local_map = {}
	local_hashes = []
	for pwd in hex_passwds:
		_digest = hashes.Hash(hashes.SHA256())
		_digest.update(candidate_salt + pwd)
		h = hexlify(_digest.finalize())
		local_hashes.append(h)
		local_map[h] = candidate_salt + pwd
	
	# compare
	if set(local_hashes) == target_set:
		salt_found = candidate_salt
		hash_to_salted_pwd = local_map
		break

# if salt found, reconstruct in shuffled order
if hash_to_salted_pwd is not None:
	for h in mixed_shlist:
		cracked_spwds.append(hash_to_salted_pwd[h])

# ------------------------------- END OF EXERCISE 2 -------------------------------

i = 0
for pwd in cracked_spwds:
	digest = hashes.Hash(hashes.SHA256())
	digest.update(pwd)
	if (mixed_shlist[i] == hexlify(digest.finalize())):
		print(i, "Check")
	i += 1
