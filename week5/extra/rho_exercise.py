from cryptography.hazmat.primitives import hashes
import os

L = 5 # output length in bytes

# Something to make calling hash functions more succint
def H(X):
	digest = hashes.Hash(hashes.SHA256())
	digest.update(X)
	return (digest.finalize()[0:L])

# Write a function that finds the collision and presents the values in which it occurred
def rho(h0):
	print("Hash is "+str(8*L)+" bits")

	# --------------- START OF EXERCISE 2 --------------------

	hi = h0		  # single-step pointer
	hi_prime = h0 # double-step pointer

	# h2 = H(h1), h2_prime = H(H(h1_prime)) where h1=h1_prime=h0 (loop starts with i = 1)
	hi = H(hi)
	hi_prime = H(H(hi_prime))
	

	# iterate until the hash values are equal -> loop found
	while hi != hi_prime:
		# next values: h_i+2 = H(h_i+1) and h'_i+2 = H(H(h'_i+1))
		hi = H(hi)
		hi_prime = H(H(hi_prime))

	# loop found, now get the collision point (start of the loop)

	m0 = h0 # first pointer (moves one step)
	m1 = hi # second pointer (already at the meeting point)

	# advance both pointers one step at a time until the next hash value is equal
	while H(m0) != H(m1):
		m0 = H(m0)
		m1 = H(m1)

	print("Collision found! :-)")

	# --------------- END OF EXERCISE 2 --------------------

	# return the collision pair (m0, m1)
	return (m0, m1)

start = os.urandom(L)
(h0, h1) = rho(start)
print(h0)
print(h1)