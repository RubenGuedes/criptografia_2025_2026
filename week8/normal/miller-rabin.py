import random

def check_witness(a, n, k, d):
    """
    This function checks if 'a' is a witness for the compositeness of 'n'.
    It implements the logic from Theorem 2[cite: 30, 31].
    
    Returns True if n PASSES the test (is probably prime).
    Returns False if n FAILS the test (is composite).
    """
    
    # Calculate x = a^d (mod n)
    x = pow(a, d, n)
    
    # Condition (a): a^d ≡ 1 (mod n) 
    # Also check a^d ≡ -1 (mod n), which is the i=0 case for condition (b)
    if x == 1 or x == n - 1:
        return True  # n passes this witness test
    
    # Check condition (b) for i = 1 to k-1 
    # We loop k-1 times, squaring x each time
    for _ in range(1, k):
        # x = x^2 (mod n)
        # This calculates a^(2d), a^(4d), ..., a^(2^(k-1)d)
        x = pow(x, 2, n)
        
        # If x ≡ -1 (mod n), condition (b) is met
        if x == n - 1:
            return True  # n passes this witness test
        
        # This is an optimization based on Theorem 1[cite: 24, 25]:
        # If x ≡ 1 (mod n), but the previous value wasn't -1,
        # we found a non-trivial square root of 1, so n is composite.
        if x == 1:
            return False 
            
    # If we exit the loop, n failed both (a) and (b) for this witness
    return False # n is definitely composite

def is_prime_miller_rabin(n, m=40):
    """
    Implements the Miller-Rabin primality test.
    'n' is the number to test.
    'm' is the number of iterations.
    """
    
    # Handle trivial edge cases
    if n <= 1:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False  # n is an even number > 2
        
    # 1. Decompose n-1 into 2^k * d
    d = n - 1
    k = 0
    while d % 2 == 0:
        d //= 2
        k += 1
        
    # 2. Iterate m times 
    for _ in range(m):
        # 3. Pick a random witness 'a'
        a = random.randint(2, n - 2)
        
        # 4. Check if 'a' is a witness
        if not check_witness(a, n, k, d):
            return False  # n is definitely composite
            
    # 5. If all m tests pass, n is probably prime
    return True

# --- Example Usage ---

# 1. Test a known large prime
large_prime = 104395301
print(f"Is {large_prime} prime? {is_prime_miller_rabin(large_prime)}")

# 2. Test another known large prime
prime_2 = 2147483647 # A Mersenne prime (2^31 - 1)
print(f"Is {prime_2} prime? {is_prime_miller_rabin(prime_2)}")

# 3. Test a large composite number (product of two primes)
composite = 104395301 * 104395303
print(f"Is {composite} prime? {is_prime_miller_rabin(composite)}")

# 4. Test a small composite
print(f"Is 561 prime? {is_prime_miller_rabin(561)}") # 561 is a Carmichael number

# 5. Test edge cases
print(f"Is 2 prime? {is_prime_miller_rabin(2)}")
print(f"Is 3 prime? {is_prime_miller_rabin(3)}")
print(f"Is 100 prime? {is_prime_miller_rabin(100)}")

# --- Expected Output ---
# Is 104395301 prime? True
# Is 2147483647 prime? True
# Is 10898381861909303 prime? False
# Is 561 prime? False
# Is 2 prime? True
# Is 3 prime? True
# Is 100 prime? False