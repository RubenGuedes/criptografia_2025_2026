from pwn import *

# --- 1. Setup Network Topology ---
# Configuration matching our modified config files
mitm_port_for_alice = 9000  # Alice connects here (config_alice)
mitm_port_for_bob   = 9001  # Bob connects here (config_bob)

# The actual listeners where Alice and Bob are waiting for input
real_alice_port = 5075
real_bob_port   = 5076

# Setup Listeners to catch the victims' outgoing connections
print(f"[*] Setting up MitM listeners on {mitm_port_for_alice} and {mitm_port_for_bob}...")
listener_alice = listen(mitm_port_for_alice)
listener_bob   = listen(mitm_port_for_bob)

print("[*] Waiting for Alice and Bob to start and connect...")
# We wait for them to connect to us
alice_incoming = listener_alice.wait_for_connection()
bob_incoming   = listener_bob.wait_for_connection()

print("[*] Both victims connected to MitM. Establishing connections to their listeners...")
# Now we connect to their actual listening ports
to_alice_listener = remote('localhost', real_alice_port)
to_bob_listener   = remote('localhost', real_bob_port)

# --- 2. Crypto Parameters ---
g = 2
p = 7853799659

# Generate MitM's malicious secret
m = random.randint(1, p)
gm = pow(g, m, p) # The attacker's public key (g^m)
print(f"\n[!] Attacker Generated g^m: {gm}")

# --- 3. The Exchange Logic ---

# We need to look at the source code order to prevent deadlock.
# Bob.py: Sends GY -> Receives GX
# Alice.py: Receives GY -> Sends GX

# STEP A: Intercept Bob's GY
# Bob connects to his 'remote' (which is us, bob_incoming) and sends GY immediately.
print("\n[->] Receiving GY from Bob...")
gy_bytes = bob_incoming.recvline() # Read line cleanly including newline
gy = int.from_bytes(gy_bytes[:-1], "little") # Strip newline, convert
print(f"     Intercepted GY: {gy}")

# STEP B: Trick Alice
# Alice is waiting on her listener (to_alice_listener) for a key.
# We send her our malicious key (GM) pretending it's from Bob.
print(f"[<-] Sending GM to Alice (pretending to be Bob)...")
to_alice_listener.sendline(gm.to_bytes(8, "little"))

# STEP C: Intercept Alice's GX
# Alice computes her secret (GM^x), then sends GX to her remote (alice_incoming).
print("[->] Receiving GX from Alice...")
gx_bytes = alice_incoming.recvline()
gx = int.from_bytes(gx_bytes[:-1], "little")
print(f"     Intercepted GX: {gx}")

# STEP D: Trick Bob
# Bob is waiting on his listener (to_bob_listener) for a key.
# We send him our malicious key (GM) pretending it's from Alice.
print(f"[<-] Sending GM to Bob (pretending to be Alice)...")
to_bob_listener.sendline(gm.to_bytes(8, "little"))

# --- 4. Calculate Secrets ---

# Alice computed: (GM)^x  == (g^m)^x == g^mx
# MitM computes:  (GX)^m  == (g^x)^m == g^mx
secret_alice = pow(gx, m, p)

# Bob computed:   (GM)^y  == (g^m)^y == g^my
# MitM computes:  (GY)^m  == (g^y)^m == g^my
secret_bob = pow(gy, m, p)

print("\n" + "="*40)
print("             ATTACK SUCCESSFUL")
print("="*40)
print(f"Alice's Secret (g^mx): {secret_alice}")
print(f"Bob's Secret   (g^my): {secret_bob}")
print("="*40)

# Clean up
listener_alice.close()
listener_bob.close()
to_alice_listener.close()
to_bob_listener.close()
alice_incoming.close()
bob_incoming.close()