from pwn import *
import random

PRIME = 9876543211
GENERATOR = 2

def parse_config(filename):
    with open(filename, "r") as f:
        lines = f.read().splitlines()
    return lines[0], int(lines[1])

def init():
    connections = {}
    
    # load configs
    host_a, port_a = parse_config("config_bob") 
    host_b, port_b = parse_config("config_alice")

    # establish connections

    # remote alice
    connections['rAlice'] = remote(host_a, port_a)
    
    # listen for alice and wait
    connections['lAlice'] = listen(port_b)
    connections['lAlice'].wait_for_connection()

    # listen for bob and wait
    connections['lBob'] = listen(port_a)
    connections['lBob'].wait_for_connection()

    # remote bob
    connections['rBob'] = remote(host_b, port_b)
    
    return connections

def generate_secret():
    return random.randint(1, PRIME)

def calc_pub(private_exp):
    return pow(GENERATOR, private_exp, PRIME)

def bytes_to_int(raw_bytes):
    return int.from_bytes(raw_bytes, "little")

def int_to_bytes(num):
    return num.to_bytes(8, "little")

def exploit(connections):
    l_bob = connections['lBob']
    r_alice = connections['rAlice']
    l_alice = connections['lAlice']
    r_bob = connections['rBob']

    # bob's public key
    raw_gy = l_bob.recvline()[:-1]
    gy = bytes_to_int(raw_gy)
    print("Received GY from Bob:", gy)

    # inject malicious C
    c = generate_secret()
    gc = calc_pub(c)

    print("Sending GC to Alice:", gc)
    r_alice.sendline(int_to_bytes(gc))

    # alice's public key
    raw_gx = l_alice.recvline()[:-1]
    gx = bytes_to_int(raw_gx)
    print("Received GX from Alice:", gx)

    # inject malicious D
    d = generate_secret()
    gd = calc_pub(d)

    print("Sending GD to Bob:", gd)
    r_bob.sendline(int_to_bytes(gd))

    # retrieve shared secrets
    secret_alice = pow(gx, c, PRIME)
    secret_bob = pow(gy, d, PRIME)

    print("Shared secret with Alice:", secret_alice)
    print("Shared secret with Bob:", secret_bob)

def cleanup(connections):
    if 'lAlice' in connections:
        connections['lAlice'].close()
    if 'rAlice' in connections:
        connections['rAlice'].close()

if __name__ == "__main__":
    conns = init()
    try:
        exploit(conns)
    finally:
        cleanup(conns)