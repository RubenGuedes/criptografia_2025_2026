from pwn import *

f = open("config_alice", "r")
hostAlice = "localhost"
portAlice = 5075
hostBob = f.readline()[:-1]
portBob = int(f.readline())
f.close()

l = listen(portAlice)
l.wait_for_connection()
r = remote(hostBob, portBob)

g = 2
p = 7853799659

x = random.randint(1, p)
gx = pow(g, x, p) 

gy = int.from_bytes(l.recvline()[:-1], "little")
print("Received GY:", gy)

print("Sending GX: ", gx)
r.sendline(gx.to_bytes(8, "little"))

print("Shared secret: ", pow(gy, x, p))

l.close()
r.close() 
