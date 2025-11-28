from pwn import *

f = open("config_bob", "r")
hostAlice = f.readline()[:-1]
portAlice = int(f.readline())
hostBob = "localhost"
portBob = 5076
f.close()

r = remote(hostAlice, portAlice)
l = listen(portBob)
l.wait_for_connection()

g = 2
p = 7853799659

y = random.randint(1, p)
gy = pow(g, y, p) 

print("Sending GY: ", gy)
r.sendline(gy.to_bytes(8, "little"))

gx = int.from_bytes(l.recvline()[:-1], "little")
print("Received GX:", gx)

print("Shared secret: ", pow(gx, y, p))

l.close()
r.close()
