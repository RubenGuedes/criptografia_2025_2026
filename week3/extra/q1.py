import ciphersuite_aesnotrand as ciphersuite
from binascii import hexlify, unhexlify
import base64

key = ciphersuite.gen() # ECB
msg = 'Attack at dawn!!'
cph = ciphersuite.enc(key, bytearray(msg,'ascii'))

f = open("weak_ciphertext", "wb")
f.write(cph)
f.close()

## 
# Extend me to
# 1 - Read ciphertext
f = open("weak_ciphertext", "rb")
file_data = f.read()

# Função auxiliar para gerar uma chave, dado um número inteiro
def gen_key(val):
	val_bytes = val.to_bytes((val.bit_length() + 7) // 8, 'big')
	offset = len(val_bytes)
	key_aux = bytearray(b'\x00' * (ciphersuite.KEYLEN-offset))
	key_aux.extend(val_bytes)
	return bytes(key_aux)

# 2 - Guess the key used
# Attack Brute-Force: Percorrer os números de 1 a (2**32) para tentar descobrir a chave 
msg_bytearr = bytearray(msg,'ascii')
for i in range(1, (2**32 + 1)):
	key_aux = gen_key(i)
		
	# 3 - Test the decryption
	pln_txt = ciphersuite.dec(key_aux, file_data)
	if (pln_txt == msg_bytearr):
		print("Chave Encontrada: {};\nMensagem Original: {}".format(key_aux, pln_txt))
		break