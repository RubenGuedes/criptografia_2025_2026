import socket
import sys

from Cryptodome.Cipher import AES
from Cryptodome.Hash import HMAC, SHA256
from Cryptodome.Random import get_random_bytes

HOST = 'localhost'
PORT = 65432
ENC_KEY_SIZE = 16   # AES-128 
MAC_KEY_SIZE = 32   # SHA-256
AES_NONCE_SIZE = 8
MAC_SIZE = 32       # SHA256 digest size
SEQ_NUM_SIZE = 8    # 64-bit sequence number 

def recv_all(sock, n):
    """Auxiliary function to receive n bytes or return None if EOF is hit"""
    data = bytearray()
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data.extend(packet)
    return data

def secure_send(sock, message, enc_key, mac_key, seq_num):
    """
    Encrypts, MACs, and sends a message.
    Format: [4-byte LEN][8-byte NONCE][CIPHERTEXT][32-byte MAC]
    """
    print(f"ALICE (SND): '{message}' (EPOCH={seq_num})")
    
    # include a sequence number... and append it to the sent message
    seq_num_bytes = seq_num.to_bytes(SEQ_NUM_SIZE, 'big')
    plaintext = seq_num_bytes + message.encode('utf-8')

    # AES-128-CTR : encrypt
    cipher = AES.new(enc_key, AES.MODE_CTR)
    nonce = cipher.nonce
    ciphertext = cipher.encrypt(plaintext)

    # HMAC-SHA256 : mac
    mac = HMAC.new(mac_key, nonce + ciphertext, SHA256).digest()

    # nonce + ciphertext + mac
    payload = nonce + ciphertext + mac

    # prepend 4-byte length of the payload
    len_prefix = len(payload).to_bytes(4, 'big')
    
    sock.sendall(len_prefix + payload)

def secure_recv(sock, enc_key, mac_key, expected_seq_num):
    """
    Receives, verifies, and decrypts a message.
    Returns the decoded string or throws an exception on failure.
    """
    
    # read the 4-byte length prefix
    len_prefix_bytes = recv_all(sock, 4)
    if not len_prefix_bytes:
        raise ConnectionError("Connection closed by peer (reading length).")
    
    payload_len = int.from_bytes(len_prefix_bytes, 'big')

    # read the full payload
    payload = recv_all(sock, payload_len)
    if not payload:
        raise ConnectionError("Connection closed by peer (reading payload).")

    # parse the payload : [8-byte NONCE][CIPHERTEXT][32-byte MAC]
    nonce = payload[:AES_NONCE_SIZE]
    received_mac = payload[-MAC_SIZE:]
    ciphertext = payload[AES_NONCE_SIZE:-MAC_SIZE]

    # verify
    mac = HMAC.new(mac_key, nonce + ciphertext, SHA256)
    try:
        mac.verify(received_mac)
    except ValueError:
        print("!!! MESSAGE AUTHENTICATION FAILED !!!")
        raise SecurityException("Received invalid MAC!")

    # decrypt
    cipher = AES.new(enc_key, AES.MODE_CTR, nonce=nonce)
    decrypted_payload = cipher.decrypt(ciphertext)

    # parse the decrypted payload : [8-byte SEQ_NUM][MESSAGE]
    
    seq_num_bytes = decrypted_payload[:SEQ_NUM_SIZE]
    message_bytes = decrypted_payload[SEQ_NUM_SIZE:]
    
    received_seq_num = int.from_bytes(seq_num_bytes, 'big')

    if received_seq_num != expected_seq_num:
        print(f"!!! INVALID EPOCH (Expected: {expected_seq_num}, Got: {received_seq_num}) !!!")
        raise SecurityException("Invalid sequence number (possible replay attack)") 

    message = message_bytes.decode('utf-8')
    print(f"ALICE (RCV): '{message}' (EPOCH={received_seq_num})")
    return message


class SecurityException(Exception):
    pass

def main():
    # read pw to retrieve keys
    try:
        with open('pw', 'rb') as f:
            ENC_KEY = f.read(ENC_KEY_SIZE)
            MAC_KEY = f.read(MAC_KEY_SIZE)
            
            if len(ENC_KEY) != ENC_KEY_SIZE or len(MAC_KEY) != MAC_KEY_SIZE:
                print(f"Error: 'pw' file is corrupt or has wrong key sizes.")
                sys.exit(1)

    except FileNotFoundError:
        print("Error: 'pw' file not found. Run gen.py first.")
        sys.exit(1)
    except Exception as e:
        print(f"Error reading keys: {e}")
        sys.exit(1)

    # initialize sequence numbers, they serve as the epoch of the convo
    send_seq = 0
    recv_seq = 0

    # start chatting... using sockets 
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            print(f"Alice connecting to {HOST}:{PORT}...")
            s.connect((HOST, PORT))
            print("Connected to Bob.")
            
            try:
                # send "Hello Bob" to Bob
                secure_send(s, "Hello Bob", ENC_KEY, MAC_KEY, send_seq)
                send_seq += 1

                # receive "Hello Alice" from Bob
                msg = secure_recv(s, ENC_KEY, MAC_KEY, recv_seq)
                recv_seq += 1

                # send "I would like to have Francesinha" to Bob
                secure_send(s, "I would like to have Francesinha", ENC_KEY, MAC_KEY, send_seq)
                send_seq += 1

                # receive "Me too. Aviz?" from Bob
                msg = secure_recv(s, ENC_KEY, MAC_KEY, recv_seq)
                recv_seq += 1

                # send "Sure!" to Bob
                secure_send(s, "Sure!", ENC_KEY, MAC_KEY, send_seq)
                send_seq += 1

                print("\nConversation successful and complete.")

            except (SecurityException, ConnectionError, EOFError) as e:
                print(f"\n!!! Conversation HALTED due to error: {e} !!!")
            except Exception as e:
                print(f"\n!!! An unexpected error occurred: {e} !!!")
            finally:
                print("Closing connection.")
    
    except ConnectionRefusedError:
        print(f"Connection refused. Is bob.py running on {HOST}:{PORT}?")
    except Exception as e:
        print(f"Failed to connect: {e}")


if __name__ == "__main__":
    main()