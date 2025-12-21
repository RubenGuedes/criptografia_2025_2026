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
    """
    print(f"SENDING: '{message}' (EPOCH={seq_num})")
    
    # AES-CTR Encryption
    cipher = AES.new(enc_key, AES.MODE_CTR)
    nonce = cipher.nonce
    ciphertext = cipher.encrypt(message.encode('utf-8'))
    
    # Prepare Sequence Number and Length Prefix
    seq_bytes = seq_num.to_bytes(SEQ_NUM_SIZE, 'big')
    mac_size = 32
    payload_len = len(seq_bytes) + len(nonce) + len(ciphertext) + mac_size
    len_bytes = payload_len.to_bytes(4, 'big')

    # HMAC Authentication
    aad = len_bytes + seq_bytes + nonce + ciphertext
    mac = HMAC.new(mac_key, aad, SHA256).digest()

    # Construct Final Packet
    # [LEN][SEQ][NONCE][CIPHERTEXT][MAC]
    final_packet = len_bytes + seq_bytes + nonce + ciphertext + mac
    
    sock.sendall(final_packet)

def secure_recv(sock, enc_key, mac_key, expected_seq_num):
    """
    Receives, authenticates header/payload, checks sequence, then decrypts.
    """
    
    # Read the length prefix first
    len_bytes = recv_all(sock, 4)
    if not len_bytes:
        raise ConnectionError("Connection closed.")
    
    payload_len = int.from_bytes(len_bytes, 'big')

    # Read the rest of the packet
    payload = recv_all(sock, payload_len)
    if not payload:
        raise ConnectionError("Connection closed.")

    # Parse payload
    seq_bytes = payload[:SEQ_NUM_SIZE]
    nonce = payload[SEQ_NUM_SIZE:SEQ_NUM_SIZE + AES_NONCE_SIZE]
    received_mac = payload[-MAC_SIZE:]
    ciphertext = payload[SEQ_NUM_SIZE + AES_NONCE_SIZE:-MAC_SIZE]

    # Verify HMAC
    aad = len_bytes + seq_bytes + nonce + ciphertext
    
    mac = HMAC.new(mac_key, aad, SHA256)
    try:
        mac.verify(received_mac)
    except ValueError:
        print("!!! INTEGRITY FAILURE: Packet tampered (or length modified) !!!")
        raise SecurityException("Invalid MAC")

    # Verify Sequence Number
    received_seq = int.from_bytes(seq_bytes, 'big')
    if received_seq != expected_seq_num:
         print(f"!!! REPLAY/ORDER ATTACK: Exp {expected_seq_num}, Got {received_seq} !!!")
         raise SecurityException("Invalid Sequence Number")

    # Decrypt
    cipher = AES.new(enc_key, AES.MODE_CTR, nonce=nonce)
    message = cipher.decrypt(ciphertext).decode('utf-8')
    
    print(f"RECEIVED: '{message}' (EPOCH={received_seq})")
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
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f"Bob is listening on {HOST}:{PORT}...")
        conn, addr = s.accept()
        with conn:
            print(f"Connected by {addr}")
            
            try:
                # receive "Hello Bob" from Alice
                msg = secure_recv(conn, ENC_KEY, MAC_KEY, recv_seq)
                recv_seq += 1

                # send "Hello Alice" to Alice
                secure_send(conn, "Hello Alice", ENC_KEY, MAC_KEY, send_seq)
                send_seq += 1

                # receive "I would like to have Francesinha" from Alice
                msg = secure_recv(conn, ENC_KEY, MAC_KEY, recv_seq)
                recv_seq += 1

                # send "Me too. Same time, same place?" to Alice
                secure_send(conn, "Me too. Same time, same place?", ENC_KEY, MAC_KEY, send_seq)
                send_seq += 1

                # receive "Sure!" from Alice
                msg = secure_recv(conn, ENC_KEY, MAC_KEY, recv_seq)
                recv_seq += 1
                
                print("\nConversation successful and complete.") #

            except (SecurityException, ConnectionError, EOFError) as e:
                print(f"\n!!! Conversation HALTED due to error: {e} !!!")
            except Exception as e:
                print(f"\n!!! An unexpected error occurred: {e} !!!")
            finally:
                print("Closing connection.")

if __name__ == "__main__":
    main()