# CLIENT.py
# This program contains Alice's socket interactions..
#  for the project, Alice is the client.

from config import *
from Session_Manager import * 
from choices import * 
from Crypto_Manager import * 
import socket
import random
from compresser import * 

def send2server(message, DES_KEY, client):

    cipher_m = DES_encrypt(message, DES_KEY)
    compressed_cm, size = compress(cipher_m)
    sent_bytes = 0
    while sent_bytes != size:
        client.send("101".encode())
        if sent_bytes + 1024 < size:
            client.send(int_to_bin(1024).encode())
            client.send(compressed_cm[sent_bytes:sent_bytes+1024].encode())
            sent_bytes += 1024
        else:
            sending_bytes = int_to_bin(size - sent_bytes)
            while len(sending_bytes) < 11:
                sending_bytes = '0' + sending_bytes
            client.send(sending_bytes.encode())
            client.send(compressed_cm[sent_bytes:].encode())
            sent_bytes = size
    client.send("000".encode()) # end message send signal
    return


def receive_from_server(continue_signal, end_signal, client):
    cipher = ""
    size_of_continue_signal = len(int_to_bin(continue_signal))
    p3c = bin_to_int(client.recv(size_of_continue_signal).decode()) == continue_signal # client must send cipher in packets
    while p3c:
        size = bin_to_int(client.recv(11).decode()) # 10 bytes to specify size of next send
        cipher += client.recv(size).decode()
        try:
            p3c = bin_to_int(client.recv(size_of_continue_signal).decode()) == continue_signal
        except:
            p3c = False
    return cipher  # compressed cipher


if __name__ == '__main__':
    client = socket.socket()
    client.connect((HOST, SERVER_PORT))
    while True:
        # Phase 1, agree on key_exchange, cipher_suite, hash.

        keyExchange = choice("KEY_EXCHANGE").prompt()
        cipherSuite = choice("CIPHER_SUITE").prompt()
        Hash = choice("HASH").prompt()
        client.send(keyExchange.encode())
        client.send(cipherSuite.encode())
        client.send(Hash.encode())

        keyExchange = choice("KEY_EXCHANGE", chosen = client.recv(len(choices["KEY_EXCHANGE"])).decode()).get_choice()
        cipherSuite = choice("CIPHER_SUITE", chosen = client.recv(len(choices["CIPHER_SUITE"])).decode()).get_choice()
        Hash = choice("HASH", chosen = client.recv(len(choices["HASH"])).decode()).get_choice()


        # Phase 2, recieve server RSA public key....
        public_key = decompress(client.recv(1024).decode())
        # retrieve public key from server
        e,n = public_key
        #raise

        # Phase 3, send an encrypted NONCE + MAC using RSA encryption.
        nonce = random.randint(0, 2.8147498e+14)
        nonce = int_to_bin(nonce)
        while len(nonce) < 48:
            nonce = '0' + nonce
        
        MAC = hmac(int_to_bin(public_key[1]), nonce)
        cipher = RSA_encrypt(nonce, public_key)
        compressed_cipher, size = compress((cipher,MAC))
        sent_bytes = 0
        while sent_bytes != size:
            client.send("11".encode())
            if sent_bytes + 1024 < size:
                client.send(int_to_bin(1024).encode())
                client.send(compressed_cipher[sent_bytes:sent_bytes+1024].encode())
                sent_bytes += 1024
            else:
                sending_bytes = int_to_bin(size - sent_bytes)
                while len(sending_bytes) < 11:
                    sending_bytes = '0' + sending_bytes
                client.send(sending_bytes.encode())
                client.send(compressed_cipher[sent_bytes:].encode())
                sent_bytes = size
        client.send("00".encode()) # end phase 3 signal
        #raise

        ret_message = client.recv(1).decode()
        if ret_message == "1":
            print("recieved success from server...")
        elif ret_message == "0":
            print("received failure from server...")

        # Phase 4, change encryption to DES... send finished message. 
        
        DES_KEY = client.recv(10).decode()

        # Phase 5: Start ATM interaction
        # receive welcome message: 
        
        cipher = receive_from_server(5,0,client)
        received_message = DES_decrypt(decompress(cipher), DES_KEY)
        print(received_message)

        # receive account creation / login message

        cipher = receive_from_server(5,0,client)
        received_message = DES_decrypt(decompress(cipher), DES_KEY)
        print(received_message)

        while True:
            next_message = input()
            try:
                send2server(next_message, DES_KEY, client)
            except:
                break
            received_message = DES_decrypt(decompress(receive_from_server(5,0,client)), DES_KEY)
            if received_message == "-1":
                break
            print(received_message)
        client.close()
        break
    print("PROGRAM END.")
