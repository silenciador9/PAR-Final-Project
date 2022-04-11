# SERVER.py
# This program contains Bob's socket interactions.
#  For the project, Bob is the ATM (SERVER).

from config import *
from Session_Manager import *
from choices import * 
import socket
from compresser import *

from banking_operations import * 



def send2client(message, DES_KEY, client):

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


def receive_from_client(continue_signal, end_signal, client):
    cipher = ""
    size_of_continue_signal = len(int_to_bin(continue_signal))
    p3c = bin_to_int(client.recv(size_of_continue_signal).decode()) == continue_signal # client must send cipher in packets
    while p3c:
        size = bin_to_int(client.recv(11).decode()) # 10 bytes to specify size of next send
        #print(size)
        cipher += client.recv(size).decode()
        try:
            p3c = bin_to_int(client.recv(size_of_continue_signal).decode()) == continue_signal
        except:
            p3c = False
    #print("RECEIVED COMPRESSED CIPHER = " + cipher)
    return cipher  # compressed cipher

if __name__ == '__main__':
    
    server = socket.socket()
    server.bind((HOST,SERVER_PORT))
    server.listen(5)
    while True:
        client, addr = server.accept()
        print( str(addr) + " connected.")

        # PHASE 1
        keyExchangebits = client.recv(len(choices["KEY_EXCHANGE"])).decode()
        cipherSuitebits = client.recv(len(choices["CIPHER_SUITE"])).decode()
        Hashbits        = client.recv(len(choices["HASH"])).decode()
        
        keyExchange     = choice("KEY_EXCHANGE", chosen = keyExchangebits).get_choice()
        cipherSuite     = choice("CIPHER_SUITE", chosen = cipherSuitebits).get_choice()
        Hash            = choice("HASH", chosen = Hashbits).get_choice()
        print("Agreed key exchange = " + keyExchange)
        print("Agreed cipher suite = " + cipherSuite)
        print("Agreed hash = " + Hash)

        # Phase 1, echo to agree.
        client.send(keyExchangebits.encode())
        client.send(cipherSuitebits.encode())
        client.send(Hashbits.encode())
        

        # PHASE 2, send public key information
        session = Session_Manager(keyExchange, cipherSuite, Hash, Server = True)
        public_key = compress(session.generate_key())[0]
        client.send(public_key.encode())


        # PHASE 3, receive encrypted nonce and mac
        #  verify mac is correct server-side, if it is valid then
        #   send back decrypted nonce for client-side verification
        #  if mac is not correct, then send error message.

        cipher = receive_from_client(3, 0, client)
        cipher,MAC = decompress(cipher)
        message = bin2ascii(RSA_decrypt(cipher, session.public_key, session.private_key))
        predicted_mac = hmac(int_to_bin(session.public_key[1]), str(message).strip())

        if predicted_mac == MAC:
            client.send("1".encode())#compress(RSA_encrypt("YAY", session.public_key)))
        else:
            client.send("0".encode())#compress(RSA_encrypt("BOO", session.public_key)))
            client.close() 
            break

        # PHASE 4 send the key for DES
        DES_KEY = session.get_DES_key()
        client.send(DES_KEY.encode())

        # (PHASE 5) receive/send information from the client while they remain connected
        from banking_operations import * 
        ATM = ATM(addr)
        message = ATM.get_welcome_message()
        send2client(message, DES_KEY, client) # send2client encrypts the message for us w/ DES

        # LOGGIN IN / CREATING ACCOUNT:
        message = "" 
        while ATM.state <= 2: # while they are not logged in, route through account creation
            message += ATM.account_creation()
            send2client(message, DES_KEY, client)
            received_message = DES_decrypt(decompress(receive_from_client(5,0,client)), DES_KEY)
            print("RECEIVED MESSAGE = " + received_message + " from " + str(addr))
            message = ATM.receive_input(received_message)
            if ATM.state == -1: # too many login attempts, close connection
                client.close()
        send2client(message,DES_KEY, client)

        # Loop for interaction interface:
        while ATM.state != -1: 
            received_message = DES_decrypt(decompress(receive_from_client(5,0,client)), DES_KEY)
            print("RECEIVED MESSAGE = " + received_message + " from " + str(addr))
            ret_message = ATM.receive_input(received_message)
            send2client(ret_message, DES_KEY, client) 
        send2client("-1",DES_KEY,client)
        client.close()       
