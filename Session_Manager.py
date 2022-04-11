# Session_Manager.py
# This class contains methods to retrieve session-level objects.
#   calls to cryptographic functions occur here...

import hmac
import random
from config import *
from Crypto_Manager import *
import secrets

class Session_Manager():
    def __init__(self, key_exchange, cipher_suite, Hash, Server = True):
        self.server = Server
        self.key_exchange = key_exchange
        self.cipher_suite = cipher_suite
        self.hash = Hash

    def get_session_items(self):
        print("KEY EXCHANGE = " + str(self.key_exchange))
        print("CIPHER SUITE = " + str(self.cipher_suite))
        print("HASH = " + str(self.hash))

    def get_DES_key(self):
        self.DES_KEY = ""
        for i in range(0,10):
            k = random.randint(0,1)
            self.DES_KEY += str(k)
        return self.DES_KEY

    def set_public_key(self, public_key):
        if self.server:
            print("only client should need to set the public key.", file = sys.stderr)
            raise 
        self.public_key = public_key
        return


    def generate_key(self):
        if self.server == False:
            print("only server can generate the keys.", file = sys.stderr)
            raise
        if self.key_exchange == "RSA":
            self.RSAKEYGEN()
        elif self.key_exchange == "Fixed Diffie-Hellman":
            print("unimplemented in generate_public_key.", file = sys.stderr)
            raise
        elif self.key_exchange == "Ephemeral Diffie-Hellman":
            print("unimplemented in generate_public_key.", file = sys.stderr)
            raise
        elif self.key_exchange ==  "Anonymous Diffie-Hellman":
            print("unimplemented in generate_public_key.", file = sys.stderr)
            raise
        else:
            print("Invalid key exchange parameter in session manager", file = sys.stderr)
            raise
        return self.public_key

    def RSAKEYGEN(self):
        d = -1
        while d < 0: 
            while(True):
                p = secrets.randbits(4)
                if isPrime(p):
                    break
            while(True):
                q = secrets.randbits(4)
                if(isPrime(q) and p != q):
                    break
            n = p*q
            on = (p-1)*(q-1)
            e = 7
            x,d = extended_euclid(on,e)
        self.public_key = [e, n]
        self.private_key = [d,p,q]
        return
