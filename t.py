
from Crypto_Manager import *
import random










key = "0101010010"
message  = "TESTING"
ct = DES_encrypt(message, key)
print(ct)
message = DES_decrypt(ct, key)
print(message)




raise

nonce = random.randint(0, 2.8147498e+14)
nonce = int_to_bin(nonce)
while len(nonce) < 48:
    nonce = '0' + nonce

public_key = 65537
public_key = int_to_bin(public_key)
h = hmac(public_key, nonce)
h = int_to_bin(h)


public_key = [7,1211]
private_key = [295, 173,7]
nonce = "ABCDEF"
print("original message = " + nonce)
cipher_text = RSA_encrypt(nonce, public_key)
print("cipher text = " + str(cipher_text))
message = RSA_decrypt(cipher_text, public_key, private_key)
print("reconstructed message = " + message)
print("plaintext = " + bin2ascii(message))



