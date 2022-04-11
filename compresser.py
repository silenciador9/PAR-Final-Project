# compresser.py


# compresses data using pickle, returns binary object + length

import pickle
from Crypto_Manager import * 
import binascii
def compress(data):
    pickled = binascii.b2a_base64(pickle.dumps(data))
    pickled = ascii2bin(pickled.decode())
    return pickled, len(pickled)

def decompress(data):
    unpickled = bin2ascii(data)
    unpickled = pickle.loads(binascii.a2b_base64(unpickled))
    return unpickled



