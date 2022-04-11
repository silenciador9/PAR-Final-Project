# Crypto_Manager.py

import math
import random
import sha1
def hmac(key, m):
    m = "".join([c for c in m if c in ["0", "1"]])
    x5C_Pad = '0101110001011100010111000101110001011100010111000101110001011100'
    x36_Pad = '0011011000110110001101100011011000110110001101100011011000110110'
    block_size = 512 #block size of hash function
    #output_size = 20 #output size for sha1
    #key longer than block size get shorteneds
    if(len(key) > block_size):
        sha1.sha1(key) #key is 20 bytes long

    #Key shorter than block size
    elif(len(key) < block_size):
        key = key + '0' * (512-len(key))
    
    o_key_pad = int(key,2) ^ int(x5C_Pad,2)
    i_key_pad = int(key,2) ^ int(x36_Pad,2)
    HMAC = sha1.sha1(bin(o_key_pad + sha1.sha1(bin(i_key_pad + int(m,2))[2:]))[2:]) 
    print(HMAC)
    return hex(HMAC)[2:]


def ascii_to_bin ( char ):
    return ''.join(format(ord(char), '08b'))


def bin2ascii(bi):
    b_arr = []
    i = 0
    while i + 8 <= len(bi):
        b_arr.append(bi[i:i+8])
        i += 8
    m = ""
    for byte in b_arr:
        k = bin_to_ascii(byte)
        if k != '':
            m += k
    return m

def bin_to_ascii ( bi ):
    if len(bi) > 8:
        return bin2ascii(bi)
    elif len(bi) != 8:
        return ''
    bi = bin_to_int(bi)
    byte_number = bi.bit_length() + 7 // 8
    bin_arr = bi.to_bytes(byte_number, "big")
    x = bin_arr.decode()
    return x

def int_to_bin ( i ):
    return "{0:b}".format(i)

def bin_to_int ( bi ) :
    return int (bi, 2)

def ascii2bin(m):
    b_arr = m.encode()
    b_int = int.from_bytes(b_arr, "big")
    b_string = bin(b_int)[2:]
    while len(b_string) % 8 != 0:
        b_string = "0" + b_string
    return b_string


def extended_euclid_slow(m,b):

   A1, A2, A3 = (1, 0, m)
   B1, B2, B3 = (0, 1, b)
   Q = 1
   while True:
       if B3 == 0 or A3 == 0:
           return  # A3 = gcd(m,b) no inverse
       elif B3 == 1 or A3 == 1:
           if A3 > B3:
               Q = math.floor(A3 / B3)
               T1, T2, T3 = (A1 - Q * B1, A2 - Q * B2, A3 - Q * B3)
               A1, A2, A3 = (T1, T2, T3)
           else:
               Q = math.floor(B3 / A3)
               T1, T2, T3 = (B1 - Q * A1, B2 - Q * A2, B3 - Q * A3)
               B1, B2, B3 = (T1, T2, T3)
           return  B1,B2# B3 = gcd(m,b) B2 = b^-1 mod m
       if A3 > B3:
           Q = math.floor(A3 / B3)
           T1, T2, T3 = (A1 - Q * B1, A2 - Q * B2, A3 - Q * B3)
           A1, A2, A3 = (T1, T2, T3)
       else:
           Q = math.floor(B3 / A3)
           T1, T2, T3 = (B1 - Q * A1, B2 - Q * A2, B3 - Q * A3)
           B1, B2, B3 = (T1, T2, T3)

def extended_euclid(m, b):
    if m == 0:
        return 0, 1
    else:
        x, y = extended_euclid(b % m, m)
        return y - (b // m) * x, x

def RSA_encrypt(m, pk):
    from RSA import RSA_encrypt
    return RSA_encrypt(m, pk)

def RSA_decrypt(c, public_key, private_key):
    from RSA import RSA_decrypt
    return RSA_decrypt(c, public_key, private_key)

def DES_encrypt(message, Key): # KEY = 10 bits.
    
    message_bytes = ascii2bin(message)
    message_byte_blocks = []
    i = 0
    while i + 8 <= len(message_bytes):
        message_byte_blocks.append(message_bytes[i:i+8])
        i += 8
    cipher = []
    from DES import key_shift, encrypt
    This_Key = key_shift(Key)
    for pt in message_byte_blocks:
        cipher.append(encrypt(pt, This_Key))
    return cipher

def DES_decrypt(cipher, Key):
    from DES import key_shift, decrypt
    message = []
    This_Key = key_shift(Key)
    for ct in cipher:
        message.append(decrypt(ct, This_Key))
    message_text = ""
    for m in message:
        message_text += m
    message_text = bin2ascii(message_text)
    new_message_text = ""
    for c in message_text:
        if c.isalnum() or c in [" ", ".", ",", ":", "?", "\n"] :
            new_message_text += c
    message_text = new_message_text
    return message_text

def isPrime(num):

    # Not that num will be 0 or 1 but for sanity's sake
    # Check if 0 or 1 or negative, which are composite
    if (num < 2):
        return False 

    # Check the number against the small prime numbers before calling rabinMiller
    lowPrimes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997]

    # Not that the number will be in this list because these numbers are 256 bits, but for santiy's sake
    # Just make sure it's not one of these primes
    if num in lowPrimes:
        return True

    # Check against low primes and return false (composite) if any mod of those is 0
    for prime in lowPrimes:
        if (num % prime == 0):
            return False

    # Final judgment on whether the number is prime
    return rabinMiller(num)

def rabinMiller(num):

    power = num - 1
    count = 0
    while power % 2 == 0:
        # Cut s in half as long as it's even
        # Take the floor of the division so there's not unnecessary decimals
        power = power // 2
        # Keep count of how many times we divide s
        count += 1

    # Check if the number is prime 50 times to be safe
    for trials in range(50):
        base = random.randrange(2, num - 1)
        # Take the random number to the power of s and mod with the number
        v = pow(base, power, num)
        if v != 1: 
            i = 0
            while v != (num - 1):
                if i == count - 1:
                    return False
                else:
                    i = i + 1
                    v = (v ** 2) % num
    return True
