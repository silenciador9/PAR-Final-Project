# -*- coding: utf-8 -*-
"""
Created on Mon Apr 12 22:43:07 2021

@author: Mark
Implement HMAC algorithm
"""
import sha1
from Crypto_Manager import * 
def hmac(key, m):
    Hex = lambda x:"".join([hex(ord(y))[2:].zfill(2) for y in x])
    block_size = 128 #block size of hash function
    #output_size = 20 #output size for sha1
    h_key = Hex(key)
    #key longer than block size get shorteneds
    if(len(key) > block_size):
        h_key = sha1.sha1(key) #key is 20 bytes long

    #Key shorter than block size
    while(len(h_key)) < 128:
            h_key += '00'
            
    o_key_pad = int(h_key,16) ^ int('5C' * block_size,16)
    i_key_pad = int(h_key,16) ^ int('36' * block_size,16)

    HMAC = sha1.sha1(bin(o_key_pad + sha1.sha1(bin(i_key_pad + int(m,2))[2:]))[2:]) 
    return HMAC

if __name__ == "__main__":
    res = hmac("10010111011", "010111011001001001111100011010101101001011110011")
    print(res)
    print(len(res))
