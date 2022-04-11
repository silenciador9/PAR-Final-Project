# -*- coding: utf-8 -*-
"""
Created on Mon Apr 12 15:36:11 2021

@author: Mark Borelli II
Implementation for SHA1 (Secure Hashing Algorithm)
Algorithm reference: http://www.herongyang.com
"""
#Helper function to left rotate string
def left_rotate(m,n):
    return ((m << n) | (m >> (32 - n))) & 0xffffffff

def sha1(m):
    L = len(m) #gather length of message
    m += '1'
#Step 1: Append Padding
#append 0 msg to 64 bits fewer than even mult 512
    for i in range(512):
        if(L+len(bin(L)[2:])) % 448 == -64:
            break
        m += '1'    

#break message into 512-bit chunks
    li_512 = []
    st = ""
    for i in range(L):
        st += m[i]
        if len(st) == 512:
            li_512.append(st)
            st = "" #reset
    
    if len(st) < 512 and len(st) > 0:
        while len(st) < 512:
            st += "0"
        li_512.append(st)
    
    #Now break into 16 32 bit words
    # For each chunk, break chunk into 16 32-bit
    # big endian words w[i] 0<i<15
    for i in li_512:
           li_16 = []
           st2 = ""
           for i in range(L):
               st2 += m[i]
               if len(st2) == 16:
                   li_16.append(st2)
                   st2 = "" #reset
           if len(st2) < 16 and len(st2) > 0:
            while len(st2) < 16:
                st2 += "0"
                li_16.append(st2)
        
           w = list(map(lambda x: int(x,2),li_16))
        
           while len(w) < 80:
               w.append(0)
        
           for t in range(16, 80):
               w[t] = left_rotate(w[t-3] ^ w[t-8] ^ w[t-14] ^ w[t-16], 1)
    
    #Step 5: Initialize 5 buffers
           H0 = 0x67452301 
           H1 = 0xEFCDAB89
           H2 = 0x98BADCFE
           H3 = 0x10325476
           H4 = 0xC3D2E1F0  
        
           a = H0
           b = H1
           c = H2
           d = H3
           e = H4
    #Main loop for XOR ops:
           for i in range(80):
               if 0 <= i <= 19:
                   f = d ^ (b&(c ^ d))
                   K = 0x5A827999
               elif 20 <= i <= 39:
                   f = b ^ c ^ d
                   K = 0x6ED9EBA1
               elif 40 <= i <= 59:
                   f = (b & c) | (b & d) | (c & d)
                   K = 0x8F1BBCDC
               elif 60 <= i <= 79:
                   f = b ^ c ^ d
                   K = 0xCA62C1D6
            
    #Following the main loop framework:
    TEMP = left_rotate(a,5) + f + e + w[i] + K & 0xffffffff
    e = d
    d = c
    c = left_rotate(b,30)
    b = a
    a = TEMP
    #Adding chunk message hash
    H0 += a
    H1 += b
    H2 += c
    H3 += d
    H4 += e
    result = (H0 << 128 | H1 << 96 | H2 << 64 | H3 << 32 | H4)
    return result

if __name__ == "__main__":
    print(bin(sha1('1010101010010101'))[2:])
