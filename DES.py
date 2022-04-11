# Implementation of 2 stage 8bit DES.
# Encryption Ciphertext does not fit the example in Hints. 
# I tried for a while to reproduce this result;
#    ( I tried both LSB 0 and MSB 0 interpretations )
# Current configuration splits entries into L/R segments as follows:

#                Right Bits
#                  vvvv
#   Example = '00101000'
#              ^^^^
#            Left Bits

# Likewise, any concatenation is :
#   Result = Left Bits + Right Bits

# Initial Perumation of Bit Positions
Init_PBP = [2,6,3,1,4,8,5,7]

# Inverse Permutation of Bit Positions
Inv_PBP = [4,1,3,5,7,2,8,6]

# P10: Permutation of 10-bit
P10 = [3,5,2,7,4,10,1,9,8,6]
P10_prime = [7,3,1,5,2,10,4,9,8,6] # inverse P10

# P8: 8 Permutation of 10-bit
P8 = [6,3,7,4,8,5,10,9]
P8_prime = [2,4,6,1,3,5,8,7] # inverse P8

# Inside F Function:

# 4-bit Expansion
BE_4 = [[4,1,2,3],[2,3,4,1]]

# S-BOX Matrices [row][col]
SBOX0 = [[1,0,3,2],[3,2,1,0],[0,2,1,3],[3,1,3,2]]
SBOX1 = [[0,1,2,3],[2,0,1,3],[3,0,1,0],[2,1,0,3]]

# 4-bit Permutation
BP_4 = [2,4,3,1]

# 10-bit key
BK_10 = '1100011110'


def ascii_to_bin ( char ):
    return ''.join(format(ord(char), '08b'))

def bin_to_ascii ( bi ):
    bi = bin_to_int(bi)
    byte_number = bi.bit_length() + 7 // 8 
    bin_arr = bi.to_bytes(byte_number, "big")
    x = bin_arr.decode()
    return x

def int_to_bin ( i ):
    return "{0:b}".format(i)

def bin_to_int ( bi ) :
    return int (bi, 2)

def left_shift(x):
    msd = x[0]
    new = ''
    for i in x[1:]:
        new = new + i 
    new = new + msd
    return new
 
def right_shift(x):
    lsd = x[len(x)-1]
    new = lsd
    for i in x[:len(x)-1]:
        new = new + i 
    return new


def permute( dat, perm ) :
    new_dat = ''
    for i in perm:
        new_dat += dat[i-1]
    return new_dat

def expand(dat, expansion):
    new_dat = ''
    for i in expansion[0]:
        new_dat += dat[i-1]
    for i in expansion[1]:
        new_dat += dat[i-1]
    return new_dat

def XOR ( d1, d2 ) :
    l = len(d1)
    x = int_to_bin(int(d1,2) ^ int(d2,2))
    while len(x) < l:
        x = '0' + x
    return x

def S_BOX ( dat, S ) :
    row = bin_to_int(dat[0]+dat[3])
    col = bin_to_int(dat[1]+dat[2])
    out = int_to_bin(S[row][col])
    while len(out) < 2:
        out = '0' + out
    return  out

def f_func ( dat, key ) :
    new_dat = expand(dat, BE_4)
    b4 = new_dat
    new_dat = XOR(new_dat, key)
    L_dat = new_dat[:4]
    R_dat = new_dat[4:]

    L_dat_out = S_BOX(L_dat, SBOX0)
    R_dat_out = S_BOX(R_dat, SBOX1)

    new_dat = L_dat_out + R_dat_out
    new_dat = permute(new_dat, BP_4)
    
    return new_dat, [(b4, L_dat, L_dat_out), (b4, R_dat, R_dat_out)]

def key_shift (KEY):
    #print("MASTER KEY = " + KEY)
    KEY = permute(KEY, P10)
    L5 = KEY[:5]
    R5 = KEY[5:]

    L4 = left_shift(L5)
    R4 = left_shift(R5)
   
    K1 = permute(L4+R4, P8)
    L3 = left_shift(L4)
    R3 = left_shift(R4)
    K2 = permute(L3+R3, P8)
    #print("KEY 1 =  " + K1)
    #print("KEY 2 =  " + K2)
    return [K1, K2]

# given predicted subkey1, return the possible corresponding master keys
def get_master_key_1 ( SUB_KEY_1 ) : 
    pos_keys = []
   
    for i in ['0','1']: # first two digits are unknown
        for j in ['0','1']: # first two digits unknown
            pos_keys.append(i+j+permute(SUB_KEY_1, P8_prime))

   
    for i in range(0,len(pos_keys)):
        key = pos_keys[i]
        L = right_shift(key[:5])
        R = right_shift(key[5:])
        key = L + R
        pos_keys[i] = permute(key, P10_prime)

    return pos_keys

# given predicted subkey1, return the possible corresponding master keys
def get_master_key_2 ( SUB_KEY_2 ) : 
    pos_keys = []
   
    for i in ['0','1']: # first two digits are unknown
        for j in ['0','1']: # first two digits unknown
            pos_keys.append(i+j+permute(SUB_KEY_2, P8_prime))
  
    for i in range(0,len(pos_keys)):
        key = pos_keys[i]
        L = right_shift(right_shift(key[:5]))  # we need to R shift twice for the second key
        R = right_shift(right_shift(key[5:])) 
        key = L + R
        pos_keys[i] = permute(key, P10_prime)

    return pos_keys


# attack flag removes first and last permute, as the homework allows
#  ( it also returns the input/output information required for the dif attack
def encrypt(pt, Keys, attack = False):
    if attack == False:
        dat = permute(pt, Init_PBP)
    else:
        dat = pt
    L4 = dat[:4]
    R4 = dat[4:]

    
    f_out_1, sins12 = f_func(R4, Keys[0])
    R2 = XOR(L4, f_out_1)
    L2 = R4

    f_out_2, sins34 = f_func(R2, Keys[1])
    out_L= XOR(L2, f_out_2)
    out_R = R2


    c_t = out_L + out_R
    if attack == False:
        c_t = permute(c_t, Inv_PBP)
        return c_t
    else:
        return c_t, [sins12[0],sins12[1],sins34[0],sins34[1]]


def decrypt (ct, Keys):
    dat = permute(ct, Init_PBP)
    L4 = dat[:4]
    R4 = dat[4:]
    R2 = XOR(L4, f_func(R4, Keys[1])[0])
    L2 = R4
    out_L = XOR(L2, f_func(R2, Keys[0])[0])
    out_R = R2
    pt = out_L + out_R
    pt = permute(pt, Inv_PBP)
    return pt
