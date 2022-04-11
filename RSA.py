from Crypto_Manager import * 

def RSA_encrypt(m, pk):
    e,n = pk
    #print("e = " + str(e))
    #print("n = " + str(n))
    m_b = ""
    for c in m:
        #print(ascii2bin(c))
        m_b += ascii2bin(c)
    #print("ENCRYPTING")
    #print(m_b)
    #print(bin_to_ascii(m_b))
    # m_b = ascii2bin(m)
    i = 0
    b_size = math.floor(math.log(n,2))
    cipher_text = []
    while i + b_size < len(m_b):
        this_m = m_b[i:i+b_size]
        #print(this_m)
        this_m_int = bin_to_int(this_m)
        #print("m = " + str(this_m_int))
        #print(str(this_m_int) + " ** " + str(e) + " % " + str(n)) 
        this_c = (this_m_int ** e) % n
        #print("c = " + str(this_c))
        bin_c = int_to_bin(this_c)
        while len(bin_c) < b_size:
            bin_c = '0' + bin_c
        #print(bin_c)
        cipher_text.append(bin_c)
        i += b_size
    if i < len(m_b): # handle the last bit of data (0-pad the end)
        this_m = m_b[i:]
        while len(this_m) < b_size:
            this_m += '0' # 0-pad the last block.
        this_m_int = bin_to_int(this_m)
        this_c = (this_m_int ** e) % n
        bin_c = int_to_bin(this_c)
        while len(bin_c) < b_size:
            bin_c = '0' + bin_c
        cipher_text.append(bin_c)
    #print(len(cipher_text))
    return cipher_text

def RSA_decrypt(c, public_key, private_key):
    e,n = public_key
    d,p,q = private_key
    b_size = math.floor(math.log(n,2))
    m_text = ''
    i = 0
    for this_c in c:
        #print(this_c)
        this_c_int = bin_to_int(this_c)
        #print("c = " + str(this_c_int))
        this_m = (this_c_int ** d) % n
        #print("m = " + str(this_m))
        bin_m = int_to_bin(this_m)
        while len(bin_m) < b_size:
            bin_m = '0' + bin_m
        #print(bin2ascii(bin_m))
        m_text += bin_m
        i += b_size
    #print(len(m_text))
    #print(m_text)    
    return m_text

