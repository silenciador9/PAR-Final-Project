# -*- coding: utf-8 -*-
"""
Created on Wed Apr 14 19:03:37 2021

@author: Mark
"""
import secrets
import socket
def power(a,b,P):
    if (b == 1):
        return a;
    else:
        return (pow(a, b) % P)

#Static secure number
def staticDiffieHellman(G,P,socket):
    unsecure_number = 16804040309001
    #G,P public numbers alice and bob get
    x = int( power(G, unsecure_number, P))
    socket.send(str(x).encode())
    y = int(socket.recv(1024).decode())
    power(y, unsecure_number, P)
    
    return power(y, unsecure_number, P)

#Random secure number
def ephemeralDiffieHellman(G,P,socket):
    secure_number = secrets.randbits(256)
    #G,P public numbers alice and bob get
    x = str(power(G, secure_number, P))
    socket.send(x.encode())
    y = int(socket.recv(1024).decode())
    
    return power(y, secure_number, P)

#Diffie hellman without authentification
def anonymousDiffieHellman(G,P, socket):
    #secure_number = secrets.randbits(256)
    #G,P public numbers alice and bob get
    x = str(pow(G, P))
    socket.send(x.encode())
    y = int(socket.recv(1024).decode())
    
    return pow(y, P)
