# from https://www.positronx.io/create-socket-server-with-multiple-clients-in-python/
import socket
import multiprocessing
import os
import subprocess
import time

# sudo kill $( sudo lsof -i:23456 -t )  
ClientMultiSocket = socket.socket()
host = "127.0.0.1"
port = 23456
print("Waiting for connection response")

def connect_ssl():
    try:
        ClientMultiSocket.connect((host, port))
    except socket.error as e:
        print(str(e))
    res = ClientMultiSocket.recv(1024)
    print(time.time())
    while True:
        # Input = input("Hey there: ")
        # ClientMultiSocket.send(str.encode(Input))
        res = ClientMultiSocket.recv(1024)
        print(res.decode("utf-8"))
        break

results = []
def log_results(result):
    results.append(result)

def run_mp_process():
    processes = []
    pool = multiprocessing.Pool()

    for i in range(multiprocessing.cpu_count()):
        processes.append(multiprocessing.Process(target=connect_ssl))

    for process in processes:
        process.start()

    for process in processes:
        process.join()
    pool.join()


def run_mp_pool():
    processes = []
    pool = multiprocessing.Pool()

    for i in range(multiprocessing.cpu_count()):
        p = pool.apply_async(connect_ssl, callback=log_results)
        processes.append(p)

    for process in processes:
        process.wait()
    pool.close()

if __name__ == '__main__':
    # run_mp_process()
    run_mp_pool()
    ClientMultiSocket.close()
