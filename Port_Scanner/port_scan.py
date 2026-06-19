import socket

def scan(ip,port):
    client = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    if client.connect_ex((ip,port)):
        pass
    else:
        print("[+] Port : ",port)
ip = socket.gethostbyname('online.mospolytech.ru')
for port in range(1,81):
    scan(ip,port)
