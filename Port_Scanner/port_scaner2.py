import socket
import termcolor

def scan(target,total_ports):
    for current_port in range(int(total_ports) + 1):
        scan_port(target,current_port)




def scan_port(ipadress,port):
    try:
        sock = socket.socket()
        sock.settimeout(1.0)
        sock.connect((ipadress, port))
        print("[+] Port : ",port)
        sock.close()
    except:
        pass

tergets = input('цели сканированя пробеды:')
ports = int(input('количество портов:'))

if ',' in tergets:
    print('[*] каго сканим')
    for ip_addr in tergets.split(','):
        scan(ip_addr.strip(),ports)
else:
    scan(tergets, ports)


