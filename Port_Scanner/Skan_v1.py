import socket
import sys

def scan_port(host, port, timeout= 0.5):
    # подключение TCP-порта на хост
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # создаем сокет AF_INET = ip4 SOCK_STREAM - TSP
    sock.settimeout(timeout)
    # установка и ожидания ответа
    try:
        # пытаемся подключиться
        result = sock.connect_ex((host,port))
        if result == 0:
            # порт открыт
            print("[+] Port : ",port)
        else:
            #если порт закрыт
            print("[-] Port : ",port)
    except socket.timeout:
        print(f'порт {port}: закрыто мб тайиаут')
    except Exception as e:
        print(f' ошбка сканирования {port}: {e}')
    finally:
        sock.close()

def self_format_result(port, status):
    return f'[+] порт {port:<5} | статус {status}'

if __name__ == '__main__':
        TARGET_HOST = input()
        # TARGET_PORT = 80
        TIMEOUT = 1

        print(f'запуск {TARGET_HOST}...')
        # scan_port(TARGET_HOST, TARGET_PORT)

        #PORTS = [21, 22, 80, 443, 8080]

        for port in range(1, 80):
            scan_port(TARGET_HOST, port, TIMEOUT)

        print("-" * 50)
        print("[*] Сканирование завершено.")

