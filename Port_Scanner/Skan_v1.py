import socket
import sys
import logging
import argparse

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('Port_Scanner.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)

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
    parser = argparse.ArgumentParser(description="Port Scanner v1.1")
    parser.add_argument('--host', required=True, type=str, help='Целевой хост')
    parser.add_argument('--ports', type=str, default='21,22,80,443', help='Порты через запятую')
    parser.add_argument('--timeout', type=float, default=1.0, help='Таймаут')

    args = parser.parse_args()

    logging.info(f"Запуск сканирования хоста: {args.host}")
    logging.info(f"Установленный таймаут: {args.timeout} сек.")

    # Проверка на обман провайдера (Fake Open Check)
    logging.info("[*] Проверка надежности сети...")
    # Проверяем порт 9999, который у Google точно закрыт
    if scan_port(args.host, 9999, timeout=args.timeout):
        logging.warning("[!] ВНИМАНИЕ: Сеть или провайдер возвращают ложные ответы (блок-заглушки)!")
        logging.warning("[!] Результаты сканирования внешних сайтов могут быть неточными.")
        print("-" * 50)



    # Парсим порты
    port_list = [int(p) for p in args.ports.split(',')]

    # Запуск основного сканирования
    for port in port_list:
        scan_port(args.host, port, args.timeout)

    logging.info("Сканирование успешно завершено. Результаты сохранены в scanner.log")