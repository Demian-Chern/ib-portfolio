import re
from collections import Counter
from pathlib import Path

# Регулярное выражение для Common Log Format
# Разбирает IP, дату/время, метод, URL, статус-код и размер ответа

LOG_PATERN = re.compile(
    r'(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<date>.*?)\]\s+"(?P<method>\S+)\s+(?P<url>\S+)\s+\S+"\s+(?P<status>\d{3})\s+(?P<size>\S+)'
)

def parse_log_file(file_path: str):
    #словари для сбора
    ip_counter = Counter()
    url_counter = Counter()
    status_counter = Counter()
    total_traffic = 0
    errors_count = 0

    path = Path(file_path)
    if not path.exists():
        print(f"[-] Файл {file_path} не найден.")
        return

    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()  # убираем переносы строк
            if not line:
                continue

            match = LOG_PATERN.match(line)
            if match:
                # извлечение данных
                data = match.groupdict()
                ip = data['ip']
                url = data['url']
                status = data['status']

                try:
                    size = int(data['size'])
                except ValueError:
                    size = 0

                ip_counter[ip] += 1
                url_counter[url] += 1
                status_counter[status] += 1
                total_traffic += size

                if status.startswith(('4', '5')):
                    errors_count += 1
            else:
                # Этот принт покажет, что именно не подошло под регулярку
                print(f"[-] Не совпало: {line}")

        return {
            'ip': ip_counter,
            'url': url_counter,
            'status': status_counter,
            'traffic': total_traffic,
            'errors': errors_count,
        }

# Обязательно должно быть def в начале!
def print_report(stats):
    # Весь код ниже должен быть смещен вправо (на 4 пробела или 1 Tab)
    if not stats:
        return

    print("=" * 50)
    print("                LOG ANALYSIS REPORT                ")
    print("=" * 50)

    print(f"\n[+] Всего трафика отдано: {stats['traffic'] / 1024:.2f} KB")
    print(f"[+] Количество ошибок (4xx/5xx): {stats['errors']}")

    print("\n🔹 Топ 3 активных IP-адресов:")
    for ip, count in stats["ip"].most_common(3):
        print(f"  - {ip}: {count} запросов")

    print("\n🔹 Топ 3 самых запрашиваемых URL:")
    for url, count in stats["url"].most_common(3):
        print(f"  - {url}: {count} раз(а)")

    print("\n🔹 Распределение статус-кодов:")
    for status, count in sorted(stats["status"].items()):
        print(f"  - {status}: {count} раз(а)")

    print("=" * 50)


if __name__ == "__main__":
    # Укажи путь к своему лог-файлу
    LOG_FILE = r"C:\Users\Алексей\PycharmProjects\ib-portfolioй\Log_Analyzer\access.log"
    metrics = parse_log_file(LOG_FILE)
    print_report(metrics)