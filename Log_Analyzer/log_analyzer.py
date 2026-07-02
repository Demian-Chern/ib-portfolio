import re
from collections import Counter
from pathlib import Path

# Регулярное выражение для парсинга логов
LOG_PATERN = re.compile(
    r'(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<date>.*?)\]\s+"(?P<method>\S+)\s+(?P<url>\S+)\s+\S+"\s+(?P<status>\d{3})\s+(?P<size>\S+)'
)

# НАСТРОЙКИ БЕЗОПАСНОСТИ (Пороги срабатывания)
MAX_401_THRESHOLD = 3  # Максимум 401 ошибок, после которых IP считается брутфорсером
MAX_404_THRESHOLD = 3  # Максимум 404 ошибок, после которых IP считается сканнером

# Список опасных сигнатур для проверки URL
DANGEROUS_SIGNATURES = [
    "../",  # Path Traversal (попытка выйти из директории)
    "etc/passwd",  # Попытка прочитать системные файлы Linux
    "select ",  # SQL-инъекция (поиск данных)
    "union ",  # SQL-инъекция (объединение запросов)
    "concat",  # SQL-инъекция
    "<script>",  # XSS (внедрение вредоносного JS-кода)
]


def parse_log_file(file_path: str):
    # Стандартные счетчики трафика и общих данных
    ip_counter = Counter()
    url_counter = Counter()
    status_counter = Counter()
    total_traffic = 0
    errors_count = 0

    # НОВЫЕ СЧЕТЧИКИ ДЛЯ ИБ-АНАЛИЗА
    bruteforce_tracker = Counter()  # Считаем коды 401 для каждого IP
    scanning_tracker = Counter()  # Считаем коды 404 для каждого IP
    security_alerts = []  # Список для хранения найденных атак по сигнатурам

    path = Path(file_path)
    if not path.exists():
        print(f"[-] Файл {file_path} не найден.")
        return

    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            match = LOG_PATERN.match(line)
            if match:
                data = match.groupdict()
                ip = data['ip']
                url = data['url']
                status = data['status']

                try:
                    size = int(data['size'])
                except ValueError:
                    size = 0

                # Заполняем базовую статистику
                ip_counter[ip] += 1
                url_counter[url] += 1
                status_counter[status] += 1
                total_traffic += size

                if status.startswith(('4', '5')):
                    errors_count += 1


                # ПОДДЕРЖКА ИБ-ЛОГИКИ:


                # 1. Поведенческий анализ: трекаем подозрительные статусы
                if status == "401":
                    bruteforce_tracker[ip] += 1
                elif status == "404":
                    scanning_tracker[ip] += 1

                # 2. Сигнатурный анализ: проверяем URL на вредоносный код
                # Приводим к нижнему регистру, чтобы хакер не обошел проверку через "SeLeCt"
                url_lower = url.lower()
                for signature in DANGEROUS_SIGNATURES:
                    if signature in url_lower:
                        security_alerts.append({
                            "ip": ip,
                            "url": url,
                            "signature": signature
                        })

        # Возвращаем расширенный словарь со всеми собранными ИБ-данными
        return {
            'ip': ip_counter,
            'url': url_counter,
            'status': status_counter,
            'traffic': total_traffic,
            'errors': errors_count,
            'bruteforce': bruteforce_tracker,
            'scanning': scanning_tracker,
            'alerts': security_alerts
        }


def print_report(stats):
    if not stats:
        return

    print("=" * 60)
    print("                LOG ANALYSIS REPORT & SECURITY IDS         ")
    print("=" * 60)

    print(f"\n[+] Всего трафика отдано: {stats['traffic'] / 1024:.2f} KB")
    print(f"[+] Количество ошибок (4xx/5xx): {stats['errors']}")


    # БЛОК ИБ-УВЕДОМЛЕНИЙ (SECURITY ALERTS)

    print("\n" + "!" * 20 + " СИСТЕМА ОБНАРУЖЕНИЯ АТАК " + "!" * 20)

    # Проверяем брутфорс
    has_alerts = False
    for ip, count in stats['bruteforce'].items():
        if count > MAX_401_THRESHOLD:
            print(f"[🚨 WARNING] Обнаружен БРУТФОРС! IP: {ip} получил {count} кодов 401 (Unauthorized)")
            has_alerts = True

    # Проверяем сканирование директорий
    for ip, count in stats['scanning'].items():
        if count > MAX_404_THRESHOLD:
            print(f"[🚨 WARNING] Обнаружено СКАНИРОВАНИЕ ДИРЕКТОРИЙ! IP: {ip} получил {count} кодов 404 (Not Found)")
            has_alerts = True

    # Выводим сработавшие сигнатуры
    for alert in stats['alerts']:
        print(
            f"[🔥 ATTACK DETECTED] IP: {alert['ip']} пытался использовать сигнатуру '{alert['signature']}' в URL: {alert['url']}")
        has_alerts = True

    if not has_alerts:
        print("[✅] Подозрений на атаки не обнаружено.")


    # Стандартная статистика
    print("\n🔹 Топ 3 активных IP-адресов:")
    for ip, count in stats["ip"].most_common(3):
        print(f"  - {ip}: {count} запросов")

    print("\n🔹 Топ 3 статус-кодов:")
    for status, count in sorted(stats["status"].items()):
        print(f"  - {status}: {count} раз(а)")



if __name__ == "__main__":
    LOG_FILE = r"C:\Users\Алексей\PycharmProjects\ib-portfolioй\Log_Analyzer\access.log"
    metrics = parse_log_file(LOG_FILE)
    print_report(metrics)