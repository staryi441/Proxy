import re
import os
import urllib.request
import socket
from urllib.parse import urlparse, parse_qs

# Список Telegram-каналов для сбора
CHANNELS = [
    "tgproxy",
    "mtproxy_s"
]

def fetch_channel_proxies(channel):
    proxies = set()
    try:
        url = f"https://t.me/s/{channel}"
        req = urllib.request.Request(
            url, 
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            html = resp.read().decode("utf-8", errors="replace")
            
        found_tg = re.findall(r'tg://proxy\?[^\s"<>]+', html)
        found_tme = re.findall(r'https://t\.me/proxy\?[^\s"<>]+', html)
        
        for p in found_tg + found_tme:
            p = re.sub(r'&amp;', '&', p).rstrip(".,;:)'\"")
            proxies.add(p)
    except Exception as e:
        print(f"Ошибка при парсинге канала {channel}: {e}")
    return proxies

def test_proxy(proxy_line):
    """Быстрая проверка доступности хоста и порта прокси (таймаут 3 секунды)"""
    try:
        # Универсальный парсинг параметров для проверки
        if "?" in proxy_line:
            query = proxy_line.split("?", 1)[1]
            p = parse_qs(query)
            host = p.get("server", [None])[0]
            port = p.get("port", [None])[0]
        else:
            return False

        if not host or not port:
            return False

        # Пробуем установить TCP-соединение с прокси-сервером
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3.0)
        result = sock.connect_ex((host, int(port)))
        sock.close()
        
        return result == 0  # 0 означает успешное соединение
    except Exception:
        return False

def main():
    all_proxies = set()
    
    # 1. Собираем со всех каналов
    for ch in CHANNELS:
        print(f"Сбор из канала: {ch}...")
        found = fetch_channel_proxies(ch)
        print(f"Найдено сырых: {len(found)}")
        all_proxies.update(found)
        
    if not all_proxies:
        print("Прокси не найдены.")
        return

    # 2. Проверяем каждый прокси на работоспособность
    print(f"Начинаем проверку работоспособности ({len(all_proxies)} шт.)...")
    working_proxies = set()
    
    for p in all_proxies:
        if test_proxy(p):
            print(f"[РАБОТАЕТ] {p}")
            working_proxies.add(p)
        else:
            print(f"[МЕРТВЫЙ] {p}")

    print(f"Проверка завершена. Рабочих: {len(working_proxies)} из {len(all_proxies)}")

    # 3. Перезаписываем файл ТОЛЬКО рабочими прокси
    filename = "proxyes.txt"
    with open(filename, "w", encoding="utf-8") as f:
        for p in sorted(working_proxies):
            f.write(p + "\n")
            
    print("Файл успешно обновлен!")

if __name__ == "__main__":
    main()
