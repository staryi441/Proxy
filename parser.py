import re
import os
import urllib.request
import json

# Список публичных Telegram-каналов, откуда собираем прокси (укажи свои)
CHANNELS = [
    "TProxyRU",        # Пример канала
    "ProxyMTProto",
    "ProxyFree_Ru",
    "tgmtproxylol",
    "tg_proxyz",
    "proxy_telegramt",
    "mtproto6",
    "mtprotoF"
]

def fetch_channel_proxies(channel):
    proxies = set()
    try:
        # Используем публичный веб-просмотрщик телеграм-каналов t.me
        url = f"https://t.me/s/{channel}"
        req = urllib.request.Request(
            url, 
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            html = resp.read().decode("utf-8", errors="replace")
            
        # Ищем в тексте страницы ссылки на прокси обоих форматов
        found_tg = re.findall(r'tg://proxy\?[^\s"<>]+', html)
        found_tme = re.findall(r'https://t\.me/proxy\?[^\s"<>]+', html)
        
        for p in found_tg + found_tme:
            # Очищаем от возможных лишних символов HTML-разметки на конце
            p = re.sub(r'&amp;', '&', p).rstrip(".,;:)'\"")
            proxies.add(p)
    except Exception as e:
        print(f"Ошибка при парсинге канала {channel}: {e}")
    return proxies

def main():
    all_proxies = set()
    
    # 1. Собираем со всех каналов
    for ch in CHANNELS:
        print(f"Сбор из канала: {ch}...")
        found = fetch_channel_proxies(ch)
        print(f"Найдено: {len(found)}")
        all_proxies.update(found)
        
    if not all_proxies:
        print("Новые прокси не найдены, файл не обновляется.")
        return

    # 2. Читаем текущий файл, чтобы сохранить уже имеющиеся рабочие прокси (опционально)
    filename = "proxyes.txt"
    existing_proxies = set()
    if os.path.exists(filename):
        with open(filename, "r", encoding="utf-8") as f:
            existing_proxies = {line.strip() for line in f if line.strip()}
            
    total_proxies = existing_proxies.union(all_proxies)
    
    # 3. Записываем обновленный и отсортированный список обратно в файл
    with open(filename, "w", encoding="utf-8") as f:
        for p in sorted(total_proxies):
            f.write(p + "\n")
            
    print(f"Готово! Всего уникальных прокси в файле: {len(total_proxies)}")

if __name__ == "__main__":
    main()
