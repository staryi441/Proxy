#!/usr/bin/env python3
"""
Сбор публичных MTProto-прокси из Telegram-каналов и ГЛОБАЛЬНАЯ проверка живучести.

Что делает скрипт:
  1. Читает каналы из channels.txt, вытягивает ссылки tg://proxy и t.me/proxy
     (несколько страниц истории каждого канала).
  2. Строго разбирает и нормализует каждую ссылку (секрет приводится к hex,
     определяется тип: simple / padded / fake-tls и домен маскировки).
  3. Проверяет, что хост вообще жив (TCP-connect с замером пинга) с серверов GitHub.
     Это ТОЛЬКО предварительный фильтр: рабочий отсюда прокси может быть
     заблокирован в РФ, поэтому окончательную проверку делает клиент.
  4. Ведёт историю (state.json): прокси, которых уже нет в каналах, но которые
     ещё живы, продолжают проверяться; мёртвые выбрасываются после MAX_FAILS
     подряд неудачных проверок.
  5. Пишет proxies.json (для клиента) и proxyes.txt (совместимый формат ссылок).

Только стандартная библиотека Python.
"""
import base64
import binascii
import concurrent.futures as cf
import html
import ipaddress
import json
import re
import socket
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qs

ROOT = Path(__file__).resolve().parent
CHANNELS_FILE = ROOT / "channels.txt"
STATE_FILE = ROOT / "state.json"
OUT_JSON = ROOT / "proxies.json"
OUT_TXT = ROOT / "proxyes.txt"

DEFAULT_CHANNELS = [
    "TProxyRU", "ProxyMTProto", "ProxyFree_Ru", "tgmtproxylol",
    "tg_proxyz", "proxy_telegramt", "mtproto6", "mtprotoF",
]

PAGES_PER_CHANNEL = 3     # сколько страниц истории читать у каждого канала
FETCH_TIMEOUT = 15        # сек, загрузка страницы канала
CONNECT_TIMEOUT = 4.0     # сек, одна попытка TCP-подключения
ATTEMPTS = 2              # попыток на адрес
WORKERS = 64              # параллельных проверок
MAX_FAILS = 12            # проверок подряд (~сутки при запуске раз в 2 часа) до удаления
MAX_NEW_PER_RUN = 500     # защита от «заливки» мусора из канала
PING_STEP_MS = 10         # округление пинга, чтобы файлы не менялись из-за шума

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
LINK_RE = re.compile(r"(?:tg://proxy|https?://t\.me/proxy)\?[^\s\"'<>]+")
POST_RE = re.compile(r'data-post="[^"/]+/(\d+)"')
HOST_RE = re.compile(r"[a-z0-9]([a-z0-9.-]*[a-z0-9])?")
DOMAIN_RE = re.compile(r"[a-z0-9.-]+")


def now_str():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%MZ")


# ───────────────────────── сбор ─────────────────────────

def load_channels():
    if not CHANNELS_FILE.exists():
        return DEFAULT_CHANNELS
    out = []
    for line in CHANNELS_FILE.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip().lstrip("@")
        if line:
            out.append(line)
    return out or DEFAULT_CHANNELS


def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT) as resp:
        return resp.read().decode("utf-8", errors="replace")


def scrape_channel(channel):
    """Возвращает сырые ссылки из нескольких страниц истории канала."""
    found, before = [], None
    for _ in range(PAGES_PER_CHANNEL):
        url = f"https://t.me/s/{channel}" + (f"?before={before}" if before else "")
        try:
            page = fetch(url)
        except Exception as e:  # сеть/блокировка/404 — просто пропускаем канал
            print(f"  ! {channel}: {e}")
            break
        found += LINK_RE.findall(page)
        ids = [int(i) for i in POST_RE.findall(page)]
        if not ids or (before is not None and min(ids) >= before):
            break
        before = min(ids)
    return found


# ───────────────────────── разбор ─────────────────────────

def decode_secret(s):
    """Секрет в ссылках бывает hex или base64url. Возвращает bytes или None."""
    s = s.strip()
    if not s:
        return None
    if len(s) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", s):
        return bytes.fromhex(s)
    try:
        return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    except (binascii.Error, ValueError):
        return None


def classify(raw):
    """Тип секрета по формату MTProxy. Возвращает (тип, домен) или None."""
    if raw is None:
        return None
    if len(raw) == 16:
        return "simple", ""
    if len(raw) == 17 and raw[0] == 0xDD:
        return "padded", ""
    if len(raw) > 17 and raw[0] == 0xEE:
        dom = raw[17:].decode("ascii", "ignore").lower()
        if dom and DOMAIN_RE.fullmatch(dom):
            return "fake-tls", dom
    return None


def normalize(link):
    """Ссылка -> словарь с чистыми полями или None, если ссылка негодная."""
    link = html.unescape(link).rstrip(".,;:)'\"")
    if "?" not in link:
        return None
    q = parse_qs(link.split("?", 1)[1])
    first = lambda k: (q.get(k) or [""])[0]

    server = first("server").strip().strip(".").lower()
    port = first("port").strip()
    secret = first("secret").strip().replace(" ", "+")  # '+' из base64 превращается в пробел

    if not server or not HOST_RE.fullmatch(server):
        return None
    try:
        ip = ipaddress.ip_address(server)
        if not ip.is_global:           # 10.x, 192.168.x, 127.x и т.п.
            return None
    except ValueError:
        pass                            # это доменное имя
    if not port.isdigit() or not 1 <= int(port) <= 65535:
        return None
    raw = decode_secret(secret)
    info = classify(raw)
    if info is None:
        return None
    kind, domain = info
    return {
        "server": server,
        "port": int(port),
        "secret": raw.hex(),
        "type": kind,
        "domain": domain,
    }


def key_of(e):
    return f"{e['server']}:{e['port']}:{e['secret']}"


def to_link(e):
    return f"https://t.me/proxy?server={e['server']}&port={e['port']}&secret={e['secret']}"


# ───────────────────────── проверка ─────────────────────────

def check_host(server, port, allow_private=False):
    """TCP-проверка живучести. Возвращает лучший пинг в мс или None."""
    try:
        infos = socket.getaddrinfo(server, port, type=socket.SOCK_STREAM)
    except OSError:
        return None
    best = None
    tried = 0
    for fam, typ, proto, _, sa in infos:
        if not allow_private:
            try:
                if not ipaddress.ip_address(sa[0].split("%")[0]).is_global:
                    continue
            except ValueError:
                continue
        if tried >= 2:                  # не более двух адресов на хост
            break
        tried += 1
        for _ in range(ATTEMPTS):
            t0 = time.perf_counter()
            try:
                with socket.socket(fam, typ, proto) as s:
                    s.settimeout(CONNECT_TIMEOUT)
                    s.connect(sa)
                ms = (time.perf_counter() - t0) * 1000
                best = ms if best is None else min(best, ms)
            except OSError:
                pass
        if best is not None:
            break
    return best


def check_all(entries):
    """Параллельная проверка. Возвращает {key: ping_ms | None}."""
    results = {}
    with cf.ThreadPoolExecutor(max_workers=WORKERS) as pool:
        futs = {pool.submit(check_host, e["server"], e["port"]): key_of(e) for e in entries}
        for fut in cf.as_completed(futs):
            try:
                results[futs[fut]] = fut.result()
            except Exception:
                results[futs[fut]] = None
    return results


# ───────────────────────── состояние ─────────────────────────

def load_state():
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            print("! state.json повреждён, начинаем с нуля")
    return {}


def seed_from_old_txt():
    """Один раз подхватываем прежний proxyes.txt, чтобы не терять накопленное."""
    out = []
    if OUT_TXT.exists():
        for line in OUT_TXT.read_text(encoding="utf-8").splitlines():
            n = normalize(line.strip())
            if n:
                out.append(n)
    return out


def main():
    ts = now_str()
    state = load_state()

    # 1. сбор
    candidates = {}
    for ch in load_channels():
        links = scrape_channel(ch)
        good = [n for n in (normalize(l) for l in links) if n]
        print(f"{ch}: ссылок {len(links)}, валидных {len(good)}")
        for n in good:
            candidates.setdefault(key_of(n), n)
    if not state:
        for n in seed_from_old_txt():
            candidates.setdefault(key_of(n), n)
    if not candidates:
        print("! Каналы ничего не дали, проверяем только накопленное")

    # 2. слияние с историей (новые — с ограничением на объём)
    new_keys = [k for k in candidates if k not in state][:MAX_NEW_PER_RUN]
    for k in new_keys:
        e = dict(candidates[k])
        e.update(first_seen=ts, last_ok=None, fails=0, ping_ms=None)
        state[k] = e
    print(f"Новых: {len(new_keys)}, всего к проверке: {len(state)}")

    # 3. глобальная проверка всех известных
    results = check_all(list(state.values()))
    alive_now = sum(1 for v in results.values() if v is not None)
    print(f"Живых сейчас: {alive_now} из {len(results)}")

    # Защита: если не ответил НИКТО — скорее всего проблема сети у раннера.
    # Ничего не перезаписываем, чтобы не обнулить рабочий список.
    if results and alive_now == 0:
        print("! Никто не ответил — похоже на сбой сети раннера. Файлы не меняю.")
        return

    # 4. обновление статусов
    for k, ping in results.items():
        e = state[k]
        if ping is not None:
            e["fails"] = 0
            e["last_ok"] = ts
            e["ping_ms"] = max(PING_STEP_MS, int(round(ping / PING_STEP_MS)) * PING_STEP_MS)
        else:
            e["fails"] += 1
            e["ping_ms"] = None
            if e["last_ok"] is None or e["fails"] >= MAX_FAILS:
                del state[k]        # ни разу не отвечал или давно мёртв

    # 5. публикация
    alive = sorted(
        (e for e in state.values() if e["fails"] == 0),
        key=lambda e: (e["ping_ms"], e["server"], e["port"]),
    )
    public = [
        {k: e[k] for k in ("server", "port", "secret", "type", "domain", "ping_ms", "first_seen", "last_ok")}
        for e in alive
    ]
    OUT_JSON.write_text(
        json.dumps({"updated": ts, "count": len(public), "proxies": public}, ensure_ascii=False, indent=1) + "\n",
        encoding="utf-8",
    )
    OUT_TXT.write_text("".join(to_link(e) + "\n" for e in alive), encoding="utf-8")
    STATE_FILE.write_text(json.dumps(state, ensure_ascii=False, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Готово: опубликовано {len(public)}, в истории {len(state)}")


if __name__ == "__main__":
    main()
