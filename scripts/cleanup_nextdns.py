#!/usr/bin/env python3
"""Удаляет из профиля NextDNS rewrites, которых больше нет в hosts/hosts.

Зачем: DnsConf добавляет rewrites, но никогда не удаляет лишние. В
NextDnsRewriteService.cleanupOutdated домен, отсутствующий в новом списке,
просто выбрасывается из очереди на добавление, а запись в NextDNS остаётся
навсегда. Поэтому сокращение hosts-файла само по себе ничего не чистит.

Денилист не трогается — только /rewrites.

Запуск:
    export NEXTDNS_API_KEY=...      # my.nextdns.io/account
    export NEXTDNS_PROFILE_ID=...   # ID из секции Endpoints
    python3 scripts/cleanup_nextdns.py           # показать, что удалилось бы
    python3 scripts/cleanup_nextdns.py --apply   # удалить
"""

import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

API_ROOT = "https://api.nextdns.io/profiles"
USER_AGENT = "MyGeoHideDNS-cleanup"
HOSTS = Path(__file__).resolve().parent.parent / "hosts" / "hosts"
HOST_LINE = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3})\s+(\S+)\s*$")

# NextDNS отдаёт 429 после ~60 запросов в минуту и сбрасывает счётчик через
# 60 секунд после последнего запроса.
REQUEST_PAUSE = 1.05
RATE_LIMIT_WAIT = 60


def api(method: str, path: str, key: str) -> dict | None:
    # User-Agent обязателен: api.nextdns.io стоит за Cloudflare, который блокирует
    # дефолтный "Python-urllib/*" и отдаёт 403 с телом "error code: 1010".
    # Снаружи это неотличимо от отказа в авторизации.
    request = urllib.request.Request(
        f"{API_ROOT}{path}",
        method=method,
        headers={"X-Api-Key": key, "User-Agent": USER_AGENT},
    )
    while True:
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                body = response.read().decode("utf-8")
                return json.loads(body) if body.strip() else None
        except urllib.error.HTTPError as error:
            if error.code in (429, 524):
                print(f"  лимит API ({error.code}), жду {RATE_LIMIT_WAIT} с…", flush=True)
                time.sleep(RATE_LIMIT_WAIT)
                continue
            if error.code in (401, 403):
                body = error.read().decode("utf-8", "replace").strip()
                sys.exit(
                    f"NextDNS отклонил запрос ({error.code}): {body}\n\n"
                    "Что проверить:\n"
                    "  1. Ключ сам по себе — этому запросу profile ID не нужен:\n"
                    '       curl -s -H "X-Api-Key: $NEXTDNS_API_KEY" https://api.nextdns.io/profiles\n'
                    "     authRequired в ответе — дело в ключе (my.nextdns.io/account,\n"
                    "     это НЕ шестизначный ID профиля из Setup).\n"
                    "     Список профилей в ответе — ключ рабочий, значит неверен profile ID,\n"
                    "     а правильный виден там же в поле id.\n"
                    "  2. Лишние пробелы и переводы строк в переменных окружения."
                )
            sys.exit(f"NextDNS вернул {error.code} на {method} {path}: {error.read().decode('utf-8', 'replace')}")
        except (urllib.error.URLError, TimeoutError) as error:
            sys.exit(f"Сеть недоступна: {error}")


def wanted_domains() -> set[str]:
    if not HOSTS.exists():
        sys.exit(f"Не найден {HOSTS} — сначала запусти scripts/generate_hosts.py")
    domains = set()
    for raw in HOSTS.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = HOST_LINE.match(line)
        if match and match.group(1) != "0.0.0.0":
            domains.add(match.group(2).lower())
    return domains


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="действительно удалить (по умолчанию сухой прогон)")
    args = parser.parse_args()

    # strip: при копировании из интерфейса легко утащить пробел или перевод строки,
    # а в значении заголовка они ломают авторизацию без внятного сообщения.
    key = os.environ.get("NEXTDNS_API_KEY", "").strip()
    profile = os.environ.get("NEXTDNS_PROFILE_ID", "").strip()
    if not key or not profile:
        sys.exit("Нужны переменные окружения NEXTDNS_API_KEY и NEXTDNS_PROFILE_ID.")

    keep = wanted_domains()
    print(f"В hosts/hosts ожидается {len(keep)} доменов с редиректом.")

    existing = (api("GET", f"/{profile}/rewrites", key) or {}).get("data", [])
    print(f"В профиле NextDNS сейчас {len(existing)} rewrites.")

    stale = [row for row in existing if row.get("name", "").lower() not in keep]
    if not stale:
        print("Лишних записей нет — чистить нечего.")
        return

    print(f"\nЛишних записей: {len(stale)}")
    for row in stale[:20]:
        print(f"  {row.get('name')} -> {row.get('content')}")
    if len(stale) > 20:
        print(f"  … и ещё {len(stale) - 20}")

    if not args.apply:
        minutes = len(stale) * REQUEST_PAUSE / 60
        print(f"\nСухой прогон. Удаление займёт примерно {minutes:.0f} мин из-за лимита API.")
        print("Повтори с --apply, чтобы удалить.")
        return

    print(f"\nУдаляю {len(stale)} записей…")
    for index, row in enumerate(stale, start=1):
        api("DELETE", f"/{profile}/rewrites/{row['id']}", key)
        print(f"  [{index}/{len(stale)}] {row.get('name')}", flush=True)
        time.sleep(REQUEST_PAUSE)

    print("Готово. Денилист не затронут.")


if __name__ == "__main__":
    main()
