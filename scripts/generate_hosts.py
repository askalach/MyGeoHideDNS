#!/usr/bin/env python3
"""Собирает hosts/hosts из upstream-источников.

Redirect-часть (строки вида "IP домен") — только категории из KEEP_CATEGORIES,
взятые из GeoHideDNS. IP прокси приезжают из upstream, поэтому обновляются сами.

Block-часть (строки вида "0.0.0.0 домен") — трекерные списки HaGeZi из реестра
AdGuard, приведённые из синтаксиса "||домен^" в hosts-формат.

Файл читает DnsConf: HostsOverrideListsLoader берёт строки с IP, а
HostsBlockListsLoader — строки с 0.0.0.0.
"""

import argparse
import re
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

GEOHIDE_URL = "https://raw.githubusercontent.com/Internet-Helper/GeoHideDNS/refs/heads/main/hosts/hosts"

# Заголовки секций РОВНО так, как они написаны в upstream-файле.
# Если upstream переименует секцию, скрипт упадёт с понятной ошибкой,
# а не выкинет её молча.
KEEP_CATEGORIES = [
    "ChatGPT (OpenAI) AI",
    "Claude AI",
    "Google Gemini AI",
    "Grok AI",
    "Meta AI",
    "DeepL",
    "ElevenLabs AI",
    "Microsoft (Copilot, Designer, Xbox)",
    "Notion",
]

# Домены, которых нет в upstream, но без них сервис работает неполноценно.
# IP подставляются те же, что upstream использует для прокси, поэтому при смене
# прокси эти записи переезжают вместе с остальными.
#
# Важно: rewrites в NextDNS действуют на все поддомены, поэтому апекс покрывает
# всё поддерево разом и перечислять хосты поштучно не нужно.
EXTRA_DOMAINS = [
    # Загруженные файлы и сгенерированные картинки ChatGPT отдаёт с хостов
    # sdmntpr<регион>.oaiusercontent.com. Upstream перечисляет лишь четыре
    # региона, и при попадании на любой другой вложения отваливаются.
    "oaiusercontent.com",
]

# Какой прокси ставить первым. NextDNS применяет только первый IP для домена
# (NextDnsRewriteService.buildNewRewrites использует putIfAbsent), поэтому порядок
# в файле определяет, через какой сервер пойдёт весь трафик. Upstream перечисляет
# прокси в своём порядке, и он не обязан совпадать с тем, что быстрее у тебя.
#
# None — сохранить порядок upstream. Иначе укажи IP, который нужно поднять наверх.
# Померить со своей сети:
#   curl -s --max-time 10 --resolve gemini.google.com:443:<IP> \
#        https://gemini.google.com -o /dev/null -w '%{speed_download}\n'
PREFERRED_PROXY_IP = "193.233.112.88"

BLOCK_URLS = [
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_67.txt",  # Apple
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_66.txt",  # OPPO & Realme
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_65.txt",  # Vivo
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_63.txt",  # Windows/Office
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_61.txt",  # Samsung
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_60.txt",  # Xiaomi
]

OUTPUT = Path(__file__).resolve().parent.parent / "hosts" / "hosts"

# Если новый файл внезапно сильно меньше старого — скорее всего upstream сломался
# или переехал. Лучше упасть, чем отдать в NextDNS обрезанный список.
SHRINK_LIMIT = 0.7

HOST_LINE = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3})\s+(\S+)\s*$")
COMMENTED_HOST = re.compile(r"^#\s*\d{1,3}(?:\.\d{1,3}){3}\s+\S+")
ADGUARD_RULE = re.compile(r"^\|\|([a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\.[a-z]{2,})\^$")
BARE_DOMAIN = re.compile(r"^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\.[a-z]{2,}$")


def fetch(url: str) -> str:
    request = urllib.request.Request(url, headers={"User-Agent": "MyGeoHideDNS-generator"})
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            return response.read().decode("utf-8")
    except (urllib.error.URLError, TimeoutError) as error:
        sys.exit(f"Не удалось скачать {url}: {error}")


def split_sections(text: str) -> dict[str, list[tuple[str, str]]]:
    """Режет upstream-hosts на секции по заголовкам вида '# Название'."""
    sections: dict[str, list[tuple[str, str]]] = {}
    current: str | None = None

    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("###"):
            current = None  # служебные рамки файла, не категория
            continue
        if line.startswith("#"):
            if COMMENTED_HOST.match(line):
                continue  # отключённая запись внутри секции, не новый заголовок
            current = line.lstrip("#").strip()
            sections.setdefault(current, [])
            continue
        if current is None:
            continue  # преамбула до первой категории (localhost, торренты, Meta)
        match = HOST_LINE.match(line)
        if match:
            sections[current].append((match.group(1), match.group(2)))

    return sections


def collect_redirects(sections: dict[str, list[tuple[str, str]]]) -> list[str]:
    missing = [name for name in KEEP_CATEGORIES if not sections.get(name)]
    if missing:
        sys.exit(
            "В upstream не найдены (или пусты) категории:\n  "
            + "\n  ".join(missing)
            + "\n\nВероятно, их переименовали. Доступные сейчас:\n  "
            + "\n  ".join(sorted(name for name, rows in sections.items() if rows))
        )

    lines: list[str] = []
    covered: set[str] = set()
    for name in KEEP_CATEGORIES:
        lines.append("")
        lines.append(f"# {name}")
        # Домены группируем, сохраняя порядок появления, чтобы можно было
        # переставить IP внутри каждого домена, не перемешивая сам список.
        by_domain: dict[str, list[str]] = {}
        for ip, domain in sections[name]:
            covered.add(domain)
            ips = by_domain.setdefault(domain, [])
            if ip not in ips:
                ips.append(ip)
        for domain, ips in by_domain.items():
            lines.extend(f"{ip} {domain}" for ip in prioritise(ips))

    extras = [domain for domain in EXTRA_DOMAINS if domain not in covered]
    if extras:
        proxy_ips = prioritise(detect_proxy_ips(sections))
        lines.append("")
        lines.append("# Добавлено вручную (EXTRA_DOMAINS), в upstream отсутствует")
        for domain in extras:
            lines.extend(f"{ip} {domain}" for ip in proxy_ips)

    return lines


def prioritise(ips: list[str]) -> list[str]:
    """Поднимает PREFERRED_PROXY_IP наверх — именно он и применится в NextDNS."""
    if PREFERRED_PROXY_IP is None or PREFERRED_PROXY_IP not in ips:
        return ips
    return [PREFERRED_PROXY_IP] + [ip for ip in ips if ip != PREFERRED_PROXY_IP]


def detect_proxy_ips(sections: dict[str, list[tuple[str, str]]]) -> list[str]:
    """Определяет адреса прокси по первому домену первой оставленной категории.

    Берём их из upstream, а не хардкодим, чтобы ручные записи переезжали вместе
    с остальными при смене прокси.
    """
    rows = sections[KEEP_CATEGORIES[0]]
    anchor = rows[0][1]
    ips = [ip for ip, domain in rows if domain == anchor]
    if not ips:
        sys.exit("Не удалось определить IP прокси из upstream.")
    return ips


def collect_blocks() -> list[str]:
    domains: set[str] = set()
    for url in BLOCK_URLS:
        for raw in fetch(url).splitlines():
            line = raw.strip().lower()
            if not line or line[0] in "!#/" or line.startswith("@@"):
                continue
            if "*" in line or "$" in line:
                continue  # правила с модификаторами в hosts не переводятся
            match = ADGUARD_RULE.match(line)
            if match:
                domains.add(match.group(1))
            elif BARE_DOMAIN.match(line):
                domains.add(line)

    lines = ["", "# Блокировка рекламы и трекеров (HaGeZi через реестр AdGuard)"]
    lines.extend(f"0.0.0.0 {domain}" for domain in sorted(domains))
    return lines


def count_redirect_domains(text: str) -> int:
    domains = set()
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("#") or not line:
            continue
        match = HOST_LINE.match(line)
        if match and match.group(1) != "0.0.0.0":
            domains.add(match.group(2))
    return len(domains)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--force", action="store_true", help="пропустить проверку на резкое сокращение списка")
    args = parser.parse_args()

    sections = split_sections(fetch(GEOHIDE_URL))
    redirects = collect_redirects(sections)
    blocks = collect_blocks()

    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    header = [
        "# Сгенерировано автоматически скриптом scripts/generate_hosts.py",
        f"# Дата сборки: {generated}",
        "# Руками не править — изменения затрутся. Категории задаются в KEEP_CATEGORIES.",
        "#",
        "# Redirect-источник:",
        f"#   {GEOHIDE_URL}",
        "# Block-источники:",
        *(f"#   {url}" for url in BLOCK_URLS),
    ]

    body = "\n".join(header + redirects + blocks) + "\n"

    new_count = count_redirect_domains(body)
    if OUTPUT.exists() and not args.force:
        old_count = count_redirect_domains(OUTPUT.read_text(encoding="utf-8"))
        if old_count and new_count < old_count * SHRINK_LIMIT:
            sys.exit(
                f"Redirect-доменов стало {new_count} против {old_count} — "
                f"падение больше {int((1 - SHRINK_LIMIT) * 100)}%. "
                "Проверь upstream; если сокращение ожидаемо, запусти с --force."
            )

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(body, encoding="utf-8")

    block_count = sum(1 for line in blocks if line.startswith("0.0.0.0"))
    print(f"Записан {OUTPUT}")
    print(f"  redirect: {new_count} доменов в {len(KEEP_CATEGORIES)} категориях")
    print(f"  block:    {block_count} доменов")


if __name__ == "__main__":
    main()
