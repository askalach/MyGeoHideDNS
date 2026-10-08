#!/usr/bin/env bash
# Меряет пропускную способность прокси, чтобы выбрать значение PREFERRED_PROXY_IP
# в scripts/generate_hosts.py.
#
# Зачем: NextDNS применяет только первый IP каждого домена, поэтому порядок строк
# в hosts решает, через какой сервер идёт весь трафик. Медленный прокси не ломает
# текстовый чат, но убивает загрузку тяжёлых страниц и отправку файлов.
#
# Запускать со своей сети — из другой страны результат не показателен.
#
#   ./scripts/measure_proxies.sh                     # 5 замеров на gemini.google.com
#   ./scripts/measure_proxies.sh chatgpt.com 3       # свой домен и число замеров

set -u

TARGET=${1:-gemini.google.com}
TRIALS=${2:-5}
TIMEOUT=10

HOSTS="$(cd "$(dirname "$0")/.." && pwd)/hosts/hosts"
[ -r "$HOSTS" ] || { echo "Не найден $HOSTS"; exit 1; }

# IP прокси берём из самого файла: это адреса, на которые смотрит масса доменов.
# Так список не разъезжается с hosts при смене прокси в upstream.
IPS=$(grep -v '^#' "$HOSTS" \
      | awk 'NF>=2 && $1!="0.0.0.0" {print $1}' \
      | sort | uniq -c | sort -rn \
      | awk '$1 > 10 {print $2}')

[ -n "$IPS" ] || { echo "В $HOSTS не нашлось адресов прокси"; exit 1; }

echo "Цель: $TARGET, замеров на прокси: $TRIALS, таймаут: ${TIMEOUT}s"
echo

for ip in $IPS; do
    printf '%-18s ' "$ip"

    # Сначала TCP: если порт не открыт, мерить скорость бессмысленно, и это
    # совсем другой диагноз, чем «подключился, но еле тянет».
    if ! nc -z -G 5 -w 5 "$ip" 443 >/dev/null 2>&1; then
        echo "порт 443 недоступен из этой сети"
        continue
    fi

    speeds=""
    slow=0
    errors=""

    for _ in $(seq 1 "$TRIALS"); do
        speed=$(curl -s --max-time "$TIMEOUT" \
                     --resolve "$TARGET:443:$ip" "https://$TARGET" \
                     -o /dev/null -w '%{speed_download}' 2>/dev/null)
        code=$?
        speed=${speed%%.*}                      # curl умеет отдавать дробное
        case $speed in
            ''|*[!0-9]*) speed=0 ;;             # на всякий случай: не число
        esac

        if [ "$code" -ne 0 ]; then
            errors="$errors $code"
            case $code in
                28) printf '   T' ;;            # таймаут: соединился, не дотянул
                7)  printf '   C' ;;            # не удалось подключиться
                35) printf '   S' ;;            # ошибка TLS
                *)  printf ' e%02d' "$code" ;;
            esac
        elif [ "$speed" -lt 1024 ]; then
            slow=$((slow + 1))
            printf '   ·'
        else
            printf ' %3dK' "$((speed / 1024))"
        fi
        speeds="$speeds $speed"
    done

    median=$(printf '%s\n' $speeds | sort -n | awk '{v[NR]=$1} END {print v[int((NR+1)/2)]}')
    printf '   медиана %s КБ/с' "$((median / 1024))"
    [ "$slow" -gt 0 ] && printf '   почти стоял: %s из %s' "$slow" "$TRIALS"
    echo
done

echo
echo "· — меньше 1 КБ/с, канал фактически стоит (но соединение было)."
echo "T — таймаут ${TIMEOUT}s: подключился, ответ не дотянул."
echo "C — подключиться не удалось.   S — ошибка TLS."
echo "Победителя впиши в PREFERRED_PROXY_IP (scripts/generate_hosts.py) и пересобери:"
echo "  python3 scripts/generate_hosts.py"
