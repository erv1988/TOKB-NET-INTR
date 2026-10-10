#!/bin/sh
# ---------------------------------------------------------------------------
# firewall_lab.sh — сборка межсетевого экрана на ЗАЩИЩАЕМОМ ХОСТЕ.
# Стенд: две ВМ Alpine Linux из dist/alpine-tokb.ova, изолированная сеть VirtualBox.
# На учебном образе скрипт лежит в /opt/tokb/firewall_lab.sh.
#
# Использование (все команды — от root):
#   ./firewall_lab.sh show        # что сейчас есть: правила, счётчики, ARP
#   ./firewall_lab.sh stateful    # ЭТАП 4.1: «запрещено всё, что не разрешено»
#   ./firewall_lab.sh synflood    # ЭТАП 4.2: защита от SYN-флуда
#   ./firewall_lab.sh arp         # ЭТАП 6: защита от ARP-спуфинга
#   ./firewall_lab.sh reset       # снять всё, что поставили (вернуть стенд в исходное)
#
# ВНИМАНИЕ: скрипт рассчитан на учебную ВМ. `reset` полностью очищает правила
# фильтрации. НЕ применять эту логику «как есть» на рабочей системе.
# ---------------------------------------------------------------------------

set -u

SERVICE_PORT=${SERVICE_PORT:-8080}      # порт учебного сервиса (vuln_service.py)
SSH_PORT=${SSH_PORT:-22}                # SSH оставляем, чтобы не потерять доступ к ВМ
GATEWAY_IP=${GATEWAY_IP:-192.168.56.1}  # «шлюз» = хост Windows (VirtualBox Host-Only)
IFACE=${IFACE:-eth0}                    # сетевой интерфейс ВМ

need_root() {
    if [ "$(id -u)" != "0" ]; then
        echo "[!] Запускайте от root: sudo $0 $*" >&2
        exit 1
    fi
}

# --------------------------------------------------------- 4.1 stateful ----
# Идея межсетевого экрана: сначала ЗАПРЕТИТЬ всё, потом разрешить нужное.
# Правила читаются СВЕРХУ ВНИЗ, срабатывает первое подходящее.
cmd_stateful() {
    echo "[*] Политика по умолчанию: DROP (запрещено всё, что не разрешено)"
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -F INPUT

    iptables -A INPUT -i lo -j ACCEPT
    # состояние соединения: ответные пакеты уже разрешённых соединений пропускаем
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A INPUT -p tcp --dport "$SSH_PORT" -j ACCEPT
    iptables -A INPUT -p tcp --dport "$SERVICE_PORT" -j ACCEPT
    iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 5/s -j ACCEPT
    # всё прочее — сначала в журнал (видно попытки сканирования), затем в утиль
    iptables -A INPUT -j LOG --log-prefix "FW_DROP: " --log-level 4
    iptables -A INPUT -j DROP

    echo "[*] Готово. Ожидаемо: сканирование чужих портов даёт состояние 'filtered'."
    iptables -L INPUT -n -v --line-numbers
}

# ------------------------------------------------------- 3 synvuln --------
# ВНИМАНИЕ: этот режим делает хост УЯЗВИМЫМ. Он нужен только для этапа 3,
# чтобы своими глазами увидеть, что именно лечит защита из этапа 4.2.
# В современных ядрах Linux `tcp_syncookies=1` включено ПО УМОЛЧАНИЮ — и без
# его отключения SYN-флуд на учебной скорости просто не даёт эффекта.
cmd_synvuln() {
    echo "[!] ВРЕМЕННО снижаем защищённость хоста (только для этапа 3)"
    sysctl -w net.ipv4.tcp_syncookies=0         # выключаем главную защиту
    sysctl -w net.ipv4.tcp_max_syn_backlog=64   # маленькая очередь полуоткрытых
    sysctl -w net.ipv4.tcp_synack_retries=5     # дольше держим полуоткрытые соединения
    echo
    echo "[*] Текущее состояние:"
    sysctl net.ipv4.tcp_syncookies net.ipv4.tcp_max_syn_backlog
    echo
    echo "[i] Теперь запускайте атаку и измеряйте:"
    echo "    watch -n1 \"ss -tan state syn-recv | wc -l\""
}

# --------------------------------------------------------- 4.2 synflood ----
# Против SYN-флуда работают ДВА разных механизма, и они дополняют друг друга:
#  1) параметры ядра (SYN-cookies) — спасают сам хост, не храня состояние;
#  2) ограничение скорости — срезают лишний поток (защита канала и сервиса).
cmd_synflood() {
    echo "[*] 1. Параметры ядра"
    sysctl -w net.ipv4.tcp_syncookies=1        # не занимать память под полуоткрытые соединения
    sysctl -w net.ipv4.tcp_max_syn_backlog=1024 # размер очереди полуоткрытых соединений
    sysctl -w net.ipv4.tcp_synack_retries=2     # меньше повторов SYN+ACK

    echo "[*] 2. Ограничение скорости НОВЫХ SYN на порт $SERVICE_PORT"
    iptables -N LAB_SYN_GUARD 2>/dev/null || true
    iptables -F LAB_SYN_GUARD
    # --syn = установлен SYN и сброшены ACK/RST/FIN, т.е. только ПЕРВЫЙ пакет соединения.
    # --limit 20/s --limit-burst 40: первые 40 пакетов пропускаются сразу, далее 20 в секунду.
    iptables -A LAB_SYN_GUARD -m limit --limit 20/s --limit-burst 40 -j RETURN
    iptables -A LAB_SYN_GUARD -j LOG --log-prefix "SYN_FLOOD: " --log-level 4
    iptables -A LAB_SYN_GUARD -j DROP

    # Альтернатива: ограничение ПО КАЖДОМУ источнику (честнее для легальных клиентов).
    # Раскомментируйте, если модуль xt_hashlimit доступен:
    #   iptables -A LAB_SYN_GUARD -m hashlimit --hashlimit-above 10/s \
    #            --hashlimit-mode srcip --hashlimit-name synperip -j DROP

    # снимаем старую копию правила, чтобы не дублировать
    while iptables -D INPUT -p tcp --syn --dport "$SERVICE_PORT" -j LAB_SYN_GUARD 2>/dev/null; do :; done
    iptables -I INPUT 1 -p tcp --syn --dport "$SERVICE_PORT" -j LAB_SYN_GUARD

    echo "[*] Готово. Счётчики срабатываний смотрите в колонке pkts:"
    iptables -L LAB_SYN_GUARD -n -v --line-numbers
}

# --------------------------------------------------------------- arp ------
# ARP-спуфинг защищается не фильтрацией IP, а ФИКСАЦИЕЙ связки IP<->MAC:
# жертва перестаёт верить «непрошеным» ARP-reply, потому что запись постоянная.
cmd_arp() {
    GATEWAY_MAC=${GATEWAY_MAC:-}
    if [ -z "$GATEWAY_MAC" ]; then
        GATEWAY_MAC=$(ip neigh show "$GATEWAY_IP" dev "$IFACE" | awk '{print $5}')
    fi
    if [ -z "$GATEWAY_MAC" ]; then
        echo "[!] Не удалось определить MAC для $GATEWAY_IP." >&2
        echo "    Выполните ping $GATEWAY_IP и повторите, либо задайте: GATEWAY_MAC=... $0 arp" >&2
        exit 1
    fi

    echo "[*] Фиксируем постоянную запись: $GATEWAY_IP -> $GATEWAY_MAC (dev $IFACE)"
    ip neigh replace "$GATEWAY_IP" lladdr "$GATEWAY_MAC" dev "$IFACE" nud permanent
    echo "[*] Таблица ARP теперь:"
    ip neigh show dev "$IFACE"

    echo
    echo "[i] Дополнительно (необязательно) — фильтр ARP, если установлен arptables:"
    echo "    arptables -A INPUT --opcode 2 --source-ip <НАШ_IP> -j DROP"
    echo "    (запрещает ARP-reply, в котором НАШ адрес выдаётся за чужой MAC)"
    echo "    Проверить наличие: arptables --version"
}

# -------------------------------------------------------------- show ------
cmd_show() {
    echo "=== filter: INPUT ==="
    iptables -L INPUT -n -v --line-numbers
    echo
    echo "=== filter: OUTPUT ==="
    iptables -L OUTPUT -n -v --line-numbers
    echo
    echo "=== цепочка защиты от SYN-флуда (если создана) ==="
    iptables -L LAB_SYN_GUARD -n -v 2>/dev/null || echo "(не создана)"
    echo
    echo "=== таблица ARP ==="
    ip neigh show
    echo
    echo "=== сводка по сокетам ==="
    ss -s
}

# ------------------------------------------------------------- reset ------
cmd_reset() {
    echo "[*] Снимаем правила (стенд возвращается в исходное состояние)"
    iptables -P INPUT ACCEPT
    iptables -P FORWARD ACCEPT
    iptables -P OUTPUT ACCEPT
    iptables -F
    iptables -X
    ip neigh del "$GATEWAY_IP" dev "$IFACE" 2>/dev/null || true
    # SYN-cookies полезны всегда — оставляем включёнными
    sysctl -w net.ipv4.tcp_syncookies=1
    echo "[*] Готово:"; iptables -L INPUT -n -v; ip neigh show
}

# -------------------------------------------------------------- main ------
case "${1:-}" in
    stateful) need_root "$@"; cmd_stateful ;;
    synvuln)  need_root "$@"; cmd_synvuln ;;
    synflood) need_root "$@"; cmd_synflood ;;
    arp)      need_root "$@"; cmd_arp ;;
    show)     need_root "$@"; cmd_show ;;
    reset)    need_root "$@"; cmd_reset ;;
    *)
        echo "Использование: sudo $0 {stateful|synvuln|synflood|arp|show|reset}"
        echo
        echo "  stateful  — политика «запрещено всё, что не разрешено» (ЭТАП 4.1)"
        echo "  synvuln   — ВРЕМЕННО отключить защиту от SYN-флуда (ЭТАП 3, «до»)"
        echo "  synflood  — SYN-cookies + ограничение скорости SYN (ЭТАП 4.2, «после»)"
        echo "  arp       — постоянная ARP-запись шлюза (ЭТАП 6)"
        echo "  show      — показать правила, счётчики и ARP-таблицу"
        echo "  reset     — снять все правила (вернуть стенд)"
        exit 1
        ;;
esac
