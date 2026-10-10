#!/usr/bin/env bash
# ===========================================================================
#  refresh_ova.sh — ПЕРЕСБОРКА dist/alpine-tokb.ova из уже готового образа.
#
#  Зачем. Полная сборка (build_ova.sh) ставит систему с ISO — это несколько
#  минут и она начинается «с нуля». Но когда меняются только МАТЕРИАЛЫ ЛР
#  (provision.sh, скрипты в scripts/, конфиги в configs/), переустанавливать
#  систему не нужно: достаточно импортировать готовый OVA, ещё раз прогнать
#  внутри него provision.sh и экспортировать обратно.
#
#  Требуется: VirtualBox 7.x, запуск ВНЕ песочницы (см. build_ova.sh),
#  работающий HTTP-сервер на 8008, раздающий корень проекта.
#
#  ВАЖНО про консоль (проверено практикой):
#    * на УСТАНОВЛЕННОЙ Alpine отправляет строку только Ctrl-J (= LF,
#      скан-коды 1d 24 9d a4), а не Enter;
#    * после keyboardputstring нужна пауза ~2 с, иначе перевод строки теряется;
#    * в импортированном образе root/alpine уже заданы (это сделал provision
#      при первой сборке), поэтому на логине нужно ввести И пароль.
#
#  Проверка результата: скриншоты консоли (shot_*.png) и строка
#    «ИТОГ: ПРОВЕРКИ ПРОЙДЕНЫ — правила работают на сформированном трафике»
#  в хвосте /tmp/prov.log.
# ===========================================================================
set -euo pipefail

PROJ="$(cd "$(dirname "$0")/.." && pwd)"
OVA="${OVA:-$PROJ/dist/alpine-tokb.ova}"
VM="${VM:-alpine-tokb-refresh}"
PORT="${PORT:-8008}"
WORK="${WORK:-$LOCALAPPDATA/Temp/tokb_build}"
VBM="${VBM:-/c/Program Files/Oracle/VirtualBox/VBoxManage.exe}"

mkdir -p "$WORK"
log() { printf '\n=== %s ===\n' "$*"; }

guest_type() {
    "$VBM" controlvm "$VM" keyboardputstring "$1"
    sleep 2
    "$VBM" controlvm "$VM" keyboardputscancode 1d 24 9d a4   # Ctrl-J = LF
}
guest_shot() {
    local f="$WORK/shot_$(date +%H%M%S).png"
    "$VBM" controlvm "$VM" screenshotpng "$f"
    echo "    скриншот: $f"
}
guest_wait() { sleep "${1:-10}"; }

[ -f "$OVA" ] || { echo "Нет файла $OVA"; exit 1; }
echo "Исходный OVA: $(ls -lh "$OVA" | awk '{print $5}') от $(date -r "$OVA" '+%F %T')"

# ===========================================================================
log "1. HTTP-сервер должен уже быть поднят (раздаёт корень проекта)"
curl -sf "http://127.0.0.1:$PORT/build/provision.sh" >/dev/null \
    && echo "HTTP-сервер отвечает на $PORT" \
    || { echo "HTTP-сервер на $PORT НЕ отвечает — поднимите его и повторите"; exit 1; }

# ===========================================================================
log "2. Импорт готового OVA во временную ВМ"
"$VBM" unregistervm "$VM" --delete 2>/dev/null || true
"$VBM" import "$OVA" --vsys 0 --vmname "$VM"

# ===========================================================================
log "3. Загрузка и вход (root, пароль alpine — задан при первой сборке)"
"$VBM" startvm "$VM" --type headless
guest_wait 30
guest_shot
guest_type "root"
guest_wait 4
guest_type "alpine"
guest_wait 5
guest_shot

# ===========================================================================
log "4. Провижн (повторный, идемпотентный)"
guest_type "wget -qO /tmp/p.sh http://10.0.2.2:$PORT/build/provision.sh && sh /tmp/p.sh > /tmp/prov.log 2>&1; echo RC=\$?; tail -30 /tmp/prov.log"
guest_wait 300
guest_shot
# Контроль состава материалов: в /opt/tokb должны быть ВСЕ скрипты,
# firewall_lab.sh и verify_ids.py (в логе провижна не должно быть «ПРОПУЩЕН»).
guest_type "ls -l /opt/tokb; echo ---; ls -l /etc/snort /etc/snort/rules; echo ---; grep -c enable_builtin_rules /etc/snort/lab.lua"
guest_wait 8
guest_shot
# Ожидаем в хвосте лога:
#   [OK  ] LAB SCAN  (sid 1000001)
#   [OK  ] LAB DOS   (sid 1000002)
#   [OK  ] ARP-спуфинг (инспектор)
#   ИТОГ: ПРОВЕРКИ ПРОЙДЕНЫ — правила работают на сформированном трафике

# ===========================================================================
log "5. Чистка гостя перед экспортом"
guest_type "rm -f /tmp/p.sh /tmp/prov.log /tmp/tokb_*.pcap /etc/snort/*.rej /etc/snort/*.orig; rm -rf /root/.ash_history /home/student/.ash_history; sync"
guest_wait 5
guest_type "poweroff"
guest_wait 20

# ===========================================================================
log "6. Экспорт"
# ВАЖНО: VBoxManage требует, чтобы имя выходного файла заканчивалось на .ova
# (или .ovf) — поэтому промежуточный файл тоже .ova, а не «.ova.tmp».
"$VBM" export "$VM" --output "$OVA.new.ova" --ovf20
mv -f "$OVA.new.ova" "$OVA"
"$VBM" unregistervm "$VM" --delete
ls -lh "$OVA"

echo
echo "Готово: $OVA обновлён — проверьте скриншот выше, что самопроверка дала «ПРОВЕРКИ ПРОЙДЕНЫ»."
echo "Быстрая проверка импорта: $VBM import '$OVA' --vsys 0 --vmname test-import --dry-run"
