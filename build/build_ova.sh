#!/usr/bin/env bash
# ===========================================================================
#  build_ova.sh — СБОРКА учебного OVA-образа Alpine Linux для лабораторной
#  работы ТОКБ «Безопасность сетей. Межсетевые экраны. СОВ».
#
#  Зачем этот скрипт. Официального OVA от Alpine Linux НЕ существует (проект
#  публикует только ISO). Поэтому образ собирается локально: установка Alpine
#  с официального ISO во временную ВМ, доводка пакетами и конфигами (provision.sh)
#  и экспорт в OVA, который затем импортируют студенты.
#
#  Требуется:
#    * VirtualBox 7.x (VBoxManage из комплекта);
#    * доступ в интернет с ХОСТА (скачать ISO, apk-пакеты внутри ВМ);
#    * запускать всё — ОБЯЗАТЕЛЬНО ВНЕ ПЕСОЧНИЦЫ/ограниченного окружения.
#      Если процесс VirtualBox и HTTP-сервер запущены в песочнице без доступа
#      к сети хоста, то ВНУТРИ ВМ DHCP работает (его обслуживает NAT), но
#      guest -> 10.0.2.2 и guest -> 8.8.8.8 не ходят, и установка падает на
#      скачивании answerfile с ошибкой "Operation timed out". При сборке через
#      ИИ-ассистента этому соответствует dangerouslyDisableSandbox = true.
#
#  КЛЮЧЕВЫЕ ГРАБЛИ (все проверены на практике):
#    * Пути только ASCII. VBoxManage не переваривает кириллицу в путях —
#      ISO и рабочий каталог кладём в %TEMP%\tokb_build.
#    * Консоль БЕЗ автологина: в live-ISO надо набрать `root` (пароль пустой).
#    * keyboardputstring + сразу Enter теряет Enter — нужна пауза ~2 с.
#    * На УСТАНОВЛЕННОЙ системе scancode CR (1c) не отправляет строку;
#      работает Ctrl-J = 1d 24 9d a4 (LF). Используем его везде.
#    * setup-alpine запускается с ключом -f http://.../answerfile: он сам
#      поднимет DHCP и СКАЧАЕТ answerfile по URL.
#    * setup-disk спросит «Erase the above disk(s)?» — вопрос подавляется
#      `export ERASE_DISKS=/dev/sda` (см. answerfile).
#    * ISO нельзя «вынуть» на ходу (SATA hot-plug не поддерживается, а boot1=dvd):
#      перед перезагрузкой ВМ надо ПОГАСИТЬ, отцепить ISO, и только потом стартовать.
#    * HTTP-сервер раздаёт КОРЕНЬ проекта, поэтому answerfile лежит по адресу
#      http://10.0.2.2:8008/build/answerfile (а не /answerfile).
# ===========================================================================
set -euo pipefail

# --- Параметры -------------------------------------------------------------
VM="${VM:-alpine-tokb-build}"          # имя временной ВМ
OUT="${OUT:-$HOME/alpine-tokb.ova}"    # куда положить готовый OVA
PORT="${PORT:-8008}"
MEM="${MEM:-1024}"
DISK_MB="${DISK_MB:-8192}"
ALPINE_BRANCH="v3.24"                  # ветка зеркала (в URL — с буквой «v»!)
ISO_URL="https://dl-cdn.alpinelinux.org/alpine/${ALPINE_BRANCH}/releases/x86_64/alpine-virt-3.24.2-x86_64.iso"
ISO_SHA256="3ab424762af704b2c2a9e57df1dc37f982af260071504d977f2fb96822e7130b"

# --- Пути ------------------------------------------------------------------
PROJ="$(cd "$(dirname "$0")/.." && pwd)"     # корень проекта (там, где build/)
WORK="${WORK:-$LOCALAPPDATA/Temp/tokb_build}" # ASCII-каталог для ISO и скриншотов
ISO="$WORK/alpine-virt.iso"

# VBoxManage: путь по умолчанию под Windows
VBM="${VBM:-/c/Program Files/Oracle/VirtualBox/VBoxManage.exe}"

mkdir -p "$WORK"
log() { printf '\n=== %s ===\n' "$*"; }

# --- Вспомогательные функции консоли ---------------------------------------
# Ввод строки в консоль ВМ. ВАЖНО: пауза перед «Ctrl-J», иначе перевод строки
# теряется и команда остаётся висеть невыполненной.
guest_type() {
    "$VBM" controlvm "$VM" keyboardputstring "$1"
    sleep 2
    "$VBM" controlvm "$VM" keyboardputscancode 1d 24 9d a4   # Ctrl-J = LF
}

# Скриншот консоли — читать глазами (в этой сборке управление шло по ним).
guest_shot() { "$VBM" controlvm "$VM" screenshotpng "$WORK/shot_$(date +%H%M%S).png"; }

guest_wait() { sleep "${1:-10}"; }

# ===========================================================================
log "1. Скачивание ISO"
if [ ! -f "$ISO" ]; then
    curl -fL -o "$ISO" "$ISO_URL"
fi
# Сверка контрольной суммы — ОБЯЗАТЕЛЬНА: ISO скачивается из интернета.
echo "Ожидаемый sha256: $ISO_SHA256"
echo "Фактический sha256: $(sha256sum "$ISO" | cut -d' ' -f1)"
echo "Проверьте совпадение вручную (или заполните ISO_SHA256 в начале скрипта)."

# ===========================================================================
log "2. HTTP-сервер для раздачи файлов проекта"
# Сервер отдаёт корень проекта, поэтому внутри ВМ пути выглядят как
# http://10.0.2.2:8008/build/<файл>. ВЫНЕСТИ ИЗ ПЕСОЧНИЦЫ, иначе guest не увидит хост.
( cd "$PROJ" && python -m http.server "$PORT" --bind 0.0.0.0 >/tmp/tokb_http.log 2>&1 ) &
HTTP_PID=$!
trap 'kill $HTTP_PID 2>/dev/null || true' EXIT
sleep 2
curl -sf "http://127.0.0.1:$PORT/build/answerfile" >/dev/null && echo "HTTP-сервер отвечает" \
    || { echo "HTTP-сервер НЕ отвечает — прерываю"; exit 1; }

# ===========================================================================
log "3. Создание временной ВМ"
"$VBM" unregistervm "$VM" --delete 2>/dev/null || true
"$VBM" createvm --name "$VM" --ostype Linux26_64 --register
"$VBM" modifyvm "$VM" \
    --memory "$MEM" --cpus 2 --ioapic on --rtcuseutc on \
    --nic1 nat --nictype1 virtio \
    --boot1 dvd --boot2 disk --boot3 none --boot4 none
"$VBM" createmedium disk --filename "$WORK/$VM.vdi" --size "$DISK_MB" --format VDI
"$VBM" storagectl "$VM" --name SATA --add sata --controller IntelAhci --portcount 2
"$VBM" storageattach "$VM" --storagectl SATA --port 0 --device 0 \
    --type hdd --medium "$WORK/$VM.vdi"
"$VBM" storageattach "$VM" --storagectl SATA --port 1 --device 0 \
    --type dvddrive --medium "$ISO"

# ===========================================================================
log "4. Установка с ISO (headless + управление консолью)"
"$VBM" startvm "$VM" --type headless
guest_wait 20
guest_shot                                   # должен быть виден загрузчик/логин live-ISO
guest_type "root"                            # live-ISO: логин root, пароль ПУСТОЙ
guest_wait 3
# Сеть live-ISO иногда поднята не сразу — поднимаем интерфейс явно:
guest_type "ip link set eth0 up; udhcpc -i eth0"
guest_wait 5
guest_shot                                   # убедиться, что DHCP выдал 10.0.2.15

# Неинтерактивная установка. -e = пустой пароль root (зададим позже),
# -f URL = setup-alpine сам скачает answerfile и выполнит его как shell-скрипт.
guest_type "setup-alpine -e -f http://10.0.2.2:8008/build/answerfile"
guest_wait 240                               # установка на диск занимает несколько минут
guest_shot                                   # ожидаем строку об успешной установке

# Перезагрузка: сначала ГАСИМ, потом отцепляем ISO (иначе гостевой ISO на загрузке).
guest_type "poweroff"
guest_wait 15
"$VBM" storageattach "$VM" --storagectl SATA --port 1 --device 0 --type dvddrive --medium none

# ===========================================================================
log "5. Первый запуск установленной системы и провижн"
"$VBM" startvm "$VM" --type headless
guest_wait 25
guest_type "root"                            # пароль пустой (install был с -e)
guest_wait 3
# Дотягиваем образ: пароли, репозитории, пакеты, sudo, материалы ЛР,
# конвертация конфига Snort 2.9 -> 3 (Lua) и самопроверка.
guest_type "wget -qO /tmp/p.sh http://10.0.2.2:8008/build/provision.sh && sh /tmp/p.sh > /tmp/prov.log 2>&1; echo RC=\$?; tail -30 /tmp/prov.log"
guest_wait 180
guest_shot
# В конце лога должно быть:
#   [OK  ] LAB SCAN  (sid 1000001)
#   [OK  ] LAB DOS   (sid 1000002)
#   [OK  ] ARP-спуфинг (инспектор)
#   ИТОГ: ПРОВЕРКИ ПРОЙДЕНЫ — правила работают на сформированном трафике

# ===========================================================================
log "6. Чистка гостя перед экспортом"
guest_type "rm -f /tmp/p.sh /tmp/prov.log /tmp/v.py /tmp/ap.py /tmp/e.txt /tmp/tbind.lua /tmp/tokb_*.pcap /tmp/tokb_arp_probe.pcap /etc/snort/*.rej /etc/snort/*.orig; rm -rf /root/.ash_history /home/student/.ash_history; sync"
guest_wait 5
guest_type "poweroff"
guest_wait 15

# ===========================================================================
log "7. Экспорт OVA"
"$VBM" export "$VM" --output "$OUT" --ovf20
ls -lh "$OUT"
echo
echo "Готово. Ожидаемый размер OVA — порядка 110 МБ (сжатый VDI занимает ~1-2 ГБ)."
echo "Проверка: $VBM import '$OUT' --vsys 0 --vmname test-import"
