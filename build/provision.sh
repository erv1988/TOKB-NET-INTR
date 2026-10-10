#!/bin/sh
# ===========================================================================
#  provision.sh — доводка учебной ВМ Alpine Linux после установки с ISO.
#
#  Запускается ОДИН РАЗ на свежеустановленной системе, от root, при наличии
#  интернета (VirtualBox NAT). Внутри сборки OVA это делает build_ova.sh:
#      wget -qO /tmp/p.sh http://10.0.2.2:8008/build/provision.sh && sh /tmp/p.sh
#  (ВНИМАНИЕ: путь именно /build/provision.sh — HTTP-сервер раздаёт корень проекта,
#   а сам скрипт лежит в подкаталоге build/.)
#
#  Что делает:
#    1) задаёт пароли (учебный стенд в изолированной сети!)
#    2) правит /etc/apk/repositories под формат apk-tools 3.x
#    3) ставит пакеты, нужные всем этапам лабораторной
#    4) включает sudo для группы wheel (чтобы команды методички с sudo работали)
#    5) раскладывает материалы лабораторной (/etc/snort, /opt/tokb)
#    6) конвертирует конфиг Snort 2.9 -> Snort 3 (Lua) и проверяет его
# ===========================================================================
set -e

BASE_URL="http://10.0.2.2:8008"   # 10.0.2.2 — «хост» в NAT VirtualBox

echo "==> 1/6 Пароли (в изолированной сети; пароли намеренно простые)"
echo "root:alpine"     | chpasswd
echo "student:student" | chpasswd

echo "==> 2/6 Репозитории apk"
# ВАЖНО — два независимых требования, проверенных на Alpine 3.24 (apk-tools 3.0.8):
#
# 1) ФОРМА ЗАПИСИ. apk 3 понимает репозитории как «базовый URL + СПИСОК
#    КОМПОНЕНТОВ ОДНОЙ СТРОКОЙ»:
#        https://<зеркало>/alpine/3.24 main community
#    Легаси-формат «по одному URL на строку» (как его пишет setup-apkrepos)
#    этот apk выполняет ЛИШЬ ЧАСТИЧНО: берёт первый репозиторий (main) и молча
#    игнорирует остальные. Внешне всё выглядит исправно — «OK: 5961 distinct
#    packages available», — но community не подключён, и `apk add sudo scapy`
#    падает с: ERROR: unable to select packages: sudo (no such package).
#    Пакеты sudo и scapy лежат именно в community.
#
# 2) СХЕМА HTTPS, А НЕ HTTP. По http:// (порт 80) HTTP-клиент apk 3.0.8 получает
#    от CDN «HTTP 404» на APKINDEX.tar.gz, тогда как по https:// тот же файл
#    скачивается нормально. (busybox wget по http:// тот же URL берёт с кодом 200,
#    т.е. дело именно в клиенте apk, а не в CDN.) Поэтому — только https://.
#
#    Префикс v3 к URL ставить НЕ надо: индекс Packages.adb на CDN отдаёт 404,
#    тип по умолчанию (v2, файл APKINDEX.tar.gz) — правильный.
ALPINE_VER=$(cut -d. -f1,2 /etc/alpine-release)     # 3.24.2 -> 3.24
# ВНИМАНИЕ: в пути зеркала ветка пишется как v3.24 — с буквой «v»
# (https://.../alpine/v3.24/...). С «3.24» без «v» будет настоящий 404.
printf '%s\n' "https://dl-cdn.alpinelinux.org/alpine/v${ALPINE_VER} main community" \
    > /etc/apk/repositories
cat /etc/apk/repositories
apk update

echo "==> 3/6 Пакеты"
apk add --no-progress --quiet \
    sudo nmap tcpdump scapy iproute2 iptables python3 \
    snort curl arpwatch conntrack-tools bash
# примечание: пакета snort в Alpine — это Snort 3 (проверка: snort -V)
apk info -v | grep -E '^(snort|scapy|nmap|iptables)-' | sort

echo "==> 4/6 sudo для группы wheel"
if grep -q '^%wheel' /etc/sudoers; then
    echo "    уже настроено"
else
    echo '%wheel ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers
fi

echo "==> 5/6 Материалы лабораторной"
mkdir -p /etc/snort/rules /opt/tokb
wget -qO /etc/snort/lab.conf        "$BASE_URL/configs/snort_lab.conf"
wget -qO /etc/snort/rules/lab.rules "$BASE_URL/configs/lab.rules"
# скрипты лабораторной (те же, что в комплекте)
for f in vuln_service.py banner_grab.py syn_scan.py syn_flood.py arp_spoof.py mini_ids.py; do
    wget -qO "/opt/tokb/$f" "$BASE_URL/scripts/$f" || echo "    ПРОПУЩЕН: $f"
done
chmod +x /opt/tokb/*.py 2>/dev/null || true
# межсетевой экран лабораторной (этап 4) — кладём РЯДОМ со скриптами,
# чтобы на ВМ все материалы лежали в одном каталоге /opt/tokb
wget -qO /opt/tokb/firewall_lab.sh "$BASE_URL/configs/firewall_lab.sh" \
    && chmod +x /opt/tokb/firewall_lab.sh \
    || echo "    ПРОПУЩЕН: firewall_lab.sh"
# проверка правил Snort без сети (собирает pcap scapy и прогоняет его через
# snort -r) — нужна и сборке, и преподавателю перед занятием
wget -qO /opt/tokb/verify_ids.py "$BASE_URL/build/verify_ids.py" \
    && chmod +x /opt/tokb/verify_ids.py \
    || echo "    ПРОПУЩЕН: verify_ids.py"
ls -l /opt/tokb

echo "==> 6/6 Snort: конфиг 2.9 -> 3 (Lua) и проверка"
snort2lua -c /etc/snort/lab.conf -o /etc/snort/lab.lua
# snort2lua пишет в начало lab.lua поиск snort_defaults.lua относительно ТЕКУЩЕГО
# каталога (dir = '.'), поэтому 'snort -c /etc/snort/lab.lua' из любого другого
# каталога падает с "cannot open ./snort_defaults.lua". Подставляем абсолютный путь.
# (Альтернатива — каждый раз задавать SNORT_LUA_PATH=/etc/snort; для студентов
#  правка файла удобнее: команда 'snort -c /etc/snort/lab.lua' работает всегда.)
sed -i "s|dir = '.'|dir = '/etc/snort'|" /etc/snort/lab.lua

# ВСТРОЕННЫЕ ПРАВИЛА — без этой строки НЕ РАБОТАЕТ обнаружение ARP-спуфинга.
# В Snort 3 алерты инспекторов (arp_spoof -> gid 112, port_scan -> gid 129,
# stream -> gid 116 и т.д.) оформлены как «встроенные правила» (builtin rules,
# их список — snort --list-builtin). По умолчанию ips.enable_builtin_rules =
# false, при этом инспектор САМ РАБОТАЕТ и события порождает, но правил, к
# которым их можно «привязать», нет — и в выводе не появляется НИ ОДНОГО
# алерта. Ключа командной строки для этого параметра не существует, только
# ips.enable_builtin_rules в конфиге (проверено на Snort 3.9.2.0, Alpine 3.24:
# инспектор arp_spoof корректно привязан и в snort --help-module виден, но
# молчит до включения этого флага).
# Строка дописывается В КОНЕЦ lab.lua: таблица ips там уже создана, поэтому
# присваивание поля её не затирает (важно — иначе потерялись бы ips.rules,
# то есть наши /etc/snort/rules/lab.rules).
cat >> /etc/snort/lab.lua <<'LUATOP'

-- =====================================================================
--  ВСТРОЕННЫЕ ПРАВИЛА (добавлено provision.sh, не трогать без нужды)
--  Без этой строки не будет алертов инспекторов: arp_spoof (gid 112),
--  port_scan (gid 129) и др. Инспекторы работают, но их события ни во что
--  не превращаются. Ключа командной строки у этого параметра нет.
-- =====================================================================
ips.enable_builtin_rules = true
LUATOP
echo "    проверка: $(grep -c 'enable_builtin_rules' /etc/snort/lab.lua) строка(и) с enable_builtin_rules"

echo "    --- фрагмент /etc/snort/lab.lua ---"
head -30 /etc/snort/lab.lua
echo "    ----------------------------------"
snort -c /etc/snort/lab.lua -T 2>&1 | tail -3

echo "==> Самопроверка образа"
snort -V 2>&1 | head -2
python3 -c "import scapy; print('scapy', scapy.__version__)"
iptables -V
if [ -f /opt/tokb/verify_ids.py ]; then
    SNORT_CFG=/etc/snort/lab.lua python3 /opt/tokb/verify_ids.py \
        || echo "    ВНИМАНИЕ: правила Snort не подтвердились — смотрите вывод выше"
fi

echo "ГОТОВО: provision.sh завершён"
