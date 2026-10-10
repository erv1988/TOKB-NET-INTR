#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_scripts.py — ПРОВЕРКА КОРРЕКТНОСТИ скриптов лабораторной работы.

Что делает: собирает объекты пакетов scapy и подаёт их прямо в детектор
мини-IDS, проверяет формируемые правила iptables (через подмену subprocess.run).
ПАКЕТЫ В СЕТЬ НЕ ОТПРАВЛЯЮТСЯ, права root НЕ НУЖНЫ — тест безопасен.

Этот файл удобно использовать на занятии как образец «как проверять сетевой
код, не ломая сеть»: внешние эффекты (отправка пакетов, вызов iptables)
подменяются заглушками, а логика проверяется по факту.

Запуск из корня комплекта:
    python -m venv venv && ./venv/bin/pip install scapy   # (Windows: venv\\Scripts\\pip)
    python tests/test_scripts.py
Ожидаемый результат: "ВСЕ ПРОВЕРКИ ПРОЙДЕНЫ" и код возврата 0.
"""

import importlib.util
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPTS_DIR = os.path.join(os.path.dirname(HERE), "scripts")

try:
    from scapy.all import ARP, Ether, IP, TCP
except ImportError:
    sys.exit("Нужен scapy: pip install scapy (в Alpine: apk add scapy)")

failures = []


def check(name, cond, extra=""):
    print(f"[{'OK  ' if cond else 'FAIL'}] {name} {extra}")
    if not cond:
        failures.append(name)


def load(module_name):
    """Загрузить скрипт из папки scripts/ по имени файла."""
    path = os.path.join(SCRIPTS_DIR, module_name + ".py")
    spec = importlib.util.spec_from_file_location(module_name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def syn(src, dst="192.168.56.10", dport=8080):
    return Ether() / IP(src=src, dst=dst) / TCP(sport=40000, dport=dport, flags="S")


def arp_reply(ip, mac):
    return Ether(src=mac) / ARP(op=2, psrc=ip, hwsrc=mac, pdst="192.168.56.10")


# ============================================================ syn_scan.py ====
syn_scan = load("syn_scan")
check("syn_scan: parse_ports список", syn_scan.parse_ports("22,80,443") == [22, 80, 443])
check("syn_scan: parse_ports диапазон", syn_scan.parse_ports("1-4") == [1, 2, 3, 4])
check("syn_scan: parse_ports смешанный", syn_scan.parse_ports("22,100-102") == [22, 100, 101, 102])

probe = IP(dst="192.168.56.10") / TCP(sport=40000, dport=8080, flags="S", seq=100)
check("syn_scan: пробник — это чистый SYN",
      int(probe[TCP].flags) & 0x02 and not int(probe[TCP].flags) & 0x10)
check("syn_scan: классификация SYN+ACK -> open",
      (int(TCP(flags="SA").flags) & 0x02) and (int(TCP(flags="SA").flags) & 0x10))
check("syn_scan: классификация RST -> closed", bool(int(TCP(flags="R").flags) & 0x04))

# =========================================================== syn_flood.py ====
syn_flood = load("syn_flood")
real = syn_flood.build_packets("192.168.56.10", 8080, 5, spoof=False)
spoofed = syn_flood.build_packets("192.168.56.10", 8080, 5, spoof=True)
check("syn_flood: собрано 5 + 5 пакетов", len(real) == 5 and len(spoofed) == 5)
check("syn_flood: спуфинг даёт адреса 10.99.x.x", spoofed[0][IP].src.startswith("10.99."))
check("syn_flood: все пакеты — SYN на нужную цель",
      all(int(p[TCP].flags) == 0x02 and p[IP].dst == "192.168.56.10" for p in spoofed))

# режим --duration: должен остановиться сам по времени, а не по счётчику
batches = []
syn_flood.send = lambda pkts, **kw: batches.append(len(pkts))   # заглушка: в сеть не шлём
sys.argv = ["syn_flood.py", "192.168.56.10", "8080", "--spoof", "--duration", "0.6"]
t0 = time.time()
syn_flood.main()
elapsed = time.time() - t0
check("syn_flood: --duration остановился по времени", 0.5 <= elapsed <= 2.0, f"({elapsed:.2f} c)")
check("syn_flood: отправка идёт пачками BATCH",
      batches and all(n == syn_flood.BATCH for n in batches), f"({batches[:3]}...)")

# режим по счётчику: ровно count пакетов, без перерасхода
batches.clear()
sys.argv = ["syn_flood.py", "192.168.56.10", "8080", "120"]
syn_flood.main()
check("syn_flood: по счётчику отправлено ровно 120", sum(batches) == 120, f"({sum(batches)})")

# =========================================================== arp_spoof.py ====
arp_spoof = load("arp_spoof")
poison = arp_spoof.arp_reply("eth0", "08:00:27:00:00:02", "192.168.56.10",
                             "192.168.56.1", "08:00:27:AA:BB:CC")
check("arp_spoof: это ARP-reply (op=2)", poison[ARP].op == 2)
check("arp_spoof: подменяется адрес шлюза", poison[ARP].psrc == "192.168.56.1")
check("arp_spoof: MAC атакующего в hwsrc", poison[ARP].hwsrc == "08:00:27:AA:BB:CC")
check("arp_spoof: кадр адресован жертве", poison[Ether].dst == "08:00:27:00:00:02")

# getmacbyip() в scapy 2.8 НЕ принимает iface — проверяем, что скрипт зовёт её верно
mac_calls = []
arp_spoof.getmacbyip = lambda *a, **kw: mac_calls.append((a, kw)) or "08:00:27:00:00:09"
check("arp_spoof: resolve_mac возвращает MAC",
      arp_spoof.resolve_mac("192.168.56.1", "eth0") == "08:00:27:00:00:09")
check("arp_spoof: getmacbyip вызвана без параметра iface",
      mac_calls and mac_calls[0][1] == {}, f"({mac_calls})")

# ============================================================ mini_ids.py ====
mini_ids = load("mini_ids")
log_lines = []
det = mini_ids.Detector(syn_threshold=20, syn_window=5.0, block=False, log_func=log_lines.append)

for _ in range(19):
    det.process(syn("192.168.56.20"))
check("mini_ids: 19 SYN — алертов нет", len(log_lines) == 0, f"({log_lines})")

alerts = det.process(syn("192.168.56.20"))
check("mini_ids: 20-й SYN -> алерт", len(alerts) == 1)
check("mini_ids: тип алерта syn_flood", alerts and alerts[0]["type"] == "syn_flood")
check("mini_ids: в алерте верный источник", alerts and alerts[0]["src"] == "192.168.56.20")

marker = len(log_lines)
for _ in range(50):
    det.process(Ether() / IP(src="192.168.56.30", dst="192.168.56.10") /
                TCP(sport=80, dport=40000, flags="SA"))
check("mini_ids: SYN+ACK не считается атакой", len(log_lines) == marker)

marker = len(log_lines)
det2 = mini_ids.Detector(syn_threshold=5, syn_window=5.0, block=False, log_func=log_lines.append)
for host in range(1, 5):
    for _ in range(4):
        det2.process(syn(f"192.168.56.{host}"))
check("mini_ids: 4 хоста по 4 SYN (порог 5) — тишина", len(log_lines) == marker)

det3 = mini_ids.Detector(syn_threshold=5, syn_window=0.5, block=False, log_func=lambda m: None)
for _ in range(4):
    det3.process(syn("192.168.56.77"))
time.sleep(0.6)
check("mini_ids: старые SYN выпадают из окна",
      det3.process(syn("192.168.56.77")) == [])

det4 = mini_ids.Detector(block=False, log_func=lambda m: None)
check("mini_ids: первый ARP-reply — тишина",
      det4.process(arp_reply("192.168.56.1", "aa:aa:aa:aa:aa:aa")) == [])
check("mini_ids: повтор того же MAC — тишина",
      det4.process(arp_reply("192.168.56.1", "aa:aa:aa:aa:aa:aa")) == [])
spoof_alert = det4.process(arp_reply("192.168.56.1", "bb:bb:bb:bb:bb:bb"))
check("mini_ids: смена MAC -> алерт ARP_SPOOF",
      len(spoof_alert) == 1 and spoof_alert[0]["type"] == "arp_spoof")
check("mini_ids: ARP-запрос (op=1) игнорируется",
      det4.process(Ether() / ARP(op=1, psrc="192.168.56.1",
                                 hwsrc="cc:cc:cc:cc:cc:cc")) == [])

# блокировка: проверяем ФОРМИРУЕМЫЕ команды, не выполняя их
import subprocess
calls = []
real_run = subprocess.run
subprocess.run = lambda *a, **kw: calls.append(a[0]) or type("R", (), {"returncode": 0})()
det5 = mini_ids.Detector(block=True, log_func=lambda m: None)
det5.block_ip("192.168.56.20", "syn_flood")
det5.cleanup()
subprocess.run = real_run
check("mini_ids: блокировка = iptables -I INPUT -s IP -j DROP",
      calls and calls[0] == ["iptables", "-I", "INPUT", "-s", "192.168.56.20", "-j", "DROP"],
      f"({calls})")
check("mini_ids: снятие правила по Ctrl+C (через -D)",
      len(calls) == 2 and calls[1][1] == "-D")

# ================================================================= ИТОГ =====
print()
if failures:
    print(f"ПРОВАЛЕНО: {len(failures)} -> {failures}")
    sys.exit(1)
print("ВСЕ ПРОВЕРКИ ПРОЙДЕНЫ")
