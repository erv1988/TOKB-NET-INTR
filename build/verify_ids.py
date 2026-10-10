#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
verify_ids.py — ПРОВЕРКА правил обнаружения Snort БЕЗ сети.

Что делает: собирает scapy-пакетами три «атаки» в один pcap и подаёт его
Snort'у в оффлайн-режиме (-r). В сеть ничего не отправляется, права root
не нужны (кроме самого snort, которому нужен доступ к конфигу).

Ожидаемый результат в конце: три строки [OK] и «ИТОГ: ПРОВЕРКИ ПРОЙДЕНЫ».

ВАЖНО (Snort 3): проверка ARP-спуфинга опирается на ВСТРОЕННОЕ правило 112:4
инспектора arp_spoof. Эти правила загружаются только если в конфиге стоит
    ips.enable_builtin_rules = true
(по умолчанию false, и тогда инспектор молчит, хотя привязан и работает).
В собранном образе эта строка уже дописана в /etc/snort/lab.lua файлом
build/provision.sh — отдельно настраивать ничего не нужно.

Запуск на защищаемой ВМ:
    python3 verify_ids.py
"""
import os
import subprocess
import sys

from scapy.all import ARP, Ether, IP, TCP, wrpcap

CFG = os.environ.get("SNORT_CFG", "/etc/snort/lab.lua")
VICTIM = "192.168.56.10"
ATTACKER = "192.168.56.20"
SCANNER = "192.168.56.30"
GATEWAY = "192.168.56.1"
GATEWAY_MAC = "00:11:22:33:44:55"   # «настоящий» MAC шлюза — как в конфиге arp_spoof
VICTIM_MAC = "08:00:27:11:22:33"    # MAC жертвы (в проверке — условный)
SPOOF_MAC = "08:00:27:aa:bb:cc"     # поддельный MAC, которым атакующий «крадёт» шлюз
T0 = 1_700_000_000.0          # время первого пакета в pcap (фиксированное!)


def syn(src, dst, dport, when, sport=40000):
    pkt = Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="S")
    pkt.time = when
    return pkt


def arp_reply(src_mac, claimed_ip, when, dst_mac):
    """ARP-ответ «claimed_ip принадлежит src_mac».

    ВАЖНО: ответ должен быть ОДНОАДРЕСНЫМ (Ether.dst = MAC жертвы,
    ARP.hwdst = он же) — именно так работает реальное отравление ARP-кэша
    и именно на такое инспектор arp_spoof выдаёт правило 112:4
    «attempted ARP cache overwrite attack». Широковещательный ответ без
    ARP.hwdst инспектор игнорирует, и проверка даёт ложный «ПРОПУСК».
    Собирается 1:1 как в scripts/arp_spoof.py (лабораторная атака).
    """
    pkt = Ether(src=src_mac, dst=dst_mac) / ARP(
        op=2, hwsrc=src_mac, psrc=claimed_ip, hwdst=dst_mac, pdst=VICTIM)
    pkt.time = when
    return pkt


def main():
    pkts = []
    # 1) сканирование: 40 чистых SYN на разные порты за ~1,2 с (порог правила 30/2с)
    for i in range(40):
        pkts.append(syn(SCANNER, VICTIM, 1 + i, T0 + i * 0.03, sport=41000 + i))
    # 2) SYN-флуд: 120 SYN на порт сервиса за ~1 с (порог правила 100/2с)
    for i in range(120):
        pkts.append(syn(ATTACKER, VICTIM, 8080, T0 + 10 + i * 0.008))
    # 3) ARP-спуфинг: сначала честный ответ шлюза (его настоящий MAC из конфига),
    #    затем подмена — «тот же IP, но чужой MAC». Оба пакета одноадресные:
    #    инспектор arp_spoof реагирует именно на попытку перезаписи кэша жертвы.
    pkts.append(arp_reply(GATEWAY_MAC, GATEWAY, T0 + 20, VICTIM_MAC))
    pkts.append(arp_reply(SPOOF_MAC,   GATEWAY, T0 + 21, VICTIM_MAC))

    pcap = "/tmp/tokb_ids_test.pcap"
    wrpcap(pcap, pkts)
    print(f"[*] pcap: {pcap} — {len(pkts)} пакетов (40 скан / 120 флуд / 2 ARP)")

    print(f"[*] 1) проверка конфига: snort -c {CFG} -T")
    r = subprocess.run(["snort", "-c", CFG, "-T"],
                       capture_output=True, text=True)
    cfg_text = (r.stdout or "") + (r.stderr or "")
    cfg_ok = r.returncode == 0
    print(f"    код возврата = {r.returncode}")
    for line in cfg_text.splitlines()[-3:]:
        print("    |", line.strip()[:100])

    print(f"[*] 2) прогон по pcap: snort -c {CFG} -r {pcap} -A alert_fast -q")
    r = subprocess.run(["snort", "-c", CFG, "-r", pcap,
                        "-A", "alert_fast", "-q"],
                       capture_output=True, text=True)
    alerts = (r.stdout or "") + (r.stderr or "")
    alert_lines = [ln for ln in alerts.splitlines() if ln.strip()]
    print(f"    код возврата = {r.returncode}, строк вывода = {len(alert_lines)}")
    for line in alert_lines[:6]:
        print("    |", line.strip()[:110])

    # --- ИТОГИ: ищем признаки срабатывания наших правил ---
    low = alerts.lower()
    checks = [
        ("LAB SCAN  (sid 1000001)", "1000001" in alerts),
        ("LAB DOS   (sid 1000002)", "1000002" in alerts),
        # Инспектор arp_spoof выдаёт алерты с gid 112 (112:4 — перезапись ARP-кэша).
        # На всякий случай принимаем и текстовые признаки (arp/poison в разных сборках).
        ("ARP-спуфинг (инспектор)",
         "112:" in alerts or ("arp" in low and ("spoof" in low or "poison" in low))),
    ]
    print()
    bad = 0
    for name, ok in checks:
        print(f"[{'OK  ' if ok else 'ПРОПУСК'}] {name}")
        bad += 0 if ok else 1
    if bad:
        print(f"ИТОГ: не подтверждено проверок: {bad}")
        print("     (разберитесь, какое правило не сработало, и почему)")
        return 1
    print("ИТОГ: ПРОВЕРКИ ПРОЙДЕНЫ — правила работают на сформированном трафике")
    return 0


if __name__ == "__main__":
    sys.exit(main())
