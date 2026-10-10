#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
arp_probe.py — ДИАГНОСТИКА инспектора arp_spoof (Snort 3).

Собирает в один pcap все варианты ARP-трафика и показывает, на какие из них
инспектор arp_spoof реагирует (правила gid 112). Нужен, чтобы понять, какой
именно пакет требуется в проверке: одноадресный запрос, честный ответ,
подмена MAC и т.п.

Запуск на ВМ:
    SNORT_CFG=/etc/snort/lab.lua python3 arp_probe.py
"""
import os
import subprocess
import sys

from scapy.all import ARP, Ether, wrpcap

CFG = os.environ.get("SNORT_CFG", "/etc/snort/lab.lua")
GATEWAY = "192.168.56.1"
GATEWAY_MAC = "00:11:22:33:44:55"      # настоящий MAC шлюза (как в конфиге)
VICTIM = "192.168.56.10"
VICTIM_MAC = "08:00:27:11:22:33"
SPOOF_MAC = "08:00:27:aa:bb:cc"
ATTACKER = "192.168.56.20"
T0 = 1_700_000_000.0


def arp_req(src_mac, dst_mac, asker_ip, target_ip, when, label):
    """ARP-ЗАПРОС (op=1). dst_mac = ff:ff:... — широковещательный,
    иначе одноадресный (правило 112:1 «unicast ARP request»)."""
    pkt = Ether(src=src_mac, dst=dst_mac) / ARP(
        op=1, hwsrc=src_mac, psrc=asker_ip, hwdst="00:00:00:00:00:00", pdst=target_ip)
    pkt.time = when
    return pkt, label


def arp_rep(src_mac, dst_mac, owner_ip, victim_ip, when, label):
    """ARP-ОТВЕТ (op=2): «owner_ip — это src_mac».
    hwdst проставляем как dst_mac (для одноадресного — MAC получателя)."""
    pkt = Ether(src=src_mac, dst=dst_mac) / ARP(
        op=2, hwsrc=src_mac, psrc=owner_ip, hwdst=dst_mac, pdst=victim_ip)
    pkt.time = when
    return pkt, label


def main():
    BC = "ff:ff:ff:ff:ff:ff"
    seq = [
        arp_req(VICTIM_MAC, BC, VICTIM, GATEWAY, T0 + 0.0,
                "P1 broadcast запрос: кто такой шлюз"),
        arp_req(VICTIM_MAC, GATEWAY_MAC, VICTIM, GATEWAY, T0 + 1.0,
                "P2 ОДНОАДРЕСНЫЙ запрос -> ожидаем 112:1"),
        arp_rep(GATEWAY_MAC, VICTIM_MAC, GATEWAY, VICTIM, T0 + 2.0,
                "P3 честный одноадресный ответ шлюза"),
        arp_rep(SPOOF_MAC, VICTIM_MAC, GATEWAY, VICTIM, T0 + 3.0,
                "P4 ПОДМЕНА: чужой MAC выдаёт себя за шлюз -> 112:4?"),
        arp_rep(GATEWAY_MAC, BC, GATEWAY, VICTIM, T0 + 4.0,
                "P5 честный ШИРОКОВЕЩАТЕЛЬНЫЙ ответ шлюза"),
        arp_rep(SPOOF_MAC, BC, GATEWAY, VICTIM, T0 + 5.0,
                "P6 ПОДМЕНА широковещательным ответом -> 112:4?"),
        arp_rep(SPOOF_MAC, VICTIM_MAC, ATTACKER, VICTIM, T0 + 6.0,
                "P7 подмена своего адреса (не шлюза)"),
    ]
    pkts = [p for p, _ in seq]
    labels = [lab for _, lab in seq]

    pcap = "/tmp/tokb_arp_probe.pcap"
    wrpcap(pcap, pkts)
    print(f"[*] pcap: {pcap} — {len(pkts)} пакетов")

    print(f"[*] snort -c {CFG} -r {pcap} -A alert_fast   (полный вывод)")
    r = subprocess.run(["snort", "-c", CFG, "-r", pcap, "-A", "alert_fast", "-q"],
                       capture_output=True, text=True)
    out = (r.stdout or "") + (r.stderr or "")
    lines = [ln for ln in out.splitlines() if ln.strip()]
    print(f"    код возврата = {r.returncode}, строк вывода = {len(lines)}")
    for ln in lines:
        print("    |", ln.strip()[:130])

    print()
    print("=== Разбор: какой пакет дал срабатывание ===")
    for lab in labels:
        print(f"    {lab}")
    print()
    if "112:" in out:
        print("[ИТОГ] инспектор arp_spoof СРАБОТАЛ (есть алерты gid 112)")
    else:
        print("[ИТОГ] ни одного алерта 112 — инспектор молчит на всём наборе")
    return 0


if __name__ == "__main__":
    sys.exit(main())
