#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
mini_ids.py — «СОВ на 100 строк»: мини-IDS/IPS на scapy.

Показывает суть любой системы обнаружения вторжений:
    ЗАХВАТ ПАКЕТА  ->  ПРИЗНАК (правило)  ->  РЕШЕНИЕ (алерт / блокировка)
                                                         ^^^^^^^^^^^^^
                                             вот это и отличает IPS от IDS

Что умеет:
  1) SYN-флуд   — считает чистые SYN от одного источника в скользящем окне;
  2) ARP-спуфинг — следит, не сменил ли один и тот же IP свой MAC.

Режимы:
    --monitor   только логировать (IDS — «вижу, но пропускаю»)
    --block     плюс блокировать источник правилом iptables (IPS — «вижу и рублю»)

Запуск на защищаемом хосте (ВМ-жертва, Alpine Linux):
    sudo python3 mini_ids.py --iface eth0 --monitor
    sudo python3 mini_ids.py --iface eth0 --block --log-file alerts.log

ВАЖНО: блокировка по IP спасает только от атак с НАСТОЯЩИХ адресов.
Если источник поддельный (--spoof в syn_flood.py) — блокировать адрес
бессмысленно (можно забанить чужую сеть), нужны ограничение скорости
и SYN-cookies. Это разбирается на этапе 4.

ВНИМАНИЕ: при выходе по Ctrl+C скрипт удаляет добавленные им правила iptables.
"""

import argparse
import subprocess
import sys
import time
from collections import defaultdict, deque

from scapy.all import ARP, IP, TCP, sniff

SYN_BIT, ACK_BIT = 0x02, 0x10


class Detector:
    """Вся логика обнаружения — в одном классе (удобно и тестировать, и объяснять)."""

    def __init__(self, syn_threshold=20, syn_window=5.0,
                 block=False, log_func=print):
        self.syn_threshold = syn_threshold      # сколько SYN считать атакой
        self.syn_window = syn_window            # за сколько секунд
        self.block = block
        self.log = log_func
        self.syn_events = defaultdict(deque)    # src_ip -> времена SYN-пакетов
        self.arp_table = {}                     # ip     -> последний MAC
        self.blocked = set()                    # уже заблокированные адреса
        self.added_rules = []                   # правила iptables, чтобы убрать за собой

    # ---------- обработка одного пакета ----------
    def process(self, pkt):
        """Вернуть список сработавших алертов (список нужен для автотестов)."""
        alerts = []
        if pkt.haslayer(ARP):
            alerts += self._check_arp(pkt)
        elif pkt.haslayer(IP) and pkt.haslayer(TCP):
            alerts += self._check_syn(pkt)
        return alerts

    # ---------- правило 1: SYN-флуд ----------
    def _check_syn(self, pkt):
        flags = int(pkt[TCP].flags)
        is_clean_syn = bool(flags & SYN_BIT) and not (flags & ACK_BIT)
        if not is_clean_syn:
            return []                            # не «чистый» SYN — не наш случай

        src, dst, dport = pkt[IP].src, pkt[IP].dst, pkt[TCP].dport
        now = time.time()

        events = self.syn_events[src]
        events.append(now)
        while events and now - events[0] > self.syn_window:
            events.popleft()                     # выбрасываем «старые» SYN

        if len(events) < self.syn_threshold:
            return []

        count = len(events)
        events.clear()                           # не спамить алертами на каждый пакет
        self.log(f"[ALERT][SYN_FLOOD] {src} -> {dst}:{dport} : "
                 f"{count} SYN за {self.syn_window:g} c (порог {self.syn_threshold})")
        if self.block:
            self.block_ip(src, "syn_flood")
        return [{"type": "syn_flood", "src": src, "dst": dst,
                 "dport": dport, "count": count, "time": now}]

    # ---------- правило 2: ARP-спуфинг ----------
    def _check_arp(self, pkt):
        arp = pkt[ARP]
        if arp.op != 2:                          # только ARP-reply
            return []

        ip, mac = arp.psrc, arp.hwsrc
        old = self.arp_table.get(ip)

        if old is None:
            self.arp_table[ip] = mac             # первое знакомство — запоминаем
            return []
        if old.lower() == mac.lower():
            return []                            # всё честно

        self.arp_table[ip] = mac
        self.log(f"[ALERT][ARP_SPOOF] {ip} сменил MAC: {old} -> {mac} "
                 f"(Ethernet-источник {pkt.src})")
        return [{"type": "arp_spoof", "ip": ip, "old_mac": old,
                 "new_mac": mac, "time": time.time()}]

    # ---------- реакция IPS: блокировка ----------
    def block_ip(self, ip, reason):
        if ip in self.blocked:                   # уже заблокирован — не дублируем правило
            return
        rule = ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"]
        try:
            subprocess.run(rule, check=True, capture_output=True)
        except Exception as exc:
            self.log(f"[BLOCK][ERROR] {ip}: {exc} "
                     f"(нужны права root и установленный iptables)")
            return
        self.added_rules.append(rule)
        self.log(f"[BLOCK] источник {ip} заблокирован ({reason}): {' '.join(rule)}")

    def cleanup(self):
        """Убрать за собой правила iptables (правила из этой сессии)."""
        for rule in self.added_rules:
            del_rule = list(rule)
            del_rule[1] = "-D"                   # -I ... -> -D ...
            subprocess.run(del_rule, capture_output=True)
        self.log(f"[*] Удалено правил iptables: {len(self.added_rules)}")


def main() -> None:
    ap = argparse.ArgumentParser(description="Мини-IDS/IPS на scapy (учебная лаборатория)")
    ap.add_argument("--iface", required=True, help="интерфейс, например eth0")
    ap.add_argument("--monitor", action="store_true", help="режим IDS: только алерты")
    ap.add_argument("--block", action="store_true", help="режим IPS: алерты + блокировка")
    ap.add_argument("--syn-threshold", type=int, default=20,
                    help="порог SYN-пакетов для алерта (по умолчанию 20)")
    ap.add_argument("--syn-window", type=float, default=5.0,
                    help="окно наблюдения в секундах (по умолчанию 5)")
    ap.add_argument("--log-file", default=None, help="файл для журнала алертов")
    args = ap.parse_args()

    if not args.block:
        args.monitor = True

    log_file = open(args.log_file, "a", encoding="utf-8") if args.log_file else None

    def log(message):
        stamp = time.strftime("%Y-%m-%d %H:%M:%S")
        line = f"{stamp} {message}"
        print(line, flush=True)
        if log_file:
            log_file.write(line + "\n")
            log_file.flush()

    mode = "IPS (обнаружение + блокировка)" if args.block else "IDS (только обнаружение)"
    log(f"[*] Режим: {mode}")
    log(f"[*] Интерфейс: {args.iface}, порог: {args.syn_threshold} SYN / "
        f"{args.syn_window:g} c")
    log("[!] Остановка: Ctrl+C")

    detector = Detector(syn_threshold=args.syn_threshold,
                        syn_window=args.syn_window,
                        block=args.block,
                        log_func=log)
    try:
        # store=0 — не копим пакеты в памяти; фильтр BPF снижает нагрузку
        sniff(iface=args.iface, prn=detector.process, store=0, filter="tcp or arp")
    except PermissionError:
        sys.exit("[!] Нужны права root: sudo python3 mini_ids.py ...")
    except KeyboardInterrupt:
        pass
    finally:
        detector.cleanup()
        if log_file:
            log_file.close()
        print("[*] Остановлено.")


if __name__ == "__main__":
    main()
