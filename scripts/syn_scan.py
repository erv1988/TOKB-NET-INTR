#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
syn_scan.py — простейший SYN-сканер (полуоткрытое сканирование) на scapy.

Идея: послать TCP-пакет с флагом SYN и посмотреть на ответ.
    SYN  -> SYN+ACK : порт ОТКРЫТ (полное соединение НЕ устанавливаем,
                      сразу отправляем RST — отсюда «полуоткрытое»)
    SYN  -> RST     : порт ЗАКРЫТ
    SYN  -> тишина  : порт ФИЛЬТРУЕТСЯ (пакет съел межсетевой экран)
                                             ^^^ это и есть «отпечаток» МЭ

Требуются права root (Linux) / администратора + Npcap (Windows).

Запуск (атакующая ВМ Alpine Linux):
    sudo python3 syn_scan.py 192.168.56.10 22,80,443,8080
    sudo python3 syn_scan.py 192.168.56.10 1-1024
"""

import random
import sys
import time

from scapy.all import IP, TCP, conf, send, sr1

conf.verb = 0                      # не засорять вывод отладкой scapy

SYN, ACK, RST = 0x02, 0x10, 0x04    # биты флагов TCP


def parse_ports(spec: str) -> list:
    """'22,80,443' или '1-1024' -> список портов."""
    ports = []
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            lo, hi = part.split("-", 1)
            ports.extend(range(int(lo), int(hi) + 1))
        elif part:
            ports.append(int(part))
    return ports


def syn_scan(target: str, ports: list, timeout: float = 1.0) -> dict:
    result = {}
    for port in ports:
        sport = random.randint(1024, 65535)
        seq = random.randint(0, 2 ** 32 - 1)
        probe = IP(dst=target) / TCP(sport=sport, dport=port, flags="S", seq=seq)

        answer = sr1(probe, timeout=timeout, verbose=0)

        if answer is None:
            result[port] = "filtered"                 # ответа нет — режет МЭ
        elif answer.haslayer(TCP):
            flags = int(answer[TCP].flags)
            if (flags & SYN) and (flags & ACK):
                result[port] = "open"                 # SYN+ACK
                # вежливо рвём полуоткрытое соединение
                send(IP(dst=target) / TCP(sport=sport, dport=port,
                                          flags="R", seq=int(answer[TCP].ack)),
                     verbose=0)
            elif flags & RST:
                result[port] = "closed"               # RST
            else:
                result[port] = f"unexpected(0x{flags:02x})"
        else:
            result[port] = "unexpected(no-tcp)"
    return result


def main() -> None:
    if len(sys.argv) < 3:
        sys.exit(f"Использование: sudo {sys.argv[0]} <ip> <порты, напр. 22,80,1-1024>")

    target = sys.argv[1]
    ports = parse_ports(sys.argv[2])
    print(f"[*] SYN-скан {target}, портов: {len(ports)}")
    print(f"{'ПОРТ':>6}  СОСТОЯНИЕ")

    t0 = time.time()
    result = syn_scan(target, ports)
    for port, state in result.items():
        print(f"{port:>6}  {state}")
    print(f"[*] Готово за {time.time() - t0:.1f} c")

    counts = {}
    for state in result.values():
        counts[state] = counts.get(state, 0) + 1
    print(f"[*] Итог: {counts}")

    # сохраняем «сырой» результат в отчёт
    with open("syn_scan_result.txt", "w", encoding="utf-8") as fh:
        fh.write(f"# SYN-скан {target}, {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        for port, state in result.items():
            fh.write(f"{port}\t{state}\n")
    print("[*] Результат сохранён в syn_scan_result.txt")


if __name__ == "__main__":
    main()
