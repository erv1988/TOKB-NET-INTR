#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
banner_grab.py — «ручная разведка» открытого порта (мини-аналог nmap -sV).

Показывает главную мысль этапа «уязвимость хоста»:
открытый порт — это не только доступ, но и УТЕЧКА ИНФОРМАЦИИ
(имя и версия сервиса позволяют подобрать известную уязвимость).

Запуск с атакующей ВМ (Alpine):
    python3 banner_grab.py 192.168.56.10 8080
"""

import socket
import sys

TIMEOUT = 3.0


def grab_banner(host: str, port: int) -> str:
    """Подключиться и прочитать то, что сервис сам расскажет о себе."""
    with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
        sock.settimeout(TIMEOUT)
        try:
            data = sock.recv(512)
        except socket.timeout:
            return "<сервис не прислал баннер>"
    return data.decode(errors="replace").strip()


def main() -> None:
    if len(sys.argv) < 3:
        sys.exit(f"Использование: {sys.argv[0]} <ip> <port>")

    host, port = sys.argv[1], int(sys.argv[2])
    print(f"[*] Подключаемся к {host}:{port} ...")
    try:
        banner = grab_banner(host, port)
    except Exception as exc:
        print(f"[-] Порт закрыт/недоступен: {exc}")
        return

    print(f"[+] Баннер: {banner}")
    print("[i] Если сервис сообщает имя и версию — это уже разведка:")
    print("    по версии ищутся известные уязвимости (CVE).")


if __name__ == "__main__":
    main()
