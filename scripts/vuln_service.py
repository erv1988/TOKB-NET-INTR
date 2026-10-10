#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
vuln_service.py — учебный TCP-сервис («защищаемый хост»).

Зачем он нужен: чтобы у хоста-жертвы был РЕАЛЬНЫЙ открытый порт,
на который можно нападать и который есть за что защищать.
Сервис намеренно «слабый»:
  * маленькая очередь listen(5) — эффект SYN-флуда виден сразу;
  * любой может подключиться без аутентификации;
  * сервис раскрывает свою версию (banner) — утечка информации.

Запуск на ВМ-жертве (Alpine Linux):
    python3 vuln_service.py 8080
Остановка: Ctrl+C
"""

import datetime
import socket
import sys
import threading

HOST = "0.0.0.0"          # слушаем все интерфейсы
BACKLOG = 5               # маленькая очередь ожидающих соединений (специально)


def ts() -> str:
    return datetime.datetime.now().strftime("%H:%M:%S")


def handle(conn: socket.socket, addr) -> None:
    """Обслужить одного клиента."""
    print(f"[{ts()}] CONNECT  {addr[0]}:{addr[1]}", flush=True)
    try:
        conn.settimeout(5)
        conn.sendall(b"LAB-SERVICE 1.0 (vulnerable demo)\r\n")
        while True:
            data = conn.recv(1024)
            if not data:
                break
            conn.sendall(b"echo: " + data)
    except Exception as exc:                       # таймаут, обрыв и т.п.
        print(f"[{ts()}] ERROR    {addr[0]}: {exc}", flush=True)
    finally:
        conn.close()
        print(f"[{ts()}] CLOSE    {addr[0]}:{addr[1]}", flush=True)


def main() -> None:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, port))
    srv.listen(BACKLOG)
    print(f"[{ts()}] LISTEN   {HOST}:{port}  (backlog={BACKLOG})", flush=True)

    while True:
        conn, addr = srv.accept()
        threading.Thread(target=handle, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[stopped]")
