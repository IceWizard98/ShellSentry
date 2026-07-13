#!/usr/bin/env python3
"""Playground alert sink: read the admin NDJSON alert socket and append each
alert to /tmp/alerts.log so you can watch rule-deny / novelty / *-otp events."""
import os
import socket
import sys

PATH = sys.argv[1] if len(sys.argv) > 1 else "/app/data/alerts.sock"
try:
    os.unlink(PATH)
except FileNotFoundError:
    pass
srv = socket.socket(socket.AF_UNIX)
srv.bind(PATH)
srv.listen()
with open("/tmp/alerts.log", "a", buffering=1) as log:
    while True:
        conn, _ = srv.accept()
        try:
            line = conn.makefile().readline()
            if line:
                log.write(line if line.endswith("\n") else line + "\n")
        finally:
            conn.close()
