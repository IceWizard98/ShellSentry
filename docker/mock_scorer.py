#!/usr/bin/env python3
"""Mock Python inference daemon: NDJSON over TCP, always returns a normal score
(high = normal for Isolation Forest), so ONLY the admin rules gate in these
tests, never the model."""
import socket, json, sys

addr = ("127.0.0.1", 19099)
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(addr)
s.listen()
sys.stderr.write("mock_scorer listening on %s:%d\n" % addr)
sys.stderr.flush()
while True:
    c, _ = s.accept()
    try:
        f = c.makefile("rw")
        f.readline()  # request line (ignored)
        f.write(json.dumps({"score": 1.0}) + "\n")
        f.flush()
    except Exception:
        pass
    finally:
        c.close()
