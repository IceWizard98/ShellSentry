"""Shell Sentry inference daemon.

A long-lived TCP server (one thread per connection) that answers the ssentry
runtime's per-command scoring requests over the fixed NDJSON contract:
  request:  {"user","session_id","features":{...}}\n
  response: {"score": float}\n
It maps user -> <root>/<user>/model.pkl via a TTL model cache and returns the
raw Isolation Forest score. No model -> a high (normal) score. A corrupt model
or malformed request -> the connection is closed with no reply, so the Go client
fail-opens."""
import argparse
import json
import os
import socketserver
import sys
import threading

import yaml

from model_cache import ModelCache

# Column order MUST match training (core.BuildMatrix) and the runtime feature.
FEATURE_ORDER = ["time_cos", "time_sin", "geo_id",
                 "cmd_index", "path_index", "secs_since_last"]

# Cap a single request line so a client cannot make us buffer unbounded memory
# by sending bytes without a newline (symmetric with the Go client's 1 MiB
# response cap in adapters/scorerclient).
MAX_REQUEST_BYTES = 1 << 20


def load_config(path):
    with open(path) as f:
        cfg = yaml.safe_load(f) or {}
    addr = str(cfg.get("daemon_addr", "127.0.0.1:9099"))
    host, sep, port = addr.rpartition(":")
    if not sep or not port.isdigit():
        raise ValueError(f"daemon_addr must be host:port, got {addr!r}")
    p = int(port)
    if not (1 <= p <= 65535):  # reject 0 (silently ephemeral) and out-of-range
        raise ValueError(f"daemon_addr port must be 1-65535, got {p}")
    return {
        "host": host or "127.0.0.1",
        "port": p,
        "root": cfg.get("root_path", "./data"),
        "ttl": int(cfg.get("model_ttl_sec", 900)),
    }


def process(cache, req):
    feats = req["features"]
    vec = [float(feats[k]) for k in FEATURE_ORDER]  # KeyError if a field is missing
    return {"score": cache.score(req["user"], vec)}


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        while True:
            # Bounded read: readline(N+1) returns at most N+1 bytes, so an
            # unterminated flood is rejected instead of buffered unbounded.
            raw = self.rfile.readline(MAX_REQUEST_BYTES + 1)
            if not raw:
                return  # EOF
            if len(raw) > MAX_REQUEST_BYTES:
                sys.stderr.write("daemon: request line too large; closing\n")
                sys.stderr.flush()
                return
            line = raw.strip()
            if not line:
                continue
            try:
                resp = process(self.server.cache, json.loads(line))
                # allow_nan=False: a NaN/Inf score would serialize as invalid
                # JSON; instead raise -> close (the Go client fail-opens) rather
                # than send a garbage reply it cannot parse.
                payload = json.dumps(resp, allow_nan=False) + "\n"
            except Exception as e:  # bad json / missing field / bad score
                sys.stderr.write(f"daemon: request error: {e}\n")
                sys.stderr.flush()
                return  # close connection with no reply -> Go fail-opens
            self.wfile.write(payload.encode())
            self.wfile.flush()


class _Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def serve(cfg, cache=None):
    cache = cache or ModelCache(cfg["root"], cfg["ttl"])
    srv = _Server((cfg["host"], cfg["port"]), Handler)
    srv.cache = cache
    stop = threading.Event()

    def sweep():
        interval = max(1, cfg["ttl"] // 2)
        while not stop.wait(interval):
            cache.evict_idle()

    threading.Thread(target=sweep, daemon=True).start()
    return srv, stop


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default=os.getenv("SSENTRY_CONFIG", "config.yaml"))
    cfg = load_config(ap.parse_args().config)
    srv, stop = serve(cfg)
    sys.stderr.write(
        f"daemon: listening on {cfg['host']}:{cfg['port']} models={cfg['root']}\n")
    sys.stderr.flush()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        stop.set()  # stop the TTL sweeper
        srv.shutdown()


if __name__ == "__main__":
    main()
