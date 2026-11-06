"""Chạy lá chắn không cần giao diện:  python -m web_shield.cli --listen 8080 --upstream 127.0.0.1:8000"""
from __future__ import annotations
import argparse, sys, time
from .config import ShieldConfig
from .proxy import ShieldServer

def run(argv=None):
    ap = argparse.ArgumentParser(prog="web_shield")
    ap.add_argument("--listen", type=int, default=8080, help="cổng lá chắn")
    ap.add_argument("--upstream", default="127.0.0.1:8000", help="web thật host:port")
    a = ap.parse_args(argv)
    host, _, port = a.upstream.partition(":")
    cfg = ShieldConfig(listen_port=a.listen, upstream_host=host or "127.0.0.1",
                       upstream_port=int(port or 8000))
    def show(ev):
        if not ev.verdict.allowed:
            print(f"⛔ CHẶN {ev.ip} {ev.method} {ev.path}  [{ev.verdict.category}] {ev.verdict.reason}")
    srv = ShieldServer(cfg, on_event=show)
    print(f"[web_shield] nghe :{cfg.listen_port} -> {cfg.upstream_host}:{cfg.upstream_port} (Ctrl+C dừng)")
    srv.start_background()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        srv.stop()
    return 0

if __name__ == "__main__":
    sys.exit(run())
