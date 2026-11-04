"""
Giao diện dòng lệnh cho bộ giám sát thời gian thực.

    python -m realtime --replay capture.pcap      # phát lại 1 file pcap (offline)
    python -m realtime --iface "Wi-Fi"            # bắt gói trực tiếp (cần Scapy + Npcap)
    python -m realtime --list                     # liệt kê card mạng (cần Scapy)

Khi bắt trực tiếp trên Windows: cài Npcap và chạy terminal bằng quyền
Administrator. Danh sách tên card mạng xem bằng --list.
"""
from __future__ import annotations

import argparse
import sys
import threading
import time

from .config import RealtimeConfig
from .engine import Prediction, RealtimeEngine

_RESET, _RED, _GRN, _YEL = "\033[0m", "\033[91m", "\033[92m", "\033[93m"


def _fmt(pred: Prediction) -> str:
    c = pred.conn
    tag = f"{_RED}🚨 TẤN CÔNG [{pred.category.upper()}]{_RESET}" if pred.is_attack \
        else f"{_GRN}✅ AN TOÀN{_RESET}"
    return (f"{c.src}:{c.sport} -> {c.dst}:{c.dport} "
            f"[{c.proto}/{c.service}/{c.flag}] "
            f"dur={c.duration}s sb={c.src_bytes} db={c.dst_bytes} "
            f"| {tag} ({pred.confidence*100:.0f}%)")


def _print_pred(pred: Prediction) -> None:
    if pred.is_attack or pred.category == "unknown":
        print(_fmt(pred))


def run(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="realtime", description="NIDS SHIELD - giám sát thời gian thực")
    ap.add_argument("--replay", metavar="PCAP", help="phát lại 1 file .pcap (không cần Scapy)")
    ap.add_argument("--iface", metavar="IFACE", help="bắt gói trực tiếp trên card mạng này")
    ap.add_argument("--list", action="store_true", help="liệt kê card mạng rồi thoát")
    ap.add_argument("--timeout", type=float, default=2.0, help="thời gian chờ đóng flow (giây)")
    ap.add_argument("--no-model", action="store_true", help="chỉ gom luồng, không nạp model")
    ap.add_argument("--seconds", type=float, default=0, help="bắt trực tiếp trong N giây rồi dừng (0=vô hạn)")
    args = ap.parse_args(argv)

    if args.list:
        try:
            from scapy.arch import get_if_list
            print("Các card mạng:")
            for name in get_if_list():
                print("  -", name)
        except Exception as exc:                   # noqa: BLE001
            print(f"Cần Scapy để liệt kê card mạng: {exc}")
        return 0

    cfg = RealtimeConfig(flow_timeout=args.timeout)
    engine = RealtimeEngine(config=cfg, load_model=not args.no_model)

    if args.replay:
        print(f"[*] Phát lại {args.replay} ...")
        preds = engine.replay_pcap(args.replay, on_prediction=_print_pred)
        _summary(engine, preds)
        return 0

    if args.iface:
        print(f"[*] Bắt gói trên '{args.iface}' (Ctrl+C để dừng) ...")
        stop = threading.Event()
        t = None
        if args.seconds > 0:
            t = threading.Timer(args.seconds, stop.set)
            t.daemon = True
            t.start()
        try:
            engine.live_capture(iface=args.iface, on_prediction=_print_pred, stop_event=stop)
        except KeyboardInterrupt:
            stop.set()
        except Exception as exc:                   # noqa: BLE001
            print(f"[!] Lỗi bắt gói: {exc}")
            print("    Kiểm tra: đã cài Scapy + Npcap? Terminal có quyền Administrator?")
            return 1
        finally:
            if t:
                t.cancel()
        _summary(engine, None)
        return 0

    ap.print_help()
    return 0


def _summary(engine: RealtimeEngine, preds) -> None:
    s = engine.stats
    print("-" * 60)
    print(f"[=] Gói: {s['packets']} | Kết nối: {s['connections']} | "
          f"Cảnh báo tấn công: {s['attacks']}")


if __name__ == "__main__":
    sys.exit(run())
