"""
Dòng lệnh cho traffic_generator.

Offline (ghi .pcap để kiểm thử / minh họa, KHÔNG cần mạng, KHÔNG cần Scapy):
    python -m traffic_generator --scenario synflood --pcap syn.pcap
    python -m traffic_generator --scenario all --outdir pcaps

Live (gửi gói thật sang máy đích, dùng khi demo 2 máy):
    python -m traffic_generator --scenario synflood --target 192.168.1.5 --send
    python -m traffic_generator --scenario connectscan --target 192.168.1.5 --send
"""
from __future__ import annotations

import argparse
import os
import sys

from realtime import pcap_io
from .scenarios import SCENARIOS, build_scenario


def run(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="traffic_generator",
                                 description="Sinh lưu lượng theo kịch bản cho NIDS SHIELD")
    ap.add_argument("--scenario", default="synflood",
                    choices=sorted(SCENARIOS) + ["all"], help="kịch bản lưu lượng")
    ap.add_argument("--target", default="10.0.0.1", help="IP máy đích")
    ap.add_argument("--attacker", default="10.0.0.9", help="IP máy nguồn (offline)")
    ap.add_argument("--count", type=int, default=400, help="số gói/cổng tùy kịch bản")
    ap.add_argument("--pcap", help="ghi ra 1 file .pcap (chế độ offline)")
    ap.add_argument("--outdir", help="ghi mỗi kịch bản 1 file .pcap vào thư mục này")
    ap.add_argument("--send", action="store_true", help="GỬI THẬT sang --target (cần Scapy/quyền)")
    ap.add_argument("--iface", help="card mạng để gửi (chế độ --send)")
    args = ap.parse_args(argv)

    names = sorted(SCENARIOS) if args.scenario == "all" else [args.scenario]

    if args.send:
        return _do_send(names[0], args)

    if args.outdir:
        os.makedirs(args.outdir, exist_ok=True)
        for name in names:
            pkts = build_scenario(name, atk=args.attacker, tgt=args.target, count=args.count)
            path = os.path.join(args.outdir, f"{name}.pcap")
            pcap_io.write_pcap(path, pkts)
            print(f"[+] {name:12s} -> {path}  ({len(pkts)} gói)")
        return 0

    pkts = build_scenario(names[0], atk=args.attacker, tgt=args.target, count=args.count)
    out = args.pcap or f"{names[0]}.pcap"
    pcap_io.write_pcap(out, pkts)
    print(f"[+] Đã ghi {len(pkts)} gói kịch bản '{names[0]}' -> {out}")
    return 0


def _do_send(name: str, args) -> int:
    from . import sender
    try:
        if name in ("connectscan",):
            res = sender.connect_scan(args.target, ports=range(1, args.count + 1))
            print(f"[+] Quét connect {args.target}: cổng mở = {res['open_ports']}")
            return 0
        if name == "normal":
            n = sender.send_normal(args.target)
            print(f"[+] Đã tạo {n} kết nối bình thường tới {args.target}")
            return 0
        pkts = build_scenario(name, atk=_local_ip(), tgt=args.target, count=args.count)
        n = sender.send_scapy(pkts, iface=args.iface)
        print(f"[+] Đã gửi {n} gói kịch bản '{name}' tới {args.target}")
        return 0
    except Exception as exc:                        # noqa: BLE001
        print(f"[!] Gửi thất bại: {exc}")
        print("    synflood/synscan/pingflood cần Scapy + quyền quản trị (Npcap/root).")
        print("    Có thể dùng --scenario connectscan (socket thường) để không cần quyền.")
        return 1


def _local_ip() -> str:
    import socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return "10.0.0.9"


if __name__ == "__main__":
    sys.exit(run())
