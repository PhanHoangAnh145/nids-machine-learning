"""
Gửi lưu lượng THẬT sang máy đích để demo end-to-end.

Hai cách:
  * send_scapy()  : dựng gói từ PacketMeta rồi bắn bằng Scapy (cần quyền quản
                    trị). Dùng cho synflood/synscan/pingflood — các kịch bản
                    cần kiểm soát cờ TCP ở mức thô.
  * connect_scan()/send_normal() : dùng socket thường (không cần quyền quản trị),
                    thực hiện kết nối TCP thật -> hệ điều hành tự bắt tay.

Chỉ dùng trong phòng lab, trên máy của nhóm. KHÔNG quét/flood mạng của người khác.
"""
from __future__ import annotations

import socket
import time
from typing import Sequence

from realtime.packet import PacketMeta


def _to_scapy(m: PacketMeta):
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    ip = IP(src=m.src_ip, dst=m.dst_ip)
    if m.proto == "tcp":
        flags = "".join(ch for ch, on in (
            ("S", "S" in m.tcp_flags), ("A", "A" in m.tcp_flags),
            ("F", "F" in m.tcp_flags), ("R", "R" in m.tcp_flags),
            ("P", "P" in m.tcp_flags), ("U", "U" in m.tcp_flags)) if on)
        return ip / TCP(sport=m.sport or 1234, dport=m.dport or 80, flags=flags) / (b"\x00" * m.length)
    if m.proto == "udp":
        return ip / UDP(sport=m.sport or 1234, dport=m.dport or 53) / (b"\x00" * m.length)
    if m.proto == "icmp":
        return ip / ICMP() / (b"\x00" * m.length)
    return ip


def send_scapy(packets: Sequence[PacketMeta], iface: str = None,
               respect_timing: bool = False, inter: float = 0.0) -> int:
    """Bắn danh sách gói bằng Scapy. Trả về số gói đã gửi."""
    from scapy.sendrecv import send
    sent = 0
    t0 = packets[0].ts if packets else 0.0
    wall0 = time.time()
    for m in packets:
        if respect_timing:
            target = wall0 + (m.ts - t0)
            now = time.time()
            if target > now:
                time.sleep(target - now)
        send(_to_scapy(m), iface=iface, verbose=False)
        sent += 1
        if inter:
            time.sleep(inter)
    return sent


def connect_scan(target: str, ports=range(1, 1025), timeout: float = 0.3) -> dict:
    """Quét cổng kiểu connect bằng socket thường (không cần quyền quản trị)."""
    open_ports = []
    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            if s.connect_ex((target, port)) == 0:
                open_ports.append(port)
        except OSError:
            pass
        finally:
            s.close()
    return {"target": target, "open_ports": open_ports}


def send_normal(target: str, port: int = 80, rounds: int = 10, timeout: float = 1.0) -> int:
    """Tạo vài kết nối TCP bình thường (vd tới cổng web) để đo báo động giả."""
    ok = 0
    for _ in range(rounds):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            if s.connect_ex((target, port)) == 0:
                try:
                    s.sendall(b"GET / HTTP/1.0\r\n\r\n")
                    s.recv(256)
                except OSError:
                    pass
                ok += 1
        finally:
            s.close()
        time.sleep(0.2)
    return ok
