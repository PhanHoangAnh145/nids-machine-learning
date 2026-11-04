"""
Các KỊCH BẢN sinh lưu lượng, trả về danh sách realtime.packet.PacketMeta đã sắp
theo thời gian. Dùng để ghi .pcap (offline) hoặc làm khuôn cho sender (live).

Mỗi gói mô phỏng đúng những gì FlowTracker cần: chiều, cờ TCP, số byte payload.
Mốc thời gian (ts) tăng dần để tái hiện mật độ gói thật.
"""
from __future__ import annotations

import random
from typing import Callable, Dict, List

from realtime.packet import PacketMeta

SYN = frozenset({"S"})
SYNACK = frozenset({"S", "A"})
ACK = frozenset({"A"})
PSHACK = frozenset({"P", "A"})
FINACK = frozenset({"F", "A"})
RSTACK = frozenset({"R", "A"})


def _tcp(ts, src, dst, sport, dport, flags, length=0):
    return PacketMeta(ts=ts, proto="tcp", src_ip=src, dst_ip=dst,
                      sport=sport, dport=dport, length=length, tcp_flags=flags)


def _handshake_session(ts, atk, tgt, sport, dport, req=200, resp=1500, gap=0.001):
    """Một phiên TCP hoàn chỉnh: SYN/SYN-ACK/ACK + dữ liệu + đóng FIN -> cờ SF."""
    p = []
    p.append(_tcp(ts, atk, tgt, sport, dport, SYN))
    p.append(_tcp(ts + gap, tgt, atk, dport, sport, SYNACK))
    p.append(_tcp(ts + 2 * gap, atk, tgt, sport, dport, ACK))
    p.append(_tcp(ts + 3 * gap, atk, tgt, sport, dport, PSHACK, length=req))
    p.append(_tcp(ts + 4 * gap, tgt, atk, dport, sport, PSHACK, length=resp))
    p.append(_tcp(ts + 5 * gap, atk, tgt, sport, dport, FINACK))
    p.append(_tcp(ts + 6 * gap, tgt, atk, dport, sport, FINACK))
    p.append(_tcp(ts + 7 * gap, atk, tgt, sport, dport, ACK))
    return p


# ============================================================= KỊCH BẢN TẤN CÔNG
def synflood(atk="10.0.0.9", tgt="10.0.0.1", dport=80, count=400,
             rate=2000.0, start=0.0, **_) -> List[PacketMeta]:
    """SYN flood: rất nhiều SYN tới 1 cổng, KHÔNG có hồi đáp -> cờ S0 (DoS)."""
    out = []
    dt = 1.0 / rate
    for i in range(count):
        out.append(_tcp(start + i * dt, atk, tgt, 1024 + (i % 40000), dport, SYN))
    return out


def synscan(atk="10.0.0.9", tgt="10.0.0.1", count=300, start=0.0,
            open_ports=(80, 22, 443), **_) -> List[PacketMeta]:
    """Quét SYN (nmap -sS): SYN tới nhiều cổng; cổng đóng -> RST (REJ)."""
    out = []
    dt = 0.002
    ports = list(range(1, count + 1))
    for i, port in enumerate(ports):
        ts = start + i * dt
        sport = 40000 + i
        out.append(_tcp(ts, atk, tgt, sport, port, SYN))
        if port in open_ports:
            out.append(_tcp(ts + 0.0005, tgt, atk, port, sport, SYNACK))
            out.append(_tcp(ts + 0.001, atk, tgt, sport, port, RSTACK))   # nmap reset
        else:
            out.append(_tcp(ts + 0.0005, tgt, atk, port, sport, RSTACK))  # cổng đóng -> REJ
    return out


def connectscan(atk="10.0.0.9", tgt="10.0.0.1", count=200, start=0.0,
                open_ports=(80, 22), **_) -> List[PacketMeta]:
    """Quét kiểu connect (nmap -sT): bắt tay đủ với cổng mở rồi đóng."""
    out = []
    dt = 0.003
    for i, port in enumerate(range(1, count + 1)):
        ts = start + i * dt
        sport = 50000 + i
        if port in open_ports:
            out.extend(_handshake_session(ts, atk, tgt, sport, port, req=0, resp=0))
        else:
            out.append(_tcp(ts, atk, tgt, sport, port, SYN))
            out.append(_tcp(ts + 0.0005, tgt, atk, port, sport, RSTACK))
    return sorted(out, key=lambda p: p.ts)


def pingflood(atk="10.0.0.9", tgt="10.0.0.1", count=400, rate=2000.0,
              start=0.0, **_) -> List[PacketMeta]:
    """Ping flood trực tiếp: ICMP echo REQUEST dồn dập (service eco_i).

    Lưu ý: KDD coi đây gần với ipsweep/normal hơn là tấn công, vì tấn công
    'smurf' kinh điển là echo REPLY (xem kịch bản 'smurf').
    """
    out = []
    dt = 1.0 / rate
    for i in range(count):
        out.append(PacketMeta(ts=start + i * dt, proto="icmp",
                              src_ip=atk, dst_ip=tgt, length=56, icmp_type=8))
    return out


def smurf(atk="10.0.0.9", tgt="10.0.0.1", count=400, rate=2000.0,
          start=0.0, **_) -> List[PacketMeta]:
    """Smurf: nạn nhân bị dội ICMP echo REPLY dồn dập (service ecr_i) -> DoS."""
    out = []
    dt = 1.0 / rate
    for i in range(count):
        out.append(PacketMeta(ts=start + i * dt, proto="icmp",
                              src_ip=atk, dst_ip=tgt, length=1032, icmp_type=0))
    return out


# ================================================================ LƯU LƯỢNG SẠCH
def normal(atk="10.0.0.50", tgt="10.0.0.1", count=60, start=0.0, seed=42, **_) -> List[PacketMeta]:
    """Duyệt web/dns bình thường: các phiên SF rải rác -> dùng đo báo động giả."""
    rng = random.Random(seed)
    services = [(80, "http"), (443, "https"), (53, "dns"), (25, "smtp")]
    out = []
    ts = start
    for i in range(count):
        dport, kind = rng.choice(services)
        sport = 1024 + rng.randint(0, 50000)
        ts += rng.uniform(0.05, 0.4)
        if kind == "dns":
            out.append(PacketMeta(ts=ts, proto="udp", src_ip=tgt, dst_ip="8.8.8.8",
                                  sport=sport, dport=53, length=40))
            out.append(PacketMeta(ts=ts + 0.01, proto="udp", src_ip="8.8.8.8", dst_ip=tgt,
                                  sport=53, dport=sport, length=120))
        else:
            out.extend(_handshake_session(ts, tgt, "93.184.216.34", sport, dport,
                                          req=rng.randint(100, 500),
                                          resp=rng.randint(500, 4000)))
    return sorted(out, key=lambda p: p.ts)


SCENARIOS: Dict[str, Callable[..., List[PacketMeta]]] = {
    "synflood": synflood,
    "synscan": synscan,
    "connectscan": connectscan,
    "pingflood": pingflood,
    "smurf": smurf,
    "normal": normal,
}


def build_scenario(name: str, **kwargs) -> List[PacketMeta]:
    if name not in SCENARIOS:
        raise KeyError(f"Chưa có kịch bản '{name}'. Có: {sorted(SCENARIOS)}")
    return SCENARIOS[name](**kwargs)
