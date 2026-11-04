"""
PacketMeta: thông tin tối giản mà FlowTracker cần từ mỗi gói tin.

Đây là ranh giới cô lập Scapy: mọi lớp phía sau chỉ làm việc với PacketMeta,
nên toàn bộ logic gom luồng / tính đặc trưng kiểm thử được mà KHÔNG cần Scapy.
Chỉ hàm from_scapy() (dùng khi bắt gói trực tiếp) mới chạm tới Scapy.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import FrozenSet, Optional

# Các cờ TCP quan tâm
SYN = "S"
ACK = "A"
FIN = "F"
RST = "R"
PSH = "P"
URG = "U"


@dataclass(frozen=True)
class PacketMeta:
    """Một gói tin đã rút gọn về các trường cần cho NSL-KDD."""
    ts: float                      # thời điểm bắt gói (giây, epoch)
    proto: str                     # 'tcp' | 'udp' | 'icmp' | 'other'
    src_ip: str
    dst_ip: str
    sport: int = 0                 # 0 với ICMP/other
    dport: int = 0
    length: int = 0                # số byte PAYLOAD lớp 4 (không gồm header)
    tcp_flags: FrozenSet[str] = field(default_factory=frozenset)
    icmp_type: int = 8             # 8=echo request (eco_i), 0=echo reply (ecr_i)

    # ---- tiện ích cờ TCP ---------------------------------------------
    @property
    def is_syn(self) -> bool:
        return SYN in self.tcp_flags

    @property
    def is_synack(self) -> bool:
        return SYN in self.tcp_flags and ACK in self.tcp_flags

    @property
    def is_pure_syn(self) -> bool:
        return SYN in self.tcp_flags and ACK not in self.tcp_flags

    @property
    def is_fin(self) -> bool:
        return FIN in self.tcp_flags

    @property
    def is_rst(self) -> bool:
        return RST in self.tcp_flags

    @property
    def is_urg(self) -> bool:
        return URG in self.tcp_flags


def _flags_from_int(bits: int) -> FrozenSet[str]:
    """Chuyển trường flags TCP (byte) thành tập ký hiệu."""
    out = set()
    if bits & 0x02:
        out.add(SYN)
    if bits & 0x10:
        out.add(ACK)
    if bits & 0x01:
        out.add(FIN)
    if bits & 0x04:
        out.add(RST)
    if bits & 0x08:
        out.add(PSH)
    if bits & 0x20:
        out.add(URG)
    return frozenset(out)


def from_scapy(pkt, ts: Optional[float] = None) -> Optional[PacketMeta]:
    """
    Chuyển một gói Scapy thành PacketMeta. Trả về None nếu không phải IPv4
    TCP/UDP/ICMP (ví dụ ARP, IPv6 — ngoài phạm vi NSL-KDD).

    CHỈ hàm này phụ thuộc Scapy; import nằm trong thân hàm để phần còn lại của
    module nạp được ngay cả khi máy chưa cài Scapy.
    """
    from scapy.layers.inet import IP, TCP, UDP, ICMP  # noqa: WPS433 (local import cố ý)

    if IP not in pkt:
        return None
    ip = pkt[IP]
    t = float(ts if ts is not None else getattr(pkt, "time", 0.0))

    if TCP in pkt:
        l4 = pkt[TCP]
        payload = len(l4.payload)
        return PacketMeta(
            ts=t, proto="tcp", src_ip=ip.src, dst_ip=ip.dst,
            sport=int(l4.sport), dport=int(l4.dport),
            length=payload, tcp_flags=_flags_from_int(int(l4.flags)),
        )
    if UDP in pkt:
        l4 = pkt[UDP]
        payload = max(len(l4.payload), int(l4.len) - 8)
        return PacketMeta(
            ts=t, proto="udp", src_ip=ip.src, dst_ip=ip.dst,
            sport=int(l4.sport), dport=int(l4.dport), length=payload,
        )
    if ICMP in pkt:
        return PacketMeta(
            ts=t, proto="icmp", src_ip=ip.src, dst_ip=ip.dst,
            sport=0, dport=0, length=len(pkt[ICMP].payload),
            icmp_type=int(pkt[ICMP].type),
        )
    return PacketMeta(ts=t, proto="other", src_ip=ip.src, dst_ip=ip.dst)
