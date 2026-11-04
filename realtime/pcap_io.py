"""
Đọc/ghi file .pcap (libpcap classic) bằng thuần Python — KHÔNG cần Scapy.

Mục đích:
  * Cho phép "phát lại" (replay) một bản ghi lưu lượng để phân tích offline.
  * Làm nền cho kiểm thử tự động: traffic_generator sinh .pcap -> realtime đọc
    lại -> chạy qua đúng pipeline (gom luồng + mô hình) mà không phụ thuộc mạng.

Hỗ trợ IPv4 + TCP/UDP/ICMP, link-layer Ethernet (DLT=1) và Raw-IP (DLT=101).
Đủ dùng cho các kịch bản của đề tài; không nhằm thay thế thư viện pcap đầy đủ.
"""
from __future__ import annotations

import struct
from typing import Iterator, List, Sequence

from .packet import PacketMeta, _flags_from_int

_PCAP_MAGIC = 0xA1B2C3D4
_PCAP_MAGIC_SWAPPED = 0xD4C3B2A1
_DLT_EN10MB = 1
_DLT_RAW = 101
_ETH_HDR = 14
_ETHERTYPE_IP = 0x0800


# ====================================================================== WRITE
def _eth_ipv4_header() -> bytes:
    # MAC đích/nguồn giả + ethertype IPv4
    return b"\x02\x00\x00\x00\x00\x02" + b"\x02\x00\x00\x00\x00\x01" + struct.pack(">H", _ETHERTYPE_IP)


def _ip_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack(f">{len(data)//2}H", data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return (~s) & 0xFFFF


def _ip_to_bytes(ip: str) -> bytes:
    return bytes(int(x) & 0xFF for x in ip.split("."))


def build_packet_bytes(m: PacketMeta) -> bytes:
    """Dựng khung Ethernet/IPv4/(TCP|UDP|ICMP) từ một PacketMeta."""
    if m.proto == "tcp":
        flags = 0
        for bit, ch in ((0x02, "S"), (0x10, "A"), (0x01, "F"), (0x04, "R"), (0x08, "P"), (0x20, "U")):
            if ch in m.tcp_flags:
                flags |= bit
        payload = b"\x00" * m.length
        l4 = struct.pack(">HHIIBBHHH", m.sport, m.dport, 0, 0, (5 << 4), flags, 8192, 0, 0) + payload
        proto_num = 6
    elif m.proto == "udp":
        payload = b"\x00" * m.length
        l4 = struct.pack(">HHHH", m.sport, m.dport, 8 + len(payload), 0) + payload
        proto_num = 17
    elif m.proto == "icmp":
        payload = b"\x00" * m.length
        l4 = struct.pack(">BBHHH", m.icmp_type, 0, 0, 0, 0) + payload
        proto_num = 1
    else:
        l4 = b""
        proto_num = 255

    total = 20 + len(l4)
    ip_hdr = struct.pack(
        ">BBHHHBBH4s4s", 0x45, 0, total, 0, 0, 64, proto_num, 0,
        _ip_to_bytes(m.src_ip), _ip_to_bytes(m.dst_ip),
    )
    chk = _ip_checksum(ip_hdr)
    ip_hdr = ip_hdr[:10] + struct.pack(">H", chk) + ip_hdr[12:]
    return _eth_ipv4_header() + ip_hdr + l4


def write_pcap(path: str, packets: Sequence[PacketMeta]) -> None:
    """Ghi danh sách PacketMeta ra file .pcap (link Ethernet)."""
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", _PCAP_MAGIC, 2, 4, 0, 0, 65535, _DLT_EN10MB))
        for m in packets:
            raw = build_packet_bytes(m)
            sec = int(m.ts)
            usec = int(round((m.ts - sec) * 1_000_000))
            f.write(struct.pack("<IIII", sec, usec, len(raw), len(raw)))
            f.write(raw)


# ======================================================================= READ
def _parse_ip_frame(buf: bytes, ts: float) -> PacketMeta | None:
    if len(buf) < 20 or (buf[0] >> 4) != 4:
        return None
    ihl = (buf[0] & 0x0F) * 4
    proto_num = buf[9]
    src = ".".join(str(b) for b in buf[12:16])
    dst = ".".join(str(b) for b in buf[16:20])
    l4 = buf[ihl:]

    if proto_num == 6 and len(l4) >= 20:          # TCP
        sport, dport = struct.unpack(">HH", l4[0:4])
        data_off = (l4[12] >> 4) * 4
        flags = l4[13]
        payload = max(0, len(l4) - data_off)
        return PacketMeta(ts=ts, proto="tcp", src_ip=src, dst_ip=dst,
                          sport=sport, dport=dport, length=payload,
                          tcp_flags=_flags_from_int(flags))
    if proto_num == 17 and len(l4) >= 8:          # UDP
        sport, dport, ulen = struct.unpack(">HHH", l4[0:6])
        return PacketMeta(ts=ts, proto="udp", src_ip=src, dst_ip=dst,
                          sport=sport, dport=dport, length=max(0, ulen - 8))
    if proto_num == 1:                            # ICMP
        itype = l4[0] if l4 else 8
        return PacketMeta(ts=ts, proto="icmp", src_ip=src, dst_ip=dst,
                          length=max(0, len(l4) - 8), icmp_type=itype)
    return PacketMeta(ts=ts, proto="other", src_ip=src, dst_ip=dst)


def read_pcap(path: str) -> List[PacketMeta]:
    """Đọc file .pcap -> danh sách PacketMeta (bỏ qua gói không phải IPv4)."""
    return list(iter_pcap(path))


def iter_pcap(path: str) -> Iterator[PacketMeta]:
    with open(path, "rb") as f:
        gh = f.read(24)
        if len(gh) < 24:
            return
        magic = struct.unpack("<I", gh[0:4])[0]
        if magic == _PCAP_MAGIC:
            end = "<"
        elif magic == _PCAP_MAGIC_SWAPPED:
            end = ">"
        else:
            raise ValueError("Không phải file pcap hợp lệ (magic sai).")
        dlt = struct.unpack(f"{end}I", gh[20:24])[0]
        while True:
            ph = f.read(16)
            if len(ph) < 16:
                break
            sec, usec, caplen, _ = struct.unpack(f"{end}IIII", ph)
            data = f.read(caplen)
            if len(data) < caplen:
                break
            ts = sec + usec / 1_000_000.0
            if dlt == _DLT_EN10MB:
                if len(data) < _ETH_HDR:
                    continue
                ethertype = struct.unpack(">H", data[12:14])[0]
                if ethertype != _ETHERTYPE_IP:
                    continue
                frame = data[_ETH_HDR:]
            elif dlt == _DLT_RAW:
                frame = data
            else:
                continue
            m = _parse_ip_frame(frame, ts)
            if m is not None:
                yield m
