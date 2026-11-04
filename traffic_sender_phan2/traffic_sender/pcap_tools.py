"""
Logic xử lý pcap cho Phần 2 (tách hoàn toàn khỏi UI).

Hai việc chính:
  * mutate_template(): đọc 1 pcap mẫu, LÀM MỚI (timestamp hiện tại, đổi IP
    nguồn/đích, xoá & tính lại checksum) rồi ghi ra ./output/.
  * send_pcap(): phát 1 pcap ra card mạng bằng Scapy, báo tiến độ qua callback.

Scapy được import trong thân hàm để UI vẫn mở được khi máy chưa cài Scapy
(chỉ thao tác sinh/gửi mới thực sự cần Scapy).

LƯU Ý SỬ DỤNG: đây là công cụ KIỂM THỬ NIDS trong phòng lab. Chỉ phát gói tới
máy/mạng do chính bạn sở hữu và được phép thử nghiệm.
"""
from __future__ import annotations

import ipaddress
import os
import random
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

# Ba loại lưu lượng mẫu <-> tên file trong ./templates/
TEMPLATES: Dict[str, str] = {
    "A - DoS / SYN Flood": "dos_attack.pcap",
    "B - Port Scanning": "port_scan.pcap",
    "C - Web Request (HTTP)": "web_attack.pcap",
}

PKG_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATES_DIR = os.path.join(PKG_DIR, "templates")
OUTPUT_DIR = os.path.join(PKG_DIR, "output")


@dataclass
class MutateOptions:
    """Tuỳ chọn làm mới khi sinh biến thể pcap."""
    randomize_src: bool = True             # đổi IP nguồn ngẫu nhiên
    src_ip: Optional[str] = None           # hoặc cố định IP nguồn do người dùng nhập
    dst_ip: Optional[str] = None           # đổi IP đích về giá trị này (vd IP máy chạy Phần 1)
    reset_time: bool = True                # dời timestamp về hiện tại, giữ nguyên khoảng cách
    recompute_checksum: bool = True        # xoá rồi tính lại IP/TCP/UDP checksum + độ dài


def _rand_ip() -> str:
    """Sinh IP riêng tư ngẫu nhiên trong 10.x.x.x (an toàn cho lab)."""
    return f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


def list_templates() -> Dict[str, str]:
    """Trả về {nhãn hiển thị: đường dẫn tuyệt đối} cho các mẫu đang có."""
    out = {}
    for label, fname in TEMPLATES.items():
        path = os.path.join(TEMPLATES_DIR, fname)
        if os.path.exists(path):
            out[label] = path
    return out


def mutate_template(label: str, options: MutateOptions,
                    log: Optional[Callable[[str], None]] = None) -> str:
    """
    Đọc pcap mẫu ứng với `label`, làm mới theo `options`, ghi ra ./output/.
    Trả về đường dẫn file vừa tạo.
    """
    from scapy.all import rdpcap, wrpcap, IP, TCP, UDP   # import cục bộ (cần Scapy)

    def _log(m):
        if log:
            log(m)

    fname = TEMPLATES.get(label)
    if not fname:
        raise KeyError(f"Không có mẫu cho loại '{label}'")
    src_path = os.path.join(TEMPLATES_DIR, fname)
    if not os.path.exists(src_path):
        raise FileNotFoundError(f"Thiếu file mẫu: {src_path}")

    _log(f"Đọc mẫu: {os.path.basename(src_path)}")
    packets = rdpcap(src_path)
    n = len(packets)
    _log(f"  -> {n} gói tin")

    # Giữ nguyên khoảng cách thời gian giữa các gói, chỉ dời mốc về hiện tại
    now = time.time()
    base = float(packets[0].time) if n else now

    # Một IP nguồn chung cho cả phiên (nếu randomize) để lưu lượng nhất quán
    session_src = options.src_ip or (_rand_ip() if options.randomize_src else None)

    for pkt in packets:
        if options.reset_time:
            pkt.time = now + (float(pkt.time) - base)

        if IP in pkt:
            ip = pkt[IP]
            # Đổi IP nguồn/đích, GIỮ ĐÚNG CHIỀU để phiên vẫn hợp lệ:
            #   - gói client->server: src = IP nguồn mới, dst = IP đích mới
            #   - gói server->client (phản hồi): đảo lại (src = đích, dst = nguồn)
            if _is_client_pkt(pkt):
                if session_src is not None:
                    ip.src = session_src
                if options.dst_ip:
                    ip.dst = options.dst_ip
            else:
                if options.dst_ip:
                    ip.src = options.dst_ip
                if session_src is not None:
                    ip.dst = session_src

            if options.recompute_checksum:
                # Xoá checksum + len để Scapy tự tính lại khi ghi file
                if hasattr(ip, "chksum"):
                    del ip.chksum
                if hasattr(ip, "len"):
                    del ip.len
                if TCP in pkt:
                    del pkt[TCP].chksum
                if UDP in pkt:
                    del pkt[UDP].chksum
                    if hasattr(pkt[UDP], "len"):
                        del pkt[UDP].len

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    attack_type = fname.replace(".pcap", "")
    stamp = time.strftime("%Y%m%d_%H%M%S")
    out_name = f"generated_{attack_type}_{stamp}.pcap"
    out_path = os.path.join(OUTPUT_DIR, out_name)
    wrpcap(out_path, packets)      # ghi lại -> checksum/len được tính mới
    _log(f"Đã ghi: {out_name}")
    return out_path


def _is_client_pkt(pkt) -> bool:
    """
    Xác định gói thuộc chiều 'client -> server' (để đổi địa chỉ đúng chiều).
    Quy ước: gói có cờ SYN-không-ACK, hoặc cổng đích < cổng nguồn, coi là client.
    """
    from scapy.all import TCP
    if TCP in pkt:
        f = pkt[TCP].flags
        if "S" in f and "A" not in f:
            return True
        return int(pkt[TCP].dport) <= int(pkt[TCP].sport)
    return True


def send_pcap(pcap_path: str, iface: Optional[str] = None,
              inter: float = 0.0, repeat: int = 1,
              progress: Optional[Callable[[int, int], None]] = None,
              log: Optional[Callable[[str], None]] = None,
              stop_flag: Optional[Callable[[], bool]] = None) -> int:
    """
    Phát pcap ra card mạng bằng Scapy sendp(). Trả về số gói đã gửi.
    progress(done, total) được gọi sau mỗi gói; stop_flag() -> True để dừng sớm.
    """
    from scapy.all import rdpcap, sendp

    def _log(m):
        if log:
            log(m)

    packets = rdpcap(pcap_path)
    total = len(packets) * max(1, repeat)
    _log(f"Nạp {len(packets)} gói từ {os.path.basename(pcap_path)}; sẽ gửi {total} gói.")
    sent = 0
    for _ in range(max(1, repeat)):
        for pkt in packets:
            if stop_flag and stop_flag():
                _log("Đã dừng theo yêu cầu.")
                return sent
            sendp(pkt, iface=iface, verbose=False)
            sent += 1
            if progress:
                progress(sent, total)
            if inter:
                time.sleep(inter)
    _log(f"Hoàn tất: đã gửi {sent}/{total} gói ra '{iface or 'card mặc định'}'.")
    return sent


# Bộ nhớ đệm ánh xạ {nhãn hiển thị -> giá trị iface dùng cho sendp}
_IFACE_MAP: Dict[str, str] = {}


def _build_iface_map() -> Dict[str, str]:
    """
    Dựng {nhãn dễ đọc -> tên card để sendp}. Trên Windows ưu tiên mô tả + IP
    thay vì GUID \\Device\\NPF_{...}. Lỗi/không có Scapy -> rỗng.
    """
    mapping: Dict[str, str] = {}
    ordered: List[tuple] = []   # (nhãn, có_IP) để sắp card có IP lên đầu
    # 1) Windows: tên mô tả + IPv4
    try:
        from scapy.arch.windows import get_windows_if_list
        for d in get_windows_if_list():
            desc = d.get("description") or d.get("name") or "?"
            ips = [ip for ip in (d.get("ips") or []) if ":" not in ip]  # chỉ IPv4
            ipstr = ips[0] if ips else "không có IP"
            label = f"{desc}  [{ipstr}]"
            # sendp chấp nhận tên card (name); dự phòng GUID nếu thiếu
            mapping[label] = d.get("name") or d.get("guid")
            ordered.append((label, bool(ips)))
    except Exception:                       # noqa: BLE001
        pass
    # 2) Dự phòng (Linux/khi trên không chạy): tên card thô
    if not mapping:
        try:
            from scapy.arch import get_if_list
            for n in get_if_list():
                mapping[n] = n
                ordered.append((n, True))
        except Exception:                   # noqa: BLE001
            return {}
    ordered.sort(key=lambda x: (not x[1]))  # có IP lên trước
    _IFACE_MAP.clear()
    _IFACE_MAP.update(mapping)
    # giữ đúng thứ tự đã sắp
    return {lbl: mapping[lbl] for lbl, _ in ordered}


# Cổng localhost để gửi thẳng sang Phần 1 (P1 lắng nghe cổng này)
PART1_HOST = "127.0.0.1"
PART1_PORT = 59999


def stream_pcap_to_part1(pcap_path: str, host: str = PART1_HOST, port: int = PART1_PORT,
                         progress: Optional[Callable[[int, int], None]] = None,
                         log: Optional[Callable[[str], None]] = None) -> int:
    """
    Đọc pcap, rút gọn từng gói thành JSON rồi GỬI QUA SOCKET tới Phần 1 đang
    lắng nghe ở (host, port). Không cần Npcap/quyền quản trị vì đi qua localhost.
    Trả về số gói đã gửi.
    """
    import json
    import socket
    from scapy.all import rdpcap, IP, TCP, UDP, ICMP

    def _log(m):
        if log:
            log(m)

    pkts = rdpcap(pcap_path)
    recs = []
    for p in pkts:
        if IP not in p:
            continue
        ip = p[IP]
        d = {"ts": float(p.time), "src": ip.src, "dst": ip.dst}
        if TCP in p:
            t = p[TCP]
            bits = int(t.flags)
            flags = [c for c, b in (("S", 0x02), ("A", 0x10), ("F", 0x01),
                                    ("R", 0x04), ("P", 0x08), ("U", 0x20)) if bits & b]
            d.update(proto="tcp", sport=int(t.sport), dport=int(t.dport),
                     length=len(t.payload), flags=flags)
        elif UDP in p:
            u = p[UDP]
            d.update(proto="udp", sport=int(u.sport), dport=int(u.dport),
                     length=max(0, int(u.len) - 8))
        elif ICMP in p:
            d.update(proto="icmp", sport=0, dport=0,
                     length=len(p[ICMP].payload), icmp_type=int(p[ICMP].type))
        else:
            continue
        recs.append(d)

    _log(f"Kết nối tới Phần 1 {host}:{port} ...")
    s = socket.create_connection((host, port), timeout=5)
    try:
        for i, d in enumerate(recs):
            s.sendall((json.dumps(d) + "\n").encode("utf-8"))
            if progress:
                progress(i + 1, len(recs))
    finally:
        s.close()
    _log(f"Đã gửi {len(recs)} gói sang Phần 1.")
    return len(recs)


def list_interfaces() -> List[str]:
    """Danh sách NHÃN card mạng dễ đọc (cần Scapy). Lỗi -> danh sách rỗng."""
    return list(_build_iface_map().keys())


def resolve_iface(label: Optional[str]) -> Optional[str]:
    """Đổi nhãn hiển thị thành tên card thật để truyền cho sendp()."""
    if not label:
        return None
    if label in _IFACE_MAP:
        return _IFACE_MAP[label]
    _build_iface_map()
    return _IFACE_MAP.get(label, label)
