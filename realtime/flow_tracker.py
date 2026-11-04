"""
FlowTracker: gom các PacketMeta cùng một "kết nối" (5-tuple) và sinh ra
ConnectionRecord mang đúng ngữ nghĩa NSL-KDD.

Phần khó nhất là suy CỜ (flag) kiểu NSL-KDD từ trình tự cờ TCP quan sát được.
Quy ước bám theo conn_state của Bro/Zeek — chính công cụ đã sinh ra NSL-KDD:

    SF    : thiết lập bình thường rồi kết thúc (có SYN, SYN-ACK, có FIN)
    S0    : chỉ thấy SYN của bên gửi, không có phản hồi  (SYN flood / cổng bị lọc)
    S1    : đã thiết lập (SYN + SYN-ACK) nhưng chưa thấy kết thúc
    REJ   : SYN bị từ chối bằng RST từ bên nhận           (cổng đóng -> quét cổng)
    RSTO  : đã thiết lập, bên GỬI gửi RST
    RSTR  : đã thiết lập, bên NHẬN gửi RST
    SH    : bên gửi gửi SYN rồi FIN, không có SYN-ACK      (half-open scan)
    OTH   : không rơi vào các trạng thái trên (bắt giữa chừng, không có SYN)

UDP/ICMP: NSL-KDD gần như luôn gán 'SF'.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .config import port_to_service, LOGIN_SERVICES
from .packet import PacketMeta

FlowKey = Tuple[str, str, int, str, int]   # (proto, ipA, portA, ipB, portB) đã chuẩn hóa

# ICMP: echo reply -> ecr_i (đặc trưng của smurf), echo request -> eco_i (ping/ipsweep)
def _icmp_service(itype: int) -> str:
    if itype == 0:
        return "ecr_i"
    if itype == 8:
        return "eco_i"
    return "urp_i"


@dataclass
class ConnectionRecord:
    """Một kết nối đã đóng, đủ thông tin để sinh 41 đặc trưng NSL-KDD."""
    ts: float                     # thời điểm bắt đầu
    end_ts: float
    proto: str                    # tcp/udp/icmp
    src: str                      # IP bên khởi tạo (originator)
    dst: str                      # IP bên nhận (responder) -> dst host của KDD
    sport: int
    dport: int
    service: str
    flag: str
    src_bytes: int
    dst_bytes: int
    land: int
    urgent: int
    logged_in: int
    is_guest_login: int = 0
    n_pkts: int = 0

    @property
    def duration(self) -> int:
        # NSL-KDD tính duration theo GIÂY nguyên
        return int(max(0.0, self.end_ts - self.ts))


class _Flow:
    """Trạng thái tích lũy của một flow đang mở."""
    __slots__ = (
        "proto", "orig_ip", "orig_port", "resp_ip", "resp_port",
        "first_ts", "last_ts", "orig_bytes", "resp_bytes", "n_pkts",
        "saw_syn", "saw_synack", "saw_ack", "fin_orig", "fin_resp",
        "rst_orig", "rst_resp", "data_orig", "data_resp", "urg", "established",
    )

    def __init__(self, proto: str, orig_ip: str, orig_port: int, resp_ip: str, resp_port: int, ts: float):
        self.proto = proto
        self.orig_ip = orig_ip
        self.orig_port = orig_port
        self.resp_ip = resp_ip
        self.resp_port = resp_port
        self.first_ts = ts
        self.last_ts = ts
        self.orig_bytes = 0
        self.resp_bytes = 0
        self.n_pkts = 0
        self.saw_syn = False
        self.saw_synack = False
        self.saw_ack = False
        self.fin_orig = False
        self.fin_resp = False
        self.rst_orig = False
        self.rst_resp = False
        self.data_orig = False
        self.data_resp = False
        self.urg = 0
        self.established = False

    def update(self, p: PacketMeta, from_orig: bool) -> None:
        self.last_ts = p.ts
        self.n_pkts += 1
        if from_orig:
            self.orig_bytes += p.length
            if p.length > 0:
                self.data_orig = True
        else:
            self.resp_bytes += p.length
            if p.length > 0:
                self.data_resp = True

        if self.proto != "tcp":
            return
        if p.is_urg:
            self.urg += 1
        if p.is_pure_syn and from_orig:
            self.saw_syn = True
        if p.is_synack and not from_orig:
            self.saw_synack = True
        if p.is_syn and self.saw_syn and self.saw_synack:
            self.established = True
        if (ACK := ("A" in p.tcp_flags)) and self.saw_syn and self.saw_synack:
            self.saw_ack = True
            self.established = True
        if p.is_fin:
            if from_orig:
                self.fin_orig = True
            else:
                self.fin_resp = True
        if p.is_rst:
            if from_orig:
                self.rst_orig = True
            else:
                self.rst_resp = True

    # -- suy cờ NSL-KDD -------------------------------------------------
    def kdd_flag(self) -> str:
        if self.proto != "tcp":
            return "SF"
        est = self.established
        if est:
            if self.rst_orig:
                return "RSTO"
            if self.rst_resp:
                return "RSTR"
            if self.fin_orig or self.fin_resp:
                return "SF"
            return "S1"                       # thiết lập nhưng chưa đóng (timeout)
        # chưa thiết lập
        if self.saw_syn and self.rst_resp:
            return "REJ"                      # SYN -> RST từ bên nhận: cổng đóng
        if self.saw_syn and (self.fin_orig or self.fin_resp):
            return "SH"                       # SYN rồi FIN, không bắt tay: half-open
        if self.saw_syn and not self.saw_synack:
            return "S0"                       # SYN không hồi đáp: SYN flood/filtered
        return "OTH"

    def to_record(self) -> ConnectionRecord:
        service = port_to_service(self.proto, self.resp_port)
        land = 1 if (self.orig_ip == self.resp_ip and self.orig_port == self.resp_port) else 0
        flag = self.kdd_flag()
        logged_in = 1 if (
            self.proto == "tcp" and self.established and service in LOGIN_SERVICES
            and self.data_resp
        ) else 0
        return ConnectionRecord(
            ts=self.first_ts, end_ts=self.last_ts, proto=self.proto,
            src=self.orig_ip, dst=self.resp_ip, sport=self.orig_port,
            dport=self.resp_port, service=service, flag=flag,
            src_bytes=self.orig_bytes, dst_bytes=self.resp_bytes,
            land=land, urgent=self.urg, logged_in=logged_in, n_pkts=self.n_pkts,
        )


def _norm_key(p: PacketMeta) -> Tuple[FlowKey, bool]:
    """
    Khóa flow bất kể chiều: hai đầu được sắp xếp. Trả về (key, is_a_src) để
    biết gói hiện tại đi theo chiều nào so với "đầu A" đã chọn.
    """
    a = (p.src_ip, p.sport)
    b = (p.dst_ip, p.dport)
    if a <= b:
        return (p.proto, a[0], a[1], b[0], b[1]), True
    return (p.proto, b[0], b[1], a[0], a[1]), False


class FlowTracker:
    """
    Nhận PacketMeta theo thứ tự thời gian, trả về danh sách ConnectionRecord
    mỗi khi một flow đóng (FIN/RST đủ, hoặc hết thời gian chờ).
    """

    def __init__(self, flow_timeout: float = 2.0):
        self.flow_timeout = flow_timeout
        self._flows: Dict[FlowKey, _Flow] = {}
        self._orig_is_a: Dict[FlowKey, bool] = {}   # đầu A có phải originator không
        self._recent_closed: Dict[FlowKey, float] = {}  # nuốt gói "đuôi" sau khi flow đóng

    def _pick_originator(self, p: PacketMeta, a_is_src: bool) -> bool:
        """Xác định đầu A có phải bên khởi tạo. Dựa vào gói SYN đầu tiên."""
        if p.proto == "tcp" and p.is_pure_syn:
            return a_is_src          # bên gửi SYN là originator
        return a_is_src              # mặc định: bên gửi gói đầu tiên là originator

    def ingest(self, p: PacketMeta) -> List[ConnectionRecord]:
        closed = self._expire(p.ts)

        # ICMP: NSL-KDD coi mỗi gói là một "kết nối" riêng (vd smurf là rất nhiều
        # kết nối echo). Sinh thẳng bản ghi, không gom theo 5-tuple.
        if p.proto == "icmp":
            closed.append(ConnectionRecord(
                ts=p.ts, end_ts=p.ts, proto="icmp", src=p.src_ip, dst=p.dst_ip,
                sport=0, dport=0, service=_icmp_service(p.icmp_type), flag="SF",
                src_bytes=p.length, dst_bytes=0, land=1 if p.src_ip == p.dst_ip else 0,
                urgent=0, logged_in=0, n_pkts=1,
            ))
            return closed

        key, a_is_src = _norm_key(p)

        # Gói "đuôi" (ACK cuối sau FIN/FIN, RST lặp...) đến ngay sau khi flow đóng
        # thì bỏ qua, tránh tạo kết nối giả.
        last_closed = self._recent_closed.get(key)
        if last_closed is not None:
            if p.ts - last_closed <= self.flow_timeout:
                return closed
            del self._recent_closed[key]

        flow = self._flows.get(key)
        if flow is None:
            orig_is_a = self._pick_originator(p, a_is_src)
            self._orig_is_a[key] = orig_is_a
            if orig_is_a:
                oi, op, ri, rp = key[1], key[2], key[3], key[4]
            else:
                oi, op, ri, rp = key[3], key[4], key[1], key[2]
            flow = _Flow(p.proto, oi, op, ri, rp, p.ts)
            self._flows[key] = flow

        from_orig = (a_is_src == self._orig_is_a[key])
        flow.update(p, from_orig)

        if self._is_terminated(flow):
            closed.append(flow.to_record())
            del self._flows[key]
            self._orig_is_a.pop(key, None)
            self._recent_closed[key] = p.ts
            self._prune_recent(p.ts)
        return closed

    def _prune_recent(self, now: float) -> None:
        dead = [k for k, t in self._recent_closed.items() if now - t > self.flow_timeout]
        for k in dead:
            del self._recent_closed[k]

    @staticmethod
    def _is_terminated(flow: _Flow) -> bool:
        if flow.proto != "tcp":
            return False                       # UDP/ICMP đóng theo timeout
        if flow.rst_orig or flow.rst_resp:
            return True
        if flow.fin_orig and flow.fin_resp:
            return True
        return False

    def _expire(self, now: float) -> List[ConnectionRecord]:
        out: List[ConnectionRecord] = []
        dead = [k for k, f in self._flows.items() if now - f.last_ts > self.flow_timeout]
        for k in dead:
            out.append(self._flows[k].to_record())
            del self._flows[k]
            self._orig_is_a.pop(k, None)
        return out

    def flush(self, now: Optional[float] = None) -> List[ConnectionRecord]:
        """Đóng toàn bộ flow còn mở (gọi khi dừng bắt gói / hết file)."""
        out = [f.to_record() for f in self._flows.values()]
        self._flows.clear()
        self._orig_is_a.clear()
        return out

    def open_count(self) -> int:
        return len(self._flows)
