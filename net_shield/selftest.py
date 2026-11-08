"""
net_shield · CHẾ ĐỘ TỰ KIỂM THỬ đường cảnh báo xâm nhập.

Mục đích: cho bạn THẤY NGAY "thông báo xâm nhập" chạy thật mà KHÔNG cần
Npcap, KHÔNG cần quyền Admin, KHÔNG cần 2 máy.

Cách hoạt động:
    (giả lập) SYN flood / quét cổng / smurf  ──┐
                                               ├─► ĐÚNG mô hình RF của dự án
    (giả lập) lưu lượng web bình thường ───────┘      (src.predictor)
                           │
                           ▼
        controller.on_prediction()  → sinh cảnh báo + tự chặn IP
                           │
                           ▼
        dashboard web http://127.0.0.1:8081  (bảng "Cảnh báo gần đây")

Chạy:
    python -m net_shield.selftest

Lưu lượng tấn công dùng IP GIẢ LẬP trong vùng lab (10.0.0.x) — đây chỉ là
dữ liệu để thử mô hình, không gửi gói nào ra mạng thật.
"""
from __future__ import annotations

import itertools
import threading
import time
import webbrowser
from typing import List

from .config import IPSConfig
from .controller import IPSController
from .server import DashboardServer


# ---------------------------------------------------------------------------
# Bộ sinh lưu lượng giả lập (nội bộ, không phụ thuộc thư mục khác).
# Chỉ tạo đối tượng PacketMeta trong RAM rồi đưa thẳng vào engine — KHÔNG gửi
# gói nào ra card mạng.
# ---------------------------------------------------------------------------
def _packets():
    from realtime.packet import PacketMeta

    SYN = frozenset({"S"})
    SYNACK = frozenset({"S", "A"})
    ACK = frozenset({"A"})
    RSTACK = frozenset({"R", "A"})
    PSHACK = frozenset({"P", "A"})
    FINACK = frozenset({"F", "A"})

    def tcp(ts, s, d, sp, dp, fl, ln=0):
        return PacketMeta(ts=ts, proto="tcp", src_ip=s, dst_ip=d,
                          sport=sp, dport=dp, length=ln, tcp_flags=fl)

    TGT = "192.168.1.10"   # "nạn nhân" giả lập

    def synflood(atk, n=350, rate=2000.0):
        dt = 1.0 / rate
        return [tcp(i * dt, atk, TGT, 1024 + (i % 40000), 80, SYN) for i in range(n)]

    def synscan(atk, n=250):
        out: List = []
        openp = {80, 22, 443}
        for i, port in enumerate(range(1, n + 1)):
            ts, sp = i * 0.002, 40000 + i
            out.append(tcp(ts, atk, TGT, sp, port, SYN))
            if port in openp:
                out.append(tcp(ts + 5e-4, TGT, atk, port, sp, SYNACK))
                out.append(tcp(ts + 1e-3, atk, TGT, sp, port, RSTACK))
            else:
                out.append(tcp(ts + 5e-4, TGT, atk, port, sp, RSTACK))
        return out

    def smurf(atk, n=350, rate=2000.0):
        from realtime.packet import PacketMeta as PM
        dt = 1.0 / rate
        return [PM(ts=i * dt, proto="icmp", src_ip=atk, dst_ip=TGT,
                   length=1032, icmp_type=0) for i in range(n)]

    def normal(src="10.0.0.50", n=12):
        from realtime.packet import PacketMeta as PM
        out: List = []
        ts = 0.0
        for i in range(n):
            sp, dp = 1024 + i * 7, 80
            out += [
                tcp(ts, src, "93.184.216.34", sp, dp, SYN),
                tcp(ts + 1e-3, "93.184.216.34", src, dp, sp, SYNACK),
                tcp(ts + 2e-3, src, "93.184.216.34", sp, dp, ACK),
                tcp(ts + 3e-3, src, "93.184.216.34", sp, dp, PSHACK, 200),
                tcp(ts + 4e-3, "93.184.216.34", src, dp, sp, PSHACK, 1500),
                tcp(ts + 5e-3, src, "93.184.216.34", sp, dp, FINACK),
                tcp(ts + 6e-3, "93.184.216.34", src, dp, sp, FINACK),
                tcp(ts + 7e-3, src, "93.184.216.34", sp, dp, ACK),
            ]
            ts += 0.2
        return out

    # vòng lặp vô hạn: lần lượt các kịch bản để dashboard luôn có cái mới
    return itertools.cycle([
        ("SYN flood (DoS)",   lambda: synflood("10.0.0.9")),
        ("Quét cổng (Probe)", lambda: synscan("10.0.0.13")),
        ("Smurf (DoS)",       lambda: smurf("10.0.0.21")),
        ("Lưu lượng sạch",    lambda: normal("10.0.0.50")),
    ])


def _feeder(controller: IPSController, stop: threading.Event):
    """Bơm từng mẻ lưu lượng qua mô hình, mỗi 3 giây một kịch bản."""
    from realtime.engine import RealtimeEngine
    from realtime.config import RealtimeConfig

    gen = _packets()
    while not stop.is_set():
        label, make = next(gen)
        pkts = make()
        controller._note(f"— Đang thử: {label} ({len(pkts)} gói giả lập) —")
        eng = RealtimeEngine(config=RealtimeConfig(flow_timeout=2.0),
                             predictor=controller.predictor, load_model=False)
        for m in pkts:
            for pred in eng.ingest_packet(m):
                controller.on_prediction(pred)
        for pred in eng.flush():
            controller.on_prediction(pred)
        with controller._lock:
            controller.stats["packets"] += len(pkts)
        stop.wait(3.0)


def run():
    cfg = IPSConfig()                      # auto_block=True, ngưỡng=3, cổng 8081
    controller = IPSController(cfg)
    if controller.predictor is None:
        print("[selftest] Chưa nạp được mô hình. Cài: "
              "pip install scikit-learn pandas joblib numpy")
        return

    srv = DashboardServer(cfg, controller)
    url = f"http://{cfg.dashboard_host}:{cfg.dashboard_port}"
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    controller._note("CHẾ ĐỘ TỰ KIỂM THỬ — không cần bấm 'Bắt đầu'. "
                     "Đang bơm tấn công giả lập để thử đường cảnh báo.")
    print(f"[selftest] Dashboard: {url}")
    print("[selftest] Đang bơm tấn công giả lập qua mô hình... (Ctrl+C để dừng)")
    if not controller.blocker.admin:
        print("[selftest] (Không phải Admin → chặn ở chế độ 'logic', chỉ cảnh báo. "
              "Vẫn thấy đầy đủ cảnh báo trên dashboard.)")
    try:
        webbrowser.open(url)
    except Exception:  # noqa: BLE001
        pass

    stop = threading.Event()
    threading.Thread(target=_feeder, args=(controller, stop), daemon=True).start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[selftest] Dừng.")
        stop.set()
        controller.stop()
        srv.shutdown()


if __name__ == "__main__":
    run()
