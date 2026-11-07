"""
RealtimeEngine: điều phối toàn bộ luồng giám sát thời gian thực.

    PacketMeta --ingest--> FlowTracker --(flow đóng)--> ConnectionRecord
        --> (gộp với lịch sử gần đây) --> FeatureAdapter --> 41 cột KDD
        --> NIDSPredictor.predict_batch --> Prediction (có cảnh báo)

Giữ một CỬA SỔ LỊCH SỬ các kết nối gần đây để build_traffic_features tính đúng
nhóm đặc trưng 2 giây / 255-host (các đặc trưng này phụ thuộc kết nối lân cận,
không thể tính từ một kết nối đơn lẻ).

KHÔNG sửa luồng cũ: engine chỉ gọi NIDSPredictor (đọc model cũ). Nếu không nạp
được model, engine vẫn gom luồng + tính đặc trưng (hữu ích cho kiểm thử offline).
"""
from __future__ import annotations

import threading
from collections import deque
from dataclasses import dataclass
from typing import Callable, Deque, List, Optional, Sequence

import pandas as pd

from .config import RealtimeConfig
from .feature_adapter import FeatureAdapter
from .flow_tracker import ConnectionRecord, FlowTracker
from .packet import PacketMeta, from_scapy
from . import pcap_io


@dataclass
class Prediction:
    conn: ConnectionRecord
    category: str
    is_attack: bool
    confidence: float
    probabilities: dict


def _load_predictor():
    """Nạp NIDSPredictor của luồng cũ (chỉ đọc model). Lỗi -> None."""
    try:
        from src.predictor import NIDSPredictor
        return NIDSPredictor()
    except Exception as exc:                       # noqa: BLE001
        print(f"[realtime] Cảnh báo: chưa nạp được model ({exc}). "
              f"Engine chạy chế độ chỉ-gom-luồng, không dự đoán.")
        return None


class RealtimeEngine:
    def __init__(self, config: Optional[RealtimeConfig] = None, predictor=None,
                 load_model: bool = True):
        self.cfg = config or RealtimeConfig()
        self.tracker = FlowTracker(flow_timeout=self.cfg.flow_timeout)
        self.adapter = FeatureAdapter()
        if predictor is not None:
            self.predictor = predictor
        elif load_model:
            self.predictor = _load_predictor()
        else:
            self.predictor = None
        self._history: Deque[ConnectionRecord] = deque()
        self._lock = threading.Lock()
        self.stats = {"packets": 0, "connections": 0, "attacks": 0}

    # ---- xử lý theo mẻ kết nối đã đóng --------------------------------
    def _prune_history(self, now: float) -> None:
        h = self._history
        lo = now - self.cfg.history_seconds
        while h and h[0].ts < lo:
            h.popleft()
        while len(h) > self.cfg.history_max:
            h.popleft()

    def _predict(self, new_records: Sequence[ConnectionRecord]) -> List[Prediction]:
        if not new_records:
            return []
        now = max(r.ts for r in new_records)
        self._prune_history(now)
        context = list(self._history) + list(new_records)
        frame = self.adapter.to_kdd_frame(context)
        tail = frame.iloc[len(frame) - len(new_records):].reset_index(drop=True)

        preds: List[Prediction] = []
        if self.predictor is not None:
            res = self.predictor.predict_batch(tail)
            classes = [str(c) for c in self.predictor.classes]
            model = self.predictor.model
            proba = None
            if hasattr(model, "predict_proba"):
                X = self.predictor.processor.column_transformer.transform(tail)
                proba = model.predict_proba(X)
            for i, rec in enumerate(new_records):
                cat = str(res.iloc[i]["predicted_category"])
                conf = float(res.iloc[i]["confidence"])
                if proba is not None:
                    probs = {classes[j]: float(proba[i][j]) for j in range(len(classes))}
                else:
                    probs = {cat: conf}
                preds.append(Prediction(rec, cat, cat != "normal", conf, probs))
        else:
            for rec in new_records:
                preds.append(Prediction(rec, "unknown", False, 0.0, {}))

        self._history.extend(new_records)
        self.stats["connections"] += len(new_records)
        self.stats["attacks"] += sum(1 for p in preds if p.is_attack)
        return preds

    # ---- API chính ----------------------------------------------------
    def ingest_packet(self, meta: PacketMeta) -> List[Prediction]:
        """Nạp 1 gói; trả về dự đoán cho các flow vừa đóng (nếu có)."""
        with self._lock:
            self.stats["packets"] += 1
            closed = self.tracker.ingest(meta)
            return self._predict(closed)

    def flush(self) -> List[Prediction]:
        """Đóng mọi flow còn mở và dự đoán nốt."""
        with self._lock:
            return self._predict(self.tracker.flush())

    # ---- phát lại pcap (offline, không cần Scapy) ---------------------
    def replay_pcap(self, path: str,
                    on_prediction: Optional[Callable[[Prediction], None]] = None
                    ) -> List[Prediction]:
        out: List[Prediction] = []
        for meta in pcap_io.iter_pcap(path):
            for pred in self.ingest_packet(meta):
                out.append(pred)
                if on_prediction:
                    on_prediction(pred)
        for pred in self.flush():
            out.append(pred)
            if on_prediction:
                on_prediction(pred)
        return out

    # ---- bắt gói trực tiếp (cần Scapy) --------------------------------
    def live_capture(self, iface: Optional[str] = None,
                     on_prediction: Optional[Callable[[Prediction], None]] = None,
                     stop_event: Optional[threading.Event] = None) -> None:
        """
        Bắt gói thật bằng Scapy trên `iface`. Chặn cho tới khi stop_event được
        đặt. CHỈ hàm này cần Scapy + quyền quản trị (Npcap trên Windows).
        """
        from scapy.sendrecv import AsyncSniffer   # local import cố ý

        stop_event = stop_event or threading.Event()

        def _handle(pkt):
            meta = from_scapy(pkt)
            if meta is None:
                return
            for pred in self.ingest_packet(meta):
                if on_prediction:
                    on_prediction(pred)

        # Khởi động sniffer theo nhiều cấp dự phòng (Windows hay kén tên card /
        # bộ lọc BPF): thử (card + lọc) -> (card, bỏ lọc) -> (mặc định + lọc) ->
        # (mặc định, bỏ lọc). Nhờ vậy nếu tên card không khớp vẫn bắt được.
        attempts = [
            dict(iface=iface, filter=self.cfg.bpf_filter),
            dict(iface=iface),
            dict(filter=self.cfg.bpf_filter),
            dict(),
        ]
        sniffer = None
        last_err = None
        for kw in attempts:
            try:
                sniffer = AsyncSniffer(prn=_handle, store=False, **kw)
                sniffer.start()
                break
            except Exception as exc:  # noqa: BLE001
                last_err = exc
                sniffer = None
        if sniffer is None:
            raise RuntimeError(f"không mở được sniffer ({last_err})")
        try:
            while not stop_event.is_set():
                stop_event.wait(self.cfg.poll_interval)
                # đóng các flow hết hạn theo đồng hồ thực
                import time as _t
                for pred in self._tick(_t.time()):
                    if on_prediction:
                        on_prediction(pred)
        finally:
            sniffer.stop()
            for pred in self.flush():
                if on_prediction:
                    on_prediction(pred)

    def _tick(self, now: float) -> List[Prediction]:
        """Đóng flow hết hạn theo đồng hồ (dùng khi bắt gói trực tiếp)."""
        with self._lock:
            closed = self.tracker._expire(now)   # noqa: SLF001 (nội bộ gói)
            return self._predict(closed)
