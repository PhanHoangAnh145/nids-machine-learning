"""
Module GIÁM SÁT THỜI GIAN THỰC (realtime) cho NIDS SHIELD.

Bắt gói tin trên card mạng -> gom thành "kết nối" (connection) -> tính lại 41
đặc trưng NSL-KDD -> đưa vào ĐÚNG mô hình cũ (models/best_model.joblib) để dự
đoán, rồi đẩy cảnh báo ra giao diện / console.

Nguyên tắc (giống cross_dataset): KHÔNG sửa, KHÔNG ghi đè bất kỳ tệp nào của
luồng cũ. Module này chỉ ĐỌC model + preprocessor và TÁI SỬ DỤNG
cross_dataset.kdd_feature_builder để bảo đảm cùng một định nghĩa đặc trưng.

Kiến trúc tách lớp để chạy và kiểm thử được cả khi KHÔNG có Scapy:
    PacketMeta      : thông tin tối giản trích từ 1 gói tin (độc lập Scapy)
    pcap_io         : đọc/ghi .pcap thuần Python -> PacketMeta (không cần Scapy)
    FlowTracker     : máy trạng thái 5-tuple -> ConnectionRecord (cờ, byte, service)
    FeatureAdapter  : ConnectionRecord -> 41 cột NSL-KDD (dùng build_traffic_features)
    RealtimeEngine  : điều phối ingest -> poll -> predict; có live_capture() (Scapy)
Scapy CHỈ xuất hiện ở lớp bắt gói trực tiếp (engine.live_capture / packet.from_scapy).
"""
from .packet import PacketMeta
from .flow_tracker import FlowTracker, ConnectionRecord
from .feature_adapter import FeatureAdapter
from .engine import RealtimeEngine, Prediction

__all__ = [
    "PacketMeta", "FlowTracker", "ConnectionRecord",
    "FeatureAdapter", "RealtimeEngine", "Prediction",
]
