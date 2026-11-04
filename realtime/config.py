"""
Cấu hình cho module realtime. Tái sử dụng các bảng ánh xạ cổng->service và
các ngưỡng NSL-KDD đã khai báo trong cross_dataset.config để KHÔNG lặp lại
"nguồn sự thật".
"""
from __future__ import annotations

from dataclasses import dataclass

from cross_dataset.config import (  # tái sử dụng, không định nghĩa lại
    PORT_TO_KDD_SERVICE, PORT_TO_KDD_SERVICE_PROTO,
    UNKNOWN_SERVICE_BY_PROTO, UNKNOWN_SERVICE_DEFAULT,
    LOGIN_SERVICES, KDD_TIME_WINDOW_SEC, KDD_DST_HOST_CAP,
)

# 41 cột NSL-KDD theo đúng thứ tự (bằng FEATURE_NAMES của src/preprocess.py).
# Khai báo tại đây để realtime không phải import src lúc nạp module.
FEATURE_NAMES = [
    "duration", "protocol_type", "service", "flag", "src_bytes",
    "dst_bytes", "land", "wrong_fragment", "urgent", "hot",
    "num_failed_logins", "logged_in", "num_compromised", "root_shell",
    "su_attempted", "num_root", "num_file_creations", "num_shells",
    "num_access_files", "num_outbound_cmds", "is_host_login",
    "is_guest_login", "count", "srv_count", "serror_rate",
    "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate",
    "diff_srv_rate", "srv_diff_host_rate", "dst_host_count",
    "dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate",
]

# 13 đặc trưng "content" + vài cột KDD không suy ra được từ gói tin -> gán 0
CONTENT_ZERO = [
    "hot", "num_failed_logins", "num_compromised", "root_shell",
    "su_attempted", "num_root", "num_file_creations", "num_shells",
    "num_access_files", "num_outbound_cmds", "is_host_login", "is_guest_login",
    "wrong_fragment",
]


@dataclass
class RealtimeConfig:
    """Tham số vận hành của bộ giám sát thời gian thực."""
    flow_timeout: float = 2.0          # giây không thấy gói -> đóng flow (bằng cửa sổ KDD)
    poll_interval: float = 1.0         # chu kỳ gom flow đã đóng rồi dự đoán (giây)
    history_seconds: float = 60.0      # giữ lịch sử flow để tính đúng cửa sổ 2s / 255-host
    history_max: int = 20000           # trần số flow lịch sử (chống phình bộ nhớ)
    attack_threshold: float = 0.5      # ngưỡng xác suất "tấn công" để bật cảnh báo
    bpf_filter: str = "ip and (tcp or udp or icmp)"   # lọc BPF khi bắt gói Scapy
    time_window: float = KDD_TIME_WINDOW_SEC
    host_window: int = KDD_DST_HOST_CAP


def port_to_service(proto: str, port: int) -> str:
    """Suy tên service kiểu NSL-KDD từ (proto, cổng đích)."""
    key = (proto, port)
    if key in PORT_TO_KDD_SERVICE_PROTO:
        return PORT_TO_KDD_SERVICE_PROTO[key]
    if port in PORT_TO_KDD_SERVICE:
        return PORT_TO_KDD_SERVICE[port]
    return UNKNOWN_SERVICE_BY_PROTO.get(proto, UNKNOWN_SERVICE_DEFAULT)
