"""Cấu hình cho Net Shield (IPS mạng + dashboard web)."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List


@dataclass
class IPSConfig:
    dashboard_host: str = "127.0.0.1"   # dashboard mở ở máy này
    dashboard_port: int = 8081
    flow_timeout: float = 2.0
    auto_block: bool = True             # tự chặn IP khi phát hiện tấn công

    # ---- chính sách chặn thông minh (chống chặn nhầm) ------------------
    # Một kết nối chỉ được TÍNH là tấn công khi xác suất "không phải normal"
    # (= 1 - P(normal), tổng xác suất các lớp tấn công) >= min_attack_prob.
    # Dùng tổng thay vì xác suất lớp cao nhất vì với port scan mô hình hay
    # phân vân giữa dos/probe (mỗi lớp ~0.4-0.5) dù chắc chắn là tấn công.
    min_attack_prob: float = 0.60
    # Chặn khi 1 IP có >= block_threshold kết nối tấn công (đã tính) trong
    # block_window giây gần nhất (cửa sổ trượt) = yêu cầu TỐC ĐỘ tối thiểu.
    # SYN flood / quét cổng tạo hàng trăm-hàng nghìn kết nối mỗi giây, còn
    # trình duyệt gặp trang bị chặn (SYN không được trả lời -> cờ S0, mô hình
    # dễ nhầm là DoS) chỉ gửi lại vài kết nối mỗi giây.
    block_threshold: int = 20
    block_window: float = 5.0
    # Kết nối do CHÍNH máy shield mở ra ngoài: hiển thị nhưng không tính là
    # tấn công (máy mình không tự tấn công ai; IP mình cũng không bao giờ bị chặn).
    count_self_outbound: bool = False
    # Tự gỡ chặn sau block_ttl giây (0 = chặn vĩnh viễn tới khi gỡ tay).
    block_ttl: float = 600.0

    # ---- hiển thị -------------------------------------------------------
    max_alerts: int = 300               # số dòng lưu lượng gần đây giữ lại
    max_attacks: int = 300              # số dòng trong bảng "Tấn công"
    replay_delay: float = 0.04          # giãn nhịp khi phát lại pcap (để kịp xem)

    # ---- truy cập dashboard từ máy khác trong LAN ----------------------
    allow_lan: bool = False             # True: mở cho máy khác cùng mạng (bind 0.0.0.0)
    dashboard_password: str = ""        # mật khẩu Basic Auth khi mở LAN (trống -> tự sinh)

    whitelist: List[str] = field(default_factory=list)   # IP không bao giờ chặn
