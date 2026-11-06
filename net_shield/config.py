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
    block_threshold: int = 3            # số kết nối tấn công từ 1 IP trước khi chặn
    max_alerts: int = 300               # số dòng cảnh báo giữ lại để hiển thị
    whitelist: List[str] = field(default_factory=list)   # IP không bao giờ chặn
