"""Cấu hình cho Web Shield (reverse proxy)."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class ShieldConfig:
    listen_host: str = "0.0.0.0"       # proxy nghe ở đây (0.0.0.0 = mọi card -> 2 máy dùng được)
    listen_port: int = 8080            # cổng proxy; client/trình duyệt trỏ vào đây
    upstream_host: str = "127.0.0.1"   # web server THẬT nằm sau lá chắn
    upstream_port: int = 8000
    # Giới hạn tần suất (chống HTTP flood): quá `rate_max` request trong `rate_window`
    # giây từ cùng 1 IP -> coi là DoS và chặn IP đó trong `block_seconds`.
    rate_window: float = 10.0
    rate_max: int = 80
    block_seconds: float = 60.0
    max_body_inspect: int = 65536      # chỉ soi tối đa 64KB thân request (đủ bắt payload)
