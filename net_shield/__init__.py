"""
Phần 3 (bản IPS mạng) — NET SHIELD: hệ thống ngăn chặn xâm nhập có dashboard web.

Bấm "Bắt đầu" -> bắt gói trực tiếp trên card mạng (realtime engine) -> mô hình
phát hiện tấn công (DoS/Probe) -> TỰ CHẶN IP nguồn bằng Windows Firewall/iptables
-> hiển thị cảnh báo & danh sách IP bị chặn trên trình duyệt.

Giao diện là trang web (dashboard.html) do một web server nhỏ phục vụ; chạy bằng
thư viện chuẩn. Bắt gói + chặn IP cần Npcap + quyền Administrator.
"""
from .controller import IPSController
from .config import IPSConfig
from .blocker import FirewallBlocker

__all__ = ["IPSController", "IPSConfig", "FirewallBlocker"]
