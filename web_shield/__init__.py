"""
Phần 3 — WEB SHIELD: reverse proxy đóng vai "lá chắn" đứng trước một web server.

Mọi request web đi qua proxy này: request nguy hiểm bị CHẶN NGAY (HTTP 403) kèm
cảnh báo; request sạch được chuyển tiếp tới web server thật rồi trả kết quả về.

Độc lập hoàn toàn với luồng cũ (đặt cạnh src/, realtime/). Chỉ dùng thư viện
chuẩn của Python cho phần lõi (http.server, http.client), nên chạy không cần cài
thêm. Giao diện dùng customtkinter.

2 lớp phát hiện (bổ trợ cho mô hình mạng NSL-KDD ở Phần 1):
  * Lớp luật (WAF): SQL Injection, XSS, Path Traversal, công cụ quét (scanner).
  * Lớp tần suất: HTTP flood (DoS) theo số request/giây của mỗi IP nguồn.
"""
from .detector import WebDetector, Verdict
from .proxy import ShieldServer

__all__ = ["WebDetector", "Verdict", "ShieldServer"]
