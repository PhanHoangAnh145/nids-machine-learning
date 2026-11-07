"""
Reverse proxy "lá chắn": nhận request -> kiểm tra -> CHẶN (403) hoặc CHUYỂN TIẾP
tới web server thật rồi trả kết quả về client.

Chỉ dùng thư viện chuẩn (http.server, http.client). Chạy đa luồng để nhiều
request không chặn nhau.
"""
from __future__ import annotations

import http.client
import threading
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable, Optional
from urllib.parse import urlsplit

from .config import ShieldConfig
from .detector import WebDetector, Verdict

# Header "hop-by-hop" không được chuyển tiếp nguyên trạng
_HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
        "te", "trailers", "transfer-encoding", "upgrade", "host"}

_BLOCK_PAGE = (
    "<!doctype html><html lang='vi'><meta charset='utf-8'>"
    "<title>403 - Bị chặn</title>"
    "<body style='font-family:system-ui;background:#1b1b1f;color:#eee;"
    "text-align:center;padding:60px'>"
    "<h1 style='color:#e74c3c'>&#128680; Yêu cầu bị chặn</h1>"
    "<p>NIDS SHIELD đã phát hiện yêu cầu nguy hiểm và chặn nó.</p>"
    "<p style='color:#888'>Loại: {category} &middot; {reason}</p>"
    "</body></html>"
)


@dataclass
class ShieldEvent:
    ts: float
    ip: str
    method: str
    path: str
    verdict: Verdict
    status: int = 0          # mã trả về (403 nếu chặn, hoặc mã của upstream)


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):   # tắt log mặc định ra stderr
        pass

    # Mọi method đều đi qua một đường xử lý chung
    def _handle(self):
        srv: "ShieldServer" = self.server      # type: ignore[assignment]
        ip = self.client_address[0]
        parts = urlsplit(self.path)
        headers = {k.lower(): v for k, v in self.headers.items()}

        length = int(self.headers.get("Content-Length", 0) or 0)
        body = b""
        if length:
            body = self.rfile.read(min(length, srv.cfg.max_body_inspect))
            # đọc nốt phần dư (không soi) để không kẹt kết nối
            remain = length - len(body)
            while remain > 0:
                chunk = self.rfile.read(min(remain, 65536))
                if not chunk:
                    break
                body += chunk
                remain -= len(chunk)

        verdict = srv.detector.inspect(
            ip, self.command, parts.path, parts.query, headers, body)

        if not verdict.allowed:
            self._send_block(verdict)
            srv._emit(ShieldEvent(time.time(), ip, self.command, self.path, verdict, 403))
            return

        status = self._forward(srv, body)
        srv._emit(ShieldEvent(time.time(), ip, self.command, self.path, verdict, status))

    def _send_block(self, verdict: Verdict):
        page = _BLOCK_PAGE.format(category=verdict.category, reason=verdict.reason).encode("utf-8")
        self.send_response(403)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(page)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(page)

    def _forward(self, srv: "ShieldServer", body: bytes) -> int:
        """Chuyển tiếp request tới upstream, relay response về client."""
        try:
            conn = http.client.HTTPConnection(srv.cfg.upstream_host, srv.cfg.upstream_port, timeout=10)
            fwd_headers = {k: v for k, v in self.headers.items() if k.lower() not in _HOP}
            fwd_headers["X-Forwarded-For"] = self.client_address[0]
            conn.request(self.command, self.path, body=body or None, headers=fwd_headers)
            resp = conn.getresponse()
            data = resp.read()
            self.send_response(resp.status)
            for k, v in resp.getheaders():
                if k.lower() in _HOP or k.lower() == "content-length":
                    continue
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(data)
            conn.close()
            return resp.status
        except Exception as exc:  # noqa: BLE001
            msg = f"Lá chắn không kết nối được web server thật ({exc}).".encode("utf-8")
            self.send_response(502)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(msg)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(msg)
            return 502

    # ánh xạ các method HTTP thường gặp vào _handle
    do_GET = do_POST = do_HEAD = do_PUT = do_DELETE = do_OPTIONS = do_PATCH = _handle


class ShieldServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, cfg: ShieldConfig, on_event: Optional[Callable[[ShieldEvent], None]] = None):
        super().__init__((cfg.listen_host, cfg.listen_port), _Handler)
        self.cfg = cfg
        self.detector = WebDetector(cfg.rate_window, cfg.rate_max, cfg.block_seconds)
        self.on_event = on_event
        self.stats = {"total": 0, "blocked": 0}
        self._thread: Optional[threading.Thread] = None

    def _emit(self, ev: ShieldEvent):
        self.stats["total"] += 1
        if not ev.verdict.allowed:
            self.stats["blocked"] += 1
        if self.on_event:
            try:
                self.on_event(ev)
            except Exception:  # noqa: BLE001
                pass

    def start_background(self):
        self._thread = threading.Thread(target=self.serve_forever, daemon=True)
        self._thread.start()

    def stop(self):
        self.shutdown()
        self.server_close()
