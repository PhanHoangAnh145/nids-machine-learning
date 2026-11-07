"""
Web server cho dashboard IPS: phục vụ trang dashboard + API JSON.
Chỉ dùng thư viện chuẩn (http.server). Trang web tự gọi /api/* để cập nhật.
"""
from __future__ import annotations

import json
import os
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from .config import IPSConfig
from .controller import IPSController, list_ifaces, list_pcaps

_HTML = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dashboard.html")


def _norm(s) -> str:
    return " ".join(str(s).split())


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _json(self, obj, status=200):
        data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(data)

    def _body(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        if not n:
            return {}
        try:
            return json.loads(self.rfile.read(n).decode("utf-8"))
        except ValueError:
            return {}

    def do_GET(self):
        path = urlparse(self.path).path
        srv = self.server
        if path in ("/", "/index.html"):
            with open(_HTML, "rb") as f:
                page = f.read()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(page)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(page)
        elif path == "/api/state":
            self._json(srv.controller.snapshot())
        elif path == "/api/ifaces":
            srv.iface_map = list_ifaces()
            self._json({"ifaces": list(srv.iface_map.keys())})
        elif path == "/api/pcaps":
            srv.pcap_map = list_pcaps()
            self._json({"pcaps": list(srv.pcap_map.keys())})
        else:
            self._json({"error": "not found"}, 404)

    def do_POST(self):
        path = urlparse(self.path).path
        srv = self.server
        body = self._body()
        if path == "/api/start":
            label = body.get("iface", "")
            iface = srv.iface_map.get(label)
            if iface is None:
                # Trình duyệt có thể gộp khoảng trắng trong nhãn -> so khớp lỏng
                for k, v in srv.iface_map.items():
                    if _norm(k) == _norm(label):
                        iface = v
                        break
                else:
                    iface = label
            ok, msg = srv.controller.start(iface)
            self._json({"ok": ok, "msg": msg})
        elif path == "/api/replay":
            # Chỉ nhận tên nằm trong danh sách đã liệt kê (không nhận đường dẫn tuỳ ý)
            if not srv.pcap_map:
                srv.pcap_map = list_pcaps()
            p = srv.pcap_map.get(body.get("name", ""))
            if p is None:
                self._json({"ok": False, "msg": "Không có file pcap này."})
            else:
                ok, msg = srv.controller.replay(p)
                self._json({"ok": ok, "msg": msg})
        elif path == "/api/stop":
            srv.controller.stop()
            self._json({"ok": True, "msg": "Đã dừng."})
        elif path == "/api/reset":
            ok, msg = srv.controller.reset()
            self._json({"ok": ok, "msg": msg})
        elif path == "/api/unblock":
            ok = srv.controller.unblock(body.get("ip", ""))
            self._json({"ok": ok})
        else:
            self._json({"error": "not found"}, 404)


class DashboardServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, cfg: IPSConfig, controller: IPSController):
        super().__init__((cfg.dashboard_host, cfg.dashboard_port), _Handler)
        self.controller = controller
        self.iface_map = {}
        self.pcap_map = {}


def run(cfg: IPSConfig = None, open_browser: bool = True):
    cfg = cfg or IPSConfig()
    controller = IPSController(cfg)
    srv = DashboardServer(cfg, controller)
    url = f"http://{cfg.dashboard_host}:{cfg.dashboard_port}"
    print(f"[net_shield] Dashboard: {url}")
    if not controller.blocker.admin:
        print("[net_shield] Chưa chạy bằng Administrator -> chặn IP ở chế độ 'logic' "
              "(chỉ cảnh báo). Chạy lại bằng quyền Admin để chặn thật qua Firewall.")
    if open_browser:
        try:
            webbrowser.open(url)
        except Exception:  # noqa: BLE001
            pass
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        controller.stop()
        srv.shutdown()
