"""
Web server cho dashboard IPS: phục vụ trang dashboard + API JSON.
Chỉ dùng thư viện chuẩn (http.server). Trang web tự gọi /api/* để cập nhật.

Mặc định chỉ mở ở 127.0.0.1 (chỉ máy chạy shield xem được). Với cfg.allow_lan
(hoặc cờ --lan) thì bind 0.0.0.0 để máy khác cùng mạng mở được, và BẮT BUỘC có
mật khẩu (Basic Auth) vì dashboard có các nút điều khiển thật (Bắt đầu/Dừng/Gỡ
chặn). Mật khẩu để trống -> tự sinh ngẫu nhiên và in ra console.
Lưu ý: Basic Auth trên HTTP thường không mã hoá đường truyền (không có HTTPS),
đủ cho phòng lab; không dùng cho Internet công khai.
"""
from __future__ import annotations

import base64
import hmac
import json
import os
import secrets
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from .config import IPSConfig
from .controller import IPSController, list_ifaces, list_pcaps, local_ips

_HTML = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dashboard.html")


def _norm(s) -> str:
    return " ".join(str(s).split())


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    # ---- xác thực -----------------------------------------------------
    def _authed(self) -> bool:
        pw = self.server.password
        if not pw:
            return True
        hdr = self.headers.get("Authorization", "")
        if hdr.startswith("Basic "):
            try:
                _, _, got = base64.b64decode(hdr[6:]).decode("utf-8").partition(":")
                if hmac.compare_digest(got, pw):
                    return True
            except Exception:  # noqa: BLE001
                pass
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="NIDS SHIELD"')
        self.send_header("Content-Length", "0")
        self.send_header("Connection", "close")
        self.end_headers()
        return False

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
        if not self._authed():
            return
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
        if not self._authed():
            return
        path = urlparse(self.path).path
        srv = self.server
        body = self._body()
        if path == "/api/start":
            label = body.get("iface", "")
            iface = srv.iface_map.get(label)
            if iface is None:
                for k, v in srv.iface_map.items():
                    if _norm(k) == _norm(label):
                        iface = v
                        break
                else:
                    iface = label
            ok, msg = srv.controller.start(iface)
            self._json({"ok": ok, "msg": msg})
        elif path == "/api/replay":
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

    def __init__(self, cfg: IPSConfig, controller: IPSController, bind_host: str, password: str):
        super().__init__((bind_host, cfg.dashboard_port), _Handler)
        self.controller = controller
        self.password = password
        self.iface_map = {}
        self.pcap_map = {}


def run(cfg: IPSConfig = None, open_browser: bool = True):
    cfg = cfg or IPSConfig()
    controller = IPSController(cfg)

    if cfg.allow_lan:
        bind_host = "0.0.0.0"
        password = cfg.dashboard_password or secrets.token_hex(3)
    else:
        bind_host = cfg.dashboard_host
        password = cfg.dashboard_password

    srv = DashboardServer(cfg, controller, bind_host, password)
    local_url = f"http://{cfg.dashboard_host}:{cfg.dashboard_port}"
    print(f"[net_shield] Dashboard (máy này): {local_url}")

    if cfg.allow_lan:
        print("[net_shield] Mở cho máy khác cùng mạng. Dùng một trong các địa chỉ:")
        for ip in sorted(local_ips()):
            if not ip.startswith("127."):
                print(f"[net_shield]   http://{ip}:{cfg.dashboard_port}")
        print(f"[net_shield] Đăng nhập — user: bất kỳ, mật khẩu: {password}")
        print("[net_shield] (Basic Auth trên HTTP không mã hoá — chỉ dùng trong mạng lab.)")
        print("[net_shield] Máy khác không mở được? Windows Firewall hỏi 'Allow access' "
              "-> tick Private networks.")

    if not controller.blocker.admin:
        print("[net_shield] Chưa chạy bằng Administrator -> chặn IP ở chế độ 'logic' "
              "(chỉ cảnh báo). Chạy lại bằng quyền Admin để chặn thật qua Firewall.")
    if open_browser:
        try:
            webbrowser.open(local_url)
        except Exception:  # noqa: BLE001
            pass
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        controller.stop()
        srv.shutdown()
