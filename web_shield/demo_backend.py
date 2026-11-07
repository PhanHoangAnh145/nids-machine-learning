"""
Web server MẪU để thử lá chắn (đóng vai "web thật" nằm sau proxy).

    python -m web_shield.demo_backend           # chạy ở 127.0.0.1:8000

Trang đơn giản có ô tìm kiếm để bạn thử gửi request sạch và request độc hại
qua lá chắn.
"""
from __future__ import annotations

import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, parse_qs

PAGE = """<!doctype html><html lang='vi'><meta charset='utf-8'>
<title>Web demo</title>
<body style='font-family:system-ui;max-width:640px;margin:40px auto'>
<h2>🌐 Web server mẫu (sau lá chắn)</h2>
<form method='get' action='/search'>
  <input name='q' placeholder='Nhập từ khoá...' style='padding:8px;width:70%'>
  <button>Tìm</button>
</form>
<p>Bạn tìm: <b>{q}</b></p>
<p style='color:#888'>Nếu thấy trang này tức là request đã qua lá chắn an toàn.</p>
</body></html>"""


class _H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def do_GET(self):
        q = parse_qs(urlsplit(self.path).query).get("q", [""])[0]
        html = PAGE.format(q=q).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(html)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(html)

    do_POST = do_GET


def main(host="127.0.0.1", port=8000):
    srv = ThreadingHTTPServer((host, port), _H)
    print(f"[demo_backend] chạy tại http://{host}:{port}  (Ctrl+C để dừng)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        srv.shutdown()
    return 0


if __name__ == "__main__":
    p = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    sys.exit(main(port=p))
