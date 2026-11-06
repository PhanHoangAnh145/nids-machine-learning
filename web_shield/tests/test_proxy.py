"""Kiểm thử tích hợp: backend thật + lá chắn, gửi request sạch và độc hại."""
import socket
import time
import unittest
import urllib.request
import urllib.error
from http.server import ThreadingHTTPServer
import threading

from web_shield.config import ShieldConfig
from web_shield.proxy import ShieldServer
from web_shield import demo_backend


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class TestProxy(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bport = _free_port()
        cls.backend = ThreadingHTTPServer(("127.0.0.1", cls.bport), demo_backend._H)
        threading.Thread(target=cls.backend.serve_forever, daemon=True).start()

        cls.pport = _free_port()
        cls.events = []
        cfg = ShieldConfig(listen_host="127.0.0.1", listen_port=cls.pport,
                           upstream_host="127.0.0.1", upstream_port=cls.bport,
                           rate_max=1000)
        cls.shield = ShieldServer(cfg, on_event=cls.events.append)
        cls.shield.start_background()
        time.sleep(0.3)

    @classmethod
    def tearDownClass(cls):
        cls.shield.stop()
        cls.backend.shutdown()

    def _req(self, path, ua="Mozilla/5.0"):
        url = f"http://127.0.0.1:{self.pport}{path}"
        req = urllib.request.Request(url, headers={"User-Agent": ua})
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status, r.read().decode("utf-8", "ignore")
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode("utf-8", "ignore")

    def test_clean_forwarded(self):
        status, body = self._req("/search?q=hello")
        self.assertEqual(status, 200)
        self.assertIn("hello", body)          # backend đã trả lời qua lá chắn

    def test_sqli_blocked(self):
        status, body = self._req("/search?q=1%27%20OR%20%271%27=%271")
        self.assertEqual(status, 403)
        self.assertIn("chặn", body)

    def test_xss_blocked(self):
        status, _ = self._req("/c?m=%3Cscript%3Ealert(1)%3C/script%3E")
        self.assertEqual(status, 403)

    def test_scanner_blocked(self):
        status, _ = self._req("/", ua="sqlmap/1.7")
        self.assertEqual(status, 403)

    def test_stats_increase(self):
        self._req("/search?q=ok")
        self.assertGreater(self.shield.stats["total"], 0)
        self.assertGreater(self.shield.stats["blocked"], 0)


if __name__ == "__main__":
    unittest.main()
