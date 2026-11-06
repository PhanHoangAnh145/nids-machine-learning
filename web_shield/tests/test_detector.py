"""Kiểm thử bộ phát hiện tấn công web (thuần, không cần mạng)."""
import unittest
from web_shield.detector import WebDetector


class TestDetector(unittest.TestCase):
    def setUp(self):
        self.d = WebDetector(rate_window=10, rate_max=5, block_seconds=30)

    def _get(self, path="/", query="", ua="Mozilla/5.0", body=b"", ip="1.2.3.4"):
        return self.d.inspect(ip, "GET", path, query, {"user-agent": ua}, body)

    def test_clean(self):
        v = self._get("/search", "q=hello")
        self.assertTrue(v.allowed)
        self.assertEqual(v.category, "Sạch")

    def test_sqli(self):
        v = self._get("/search", "q=1' OR '1'='1")
        self.assertFalse(v.allowed)
        self.assertEqual(v.category, "SQLi")

    def test_sqli_union_encoded(self):
        v = self._get("/p", "id=1%20UNION%20SELECT%20password%20FROM%20users")
        self.assertFalse(v.allowed)
        self.assertEqual(v.category, "SQLi")

    def test_xss(self):
        v = self._get("/c", "m=<script>alert(1)</script>")
        self.assertFalse(v.allowed)
        self.assertEqual(v.category, "XSS")

    def test_path_traversal(self):
        v = self._get("/../../etc/passwd")
        self.assertFalse(v.allowed)
        self.assertEqual(v.category, "Path Traversal")

    def test_scanner_ua_blocks_ip(self):
        v = self._get("/", ua="sqlmap/1.7")
        self.assertFalse(v.allowed)
        self.assertEqual(v.category, "Scanner")
        self.assertTrue(self.d.is_ip_blocked("1.2.3.4"))

    def test_rate_limit_flood(self):
        cats = []
        for _ in range(8):     # rate_max=5 -> vượt ngưỡng sẽ bị chặn
            v = self._get("/", "q=ok", ip="9.9.9.9")
            cats.append(v.category)
        # Lần vượt ngưỡng đầu tiên báo DoS/Flood; các lần sau IP đã bị chặn
        self.assertIn("DoS/Flood", cats)
        self.assertFalse(self._get("/", "q=ok", ip="9.9.9.9").allowed)
        self.assertTrue(self.d.is_ip_blocked("9.9.9.9"))


if __name__ == "__main__":
    unittest.main()
