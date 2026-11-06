"""Kiểm thử bộ chặn IP (chạy chế độ dry-run, không gọi tường lửa thật)."""
import unittest
from net_shield.blocker import FirewallBlocker


class TestBlocker(unittest.TestCase):
    def setUp(self):
        self.b = FirewallBlocker(whitelist={"10.0.0.1"}, force_dry_run=True)

    def test_block_and_list(self):
        ok, how = self.b.block("203.0.113.9")
        self.assertIn("203.0.113.9", [x["ip"] for x in self.b.list_blocked()])
        self.assertIn("logic", how)   # dry-run

    def test_skip_whitelist_and_loopback(self):
        self.assertTrue(self.b.should_skip("10.0.0.1"))
        self.assertTrue(self.b.should_skip("127.0.0.1"))
        ok, why = self.b.block("127.0.0.1")
        self.assertFalse(ok)

    def test_invalid_ip(self):
        ok, _ = self.b.block("not-an-ip")
        self.assertFalse(ok)

    def test_unblock(self):
        self.b.block("203.0.113.50")
        self.assertTrue(self.b.unblock("203.0.113.50"))
        self.assertEqual(self.b.list_blocked(), [])


if __name__ == "__main__":
    unittest.main()
