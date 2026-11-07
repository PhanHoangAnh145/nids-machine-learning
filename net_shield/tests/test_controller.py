"""Kiểm thử logic tự-chặn của IPS (không cần Npcap, nạp sẵn Prediction giả)."""
import unittest
from net_shield.controller import IPSController
from net_shield.config import IPSConfig
from realtime.flow_tracker import ConnectionRecord
from realtime.engine import Prediction


def pred(src, is_attack=True, cat="dos"):
    c = ConnectionRecord(ts=0, end_ts=0, proto="tcp", src=src, dst="192.168.1.10",
                         sport=1234, dport=80, service="http", flag="S0",
                         src_bytes=0, dst_bytes=0, land=0, urgent=0, logged_in=0)
    return Prediction(c, cat, is_attack, 0.9, {})


class TestController(unittest.TestCase):
    def setUp(self):
        # predictor=object() để khỏi nạp model; ta gọi thẳng on_prediction
        self.c = IPSController(IPSConfig(block_threshold=3, auto_block=True), predictor=object())

    def test_block_after_threshold(self):
        ip = "203.0.113.7"
        for _ in range(2):
            self.c.on_prediction(pred(ip))
        self.assertNotIn(ip, [b["ip"] for b in self.c.blocker.list_blocked()])  # chưa đủ ngưỡng
        self.c.on_prediction(pred(ip))                                          # hit thứ 3
        self.assertIn(ip, [b["ip"] for b in self.c.blocker.list_blocked()])
        self.assertEqual(self.c.stats["attacks"], 3)

    def test_clean_not_blocked(self):
        for _ in range(5):
            self.c.on_prediction(pred("203.0.113.8", is_attack=False, cat="normal"))
        self.assertEqual(self.c.blocker.list_blocked(), [])

    def test_own_ip_whitelisted(self):
        # IP loopback không bao giờ bị chặn dù vượt ngưỡng
        for _ in range(5):
            self.c.on_prediction(pred("127.0.0.1"))
        self.assertNotIn("127.0.0.1", [b["ip"] for b in self.c.blocker.list_blocked()])

    def test_snapshot_shape(self):
        self.c.on_prediction(pred("203.0.113.9"))
        s = self.c.snapshot()
        self.assertIn("stats", s); self.assertIn("alerts", s); self.assertIn("blocked", s)
        self.assertFalseOrTrue = None


if __name__ == "__main__":
    unittest.main()
