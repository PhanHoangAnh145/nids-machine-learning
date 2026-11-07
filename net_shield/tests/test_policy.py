"""Kiểm thử chính sách chặn thông minh, tự gỡ chặn, bảng thiết bị, phát lại pcap.

Không cần Npcap/quyền Admin: dùng Prediction giả và bộ chặn dry-run.
"""
import os
import unittest

from net_shield.blocker import FirewallBlocker
from net_shield.config import IPSConfig
from net_shield.controller import IPSController, attack_prob, is_lan_ip, list_pcaps
from realtime.engine import Prediction
from realtime.flow_tracker import ConnectionRecord


def pred(src, ts=0.0, is_attack=True, p_normal=0.05, dst="192.168.1.10", cat="dos"):
    c = ConnectionRecord(ts=ts, end_ts=ts, proto="tcp", src=src, dst=dst,
                         sport=1234, dport=80, service="http", flag="S0",
                         src_bytes=0, dst_bytes=0, land=0, urgent=0, logged_in=0)
    probs = {"normal": p_normal, cat: 1 - p_normal}
    return Prediction(c, cat if is_attack else "normal", is_attack, max(probs.values()), probs)


def make(**kw):
    cfg = IPSConfig(**{"block_threshold": 3, "block_window": 30.0, "min_attack_prob": 0.6,
                       "block_ttl": 600.0, **kw})
    c = IPSController(cfg, predictor=object())
    c.blocker = FirewallBlocker(whitelist=c.blocker.whitelist, force_dry_run=True)
    return c


def blocked(c):
    return [b["ip"] for b in c.blocker.list_blocked()]


class TestSmartBlocking(unittest.TestCase):
    def test_attack_prob_uses_one_minus_normal(self):
        # mô hình phân vân dos/probe (0.45/0.45) nhưng P(normal)=0.1 -> P(tấn công)=0.9
        p = Prediction(None, "dos", True, 0.45, {"dos": 0.45, "probe": 0.45, "normal": 0.1})
        self.assertAlmostEqual(attack_prob(p), 0.9)

    def test_low_probability_not_counted(self):
        c = make()
        for i in range(10):
            c.on_prediction(pred("203.0.113.1", ts=i, p_normal=0.55))   # P(tấn công)=45%
        self.assertEqual(blocked(c), [])
        self.assertEqual(c.stats["attacks"], 0)
        self.assertEqual(c.stats["suspects"], 10)

    def test_burst_inside_window_blocks(self):
        c = make()
        for i in range(3):
            c.on_prediction(pred("203.0.113.2", ts=100 + i))
        self.assertIn("203.0.113.2", blocked(c))

    def test_sparse_hits_outside_window_not_blocked(self):
        c = make()
        for i in range(10):                                 # 1 lần mỗi 60s, cửa sổ 30s
            c.on_prediction(pred("203.0.113.3", ts=i * 60))
        self.assertNotIn("203.0.113.3", blocked(c))
        self.assertEqual(c.stats["attacks"], 10)

    def test_auto_block_off(self):
        c = make(auto_block=False)
        for i in range(5):
            c.on_prediction(pred("203.0.113.4", ts=i))
        self.assertEqual(blocked(c), [])

    def test_attacks_table_only_attacks(self):
        c = make()
        for i in range(5):
            c.on_prediction(pred("192.168.1.20", ts=i, is_attack=False, p_normal=0.95))
        c.on_prediction(pred("203.0.113.5", ts=10))
        s = c.snapshot()
        self.assertEqual(len(s["attacks"]), 1)
        self.assertTrue(all(a["is_attack"] for a in s["attacks"]))


class TestExpiry(unittest.TestCase):
    def test_ttl_unblocks(self):
        c = make(block_ttl=60)
        for i in range(3):
            c.on_prediction(pred("203.0.113.6", ts=i))
        self.assertIn("203.0.113.6", blocked(c))
        t0 = c.blocker._blocked["203.0.113.6"]["ts"]
        c._maintain(t0 + 30)
        self.assertIn("203.0.113.6", blocked(c))
        c._maintain(t0 + 61)
        self.assertNotIn("203.0.113.6", blocked(c))

    def test_ttl_zero_is_permanent(self):
        b = FirewallBlocker(force_dry_run=True)
        b.block("203.0.113.7")
        self.assertEqual(b.expire(0, now=10 ** 12), [])

    def test_simulated_cleared_on_reset(self):
        c = make()
        c._simulate = True
        for i in range(3):
            c.on_prediction(pred("10.0.0.9", ts=i))
        self.assertTrue(c.blocker.list_blocked()[0]["simulated"])
        c._simulate = False
        ok, _ = c.reset()
        self.assertTrue(ok)
        self.assertEqual(blocked(c), [])
        self.assertEqual(c.stats["connections"], 0)


class TestDevices(unittest.TestCase):
    def test_lan_detection(self):
        self.assertTrue(is_lan_ip("192.168.137.5"))
        self.assertTrue(is_lan_ip("10.28.188.90"))
        self.assertFalse(is_lan_ip("8.8.8.8"))
        self.assertFalse(is_lan_ip("239.255.255.250"))   # multicast
        self.assertFalse(is_lan_ip("169.254.1.1"))       # link-local
        self.assertFalse(is_lan_ip("192.168.1.255"))     # broadcast

    def test_device_table(self):
        c = make()
        c.on_prediction(pred("192.168.137.20", ts=0, is_attack=False, p_normal=0.9,
                             dst="142.250.1.1"))
        for i in range(3):
            c.on_prediction(pred("192.168.137.66", ts=i, dst="192.168.137.20"))
        devs = {d["ip"]: d for d in c.snapshot()["devices"]}
        self.assertNotIn("142.250.1.1", devs)                 # Internet sạch: không liệt kê
        self.assertEqual(devs["192.168.137.66"]["status"], "đã chặn")
        self.assertEqual(devs["192.168.137.66"]["attacks_sent"], 3)
        self.assertEqual(devs["192.168.137.20"]["attacks_recv"], 3)
        self.assertEqual(devs["192.168.137.20"]["status"], "bình thường")

    def test_external_attacker_listed(self):
        c = make()
        c.on_prediction(pred("45.33.32.156", ts=0))
        devs = {d["ip"]: d for d in c.snapshot()["devices"]}
        self.assertIn("45.33.32.156", devs)
        self.assertFalse(devs["45.33.32.156"]["lan"])


class TestReplay(unittest.TestCase):
    def test_list_pcaps_finds_templates(self):
        names = list(list_pcaps().keys())
        self.assertTrue(any(n.endswith("dos_attack.pcap") for n in names), names)

    def test_replay_rejects_missing_file_and_running(self):
        c = make()
        ok, _ = c.replay(os.path.join("khong", "co.pcap"))
        self.assertFalse(ok)
        c.running = True
        ok, _ = c.replay(next(iter(list_pcaps().values())))
        self.assertFalse(ok)


class TestFalsePositiveFixes(unittest.TestCase):
    def test_self_outbound_not_counted(self):
        c = make()
        c.self_ips.add("10.28.188.90")
        for i in range(30):                     # trình duyệt: SYN không được trả lời (S0)
            c.on_prediction(pred("10.28.188.90", ts=i * 0.1, dst="57.145.12.1"))
        self.assertEqual(c.stats["attacks"], 0)
        self.assertEqual(c.stats["suspects"], 30)
        dev = {d["ip"]: d for d in c.snapshot()["devices"]}["10.28.188.90"]
        self.assertEqual(dev["status"], "bình thường")

    def test_default_policy_needs_attack_rate(self):
        c = IPSController(IPSConfig(), predictor=object())     # mặc định: 20 lần / 5s
        c.blocker = FirewallBlocker(whitelist=c.blocker.whitelist, force_dry_run=True)
        for i in range(40):                     # ~2 kết nối/giây kiểu trình duyệt
            c.on_prediction(pred("192.168.137.30", ts=i * 0.5))
        self.assertEqual(blocked(c), [])
        for i in range(25):                     # flood: 25 kết nối trong 0.1s
            c.on_prediction(pred("192.168.137.66", ts=100 + i * 0.004))
        self.assertEqual(blocked(c), ["192.168.137.66"])

    def test_broadcast_only_devices_hidden_flag(self):
        c = make()
        c.on_prediction(pred("10.28.188.55", is_attack=False, p_normal=0.9, dst="239.255.255.250"))
        c.on_prediction(pred("10.28.188.56", is_attack=False, p_normal=0.9, dst="10.28.188.255"))
        c.on_prediction(pred("10.28.188.57", is_attack=False, p_normal=0.9, dst="10.28.188.90"))
        devs = {d["ip"]: d for d in c.snapshot()["devices"]}
        self.assertFalse(devs["10.28.188.55"]["unicast"])
        self.assertFalse(devs["10.28.188.56"]["unicast"])
        self.assertTrue(devs["10.28.188.57"]["unicast"])
        self.assertEqual(c.stats["broadcast_only"], 2)


if __name__ == "__main__":
    unittest.main()
