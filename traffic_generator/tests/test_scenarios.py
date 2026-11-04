"""Kiểm thử hình dạng các kịch bản sinh lưu lượng."""
import unittest

from traffic_generator.scenarios import build_scenario, SCENARIOS


class TestScenarios(unittest.TestCase):
    def test_all_sorted_by_time(self):
        for name in SCENARIOS:
            pkts = build_scenario(name, count=50)
            ts = [p.ts for p in pkts]
            self.assertTrue(all(ts[i] <= ts[i + 1] for i in range(len(ts) - 1)),
                            f"{name} phải tăng dần theo thời gian")
            self.assertGreater(len(pkts), 0)

    def test_synflood_all_syn_no_reply(self):
        pkts = build_scenario("synflood", count=100)
        self.assertTrue(all(p.proto == "tcp" and p.is_pure_syn for p in pkts))
        # tất cả đi cùng một chiều (atk -> tgt)
        self.assertEqual(len({p.src_ip for p in pkts}), 1)

    def test_synscan_hits_many_ports(self):
        pkts = build_scenario("synscan", count=100)
        dports = {p.dport for p in pkts if p.is_pure_syn}
        self.assertGreaterEqual(len(dports), 90)

    def test_pingflood_icmp(self):
        pkts = build_scenario("pingflood", count=50)
        self.assertTrue(all(p.proto == "icmp" for p in pkts))


if __name__ == "__main__":
    unittest.main()
