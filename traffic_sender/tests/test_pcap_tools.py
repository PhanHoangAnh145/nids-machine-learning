"""
Kiểm thử logic sinh biến thể pcap. Bỏ qua nếu máy chưa cài Scapy.
"""
import os
import time
import unittest

try:
    import scapy  # noqa: F401
    HAS_SCAPY = True
except Exception:       # noqa: BLE001
    HAS_SCAPY = False

from traffic_sender import pcap_tools as pt


@unittest.skipUnless(HAS_SCAPY, "cần Scapy")
class TestMutate(unittest.TestCase):
    def test_templates_present(self):
        tpls = pt.list_templates()
        self.assertIn("A - DoS / SYN Flood", tpls)
        self.assertIn("B - Port Scanning", tpls)
        self.assertIn("C - Web Request (HTTP)", tpls)

    def test_mutate_dos(self):
        from scapy.all import rdpcap, Ether, IP, TCP
        opt = pt.MutateOptions(randomize_src=False, src_ip="10.0.0.77",
                               dst_ip="192.168.1.50", reset_time=True,
                               recompute_checksum=True)
        out = pt.mutate_template("A - DoS / SYN Flood", opt)
        self.addCleanup(lambda: os.path.exists(out) and os.remove(out))
        self.assertTrue(os.path.exists(out))
        self.assertIn("generated_dos_attack_", os.path.basename(out))

        pk = rdpcap(out)
        self.assertGreater(len(pk), 0)
        # timestamp mới
        self.assertLess(abs(float(pk[0].time) - time.time()), 10)
        # IP nguồn/đích đã đổi; checksum tính lại (khác 0 sau khi build)
        first = Ether(bytes(pk[0]))
        self.assertEqual(first[IP].src, "10.0.0.77")
        self.assertEqual(first[IP].dst, "192.168.1.50")
        self.assertNotEqual(first[IP].chksum, 0)
        self.assertNotEqual(first[TCP].chksum, 0)

    def test_output_naming(self):
        opt = pt.MutateOptions()
        out = pt.mutate_template("B - Port Scanning", opt)
        self.addCleanup(lambda: os.path.exists(out) and os.remove(out))
        self.assertTrue(os.path.basename(out).endswith(".pcap"))
        self.assertIn("generated_port_scan_", os.path.basename(out))


if __name__ == "__main__":
    unittest.main()
