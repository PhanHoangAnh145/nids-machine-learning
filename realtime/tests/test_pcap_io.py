"""Kiểm thử đọc/ghi pcap thuần Python: round-trip không mất thông tin."""
import os
import tempfile
import unittest

from realtime import pcap_io
from realtime.packet import PacketMeta


class TestPcapIO(unittest.TestCase):
    def test_round_trip(self):
        pkts = [
            PacketMeta(ts=1.5, proto="tcp", src_ip="10.0.0.9", dst_ip="10.0.0.1",
                       sport=5000, dport=80, length=120, tcp_flags=frozenset({"S", "A"})),
            PacketMeta(ts=1.6, proto="udp", src_ip="10.0.0.1", dst_ip="8.8.8.8",
                       sport=5353, dport=53, length=40),
            PacketMeta(ts=1.7, proto="icmp", src_ip="10.0.0.9", dst_ip="10.0.0.1", length=56),
        ]
        fd, path = tempfile.mkstemp(suffix=".pcap")
        os.close(fd)
        try:
            pcap_io.write_pcap(path, pkts)
            back = pcap_io.read_pcap(path)
            self.assertEqual(len(back), 3)
            self.assertEqual(back[0].proto, "tcp")
            self.assertEqual(back[0].src_ip, "10.0.0.9")
            self.assertEqual(back[0].dport, 80)
            self.assertEqual(back[0].length, 120)
            self.assertIn("S", back[0].tcp_flags)
            self.assertIn("A", back[0].tcp_flags)
            self.assertEqual(back[1].proto, "udp")
            self.assertEqual(back[1].dport, 53)
            self.assertEqual(back[1].length, 40)
            self.assertEqual(back[2].proto, "icmp")
            self.assertAlmostEqual(back[0].ts, 1.5, places=5)
        finally:
            os.remove(path)


if __name__ == "__main__":
    unittest.main()
