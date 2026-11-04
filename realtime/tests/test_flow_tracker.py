"""Kiểm thử máy trạng thái gom luồng và suy cờ NSL-KDD."""
import unittest

from realtime.flow_tracker import FlowTracker
from realtime.packet import PacketMeta

SYN = frozenset({"S"})
SYNACK = frozenset({"S", "A"})
ACK = frozenset({"A"})
PSHACK = frozenset({"P", "A"})
FINACK = frozenset({"F", "A"})
RSTACK = frozenset({"R", "A"})


def tcp(ts, src, dst, sp, dp, fl, length=0):
    return PacketMeta(ts=ts, proto="tcp", src_ip=src, dst_ip=dst,
                      sport=sp, dport=dp, length=length, tcp_flags=fl)


class TestFlag(unittest.TestCase):
    def _one(self, packets, timeout=2.0):
        ft = FlowTracker(flow_timeout=timeout)
        recs = []
        for p in packets:
            recs += ft.ingest(p)
        recs += ft.flush()
        self.assertEqual(len(recs), 1, "phải sinh đúng 1 kết nối")
        return recs[0]

    def test_sf_normal_session(self):
        a, b = "10.0.0.9", "10.0.0.1"
        pk = [
            tcp(0.0, a, b, 5000, 80, SYN),
            tcp(0.01, b, a, 80, 5000, SYNACK),
            tcp(0.02, a, b, 5000, 80, ACK),
            tcp(0.03, a, b, 5000, 80, PSHACK, length=200),
            tcp(0.04, b, a, 80, 5000, PSHACK, length=1500),
            tcp(0.05, a, b, 5000, 80, FINACK),
            tcp(0.06, b, a, 80, 5000, FINACK),
            tcp(0.07, a, b, 5000, 80, ACK),
        ]
        r = self._one(pk)
        self.assertEqual(r.flag, "SF")
        self.assertEqual(r.service, "http")
        self.assertEqual(r.src, a)
        self.assertEqual(r.dst, b)
        self.assertEqual(r.src_bytes, 200)
        self.assertEqual(r.dst_bytes, 1500)

    def test_s0_synflood(self):
        # SYN không hồi đáp -> S0
        r = self._one([tcp(0.0, "10.0.0.9", "10.0.0.1", 6000, 80, SYN)])
        self.assertEqual(r.flag, "S0")

    def test_rej_closed_port(self):
        # SYN -> RST từ bên nhận -> REJ (cổng đóng)
        pk = [
            tcp(0.0, "10.0.0.9", "10.0.0.1", 7000, 81, SYN),
            tcp(0.001, "10.0.0.1", "10.0.0.9", 81, 7000, RSTACK),
        ]
        self.assertEqual(self._one(pk).flag, "REJ")

    def test_s1_established_no_close(self):
        pk = [
            tcp(0.0, "10.0.0.9", "10.0.0.1", 8000, 22, SYN),
            tcp(0.01, "10.0.0.1", "10.0.0.9", 22, 8000, SYNACK),
            tcp(0.02, "10.0.0.9", "10.0.0.1", 8000, 22, ACK),
            tcp(0.03, "10.0.0.9", "10.0.0.1", 8000, 22, PSHACK, length=10),
        ]
        self.assertEqual(self._one(pk).flag, "S1")

    def test_rsto_originator_reset(self):
        pk = [
            tcp(0.0, "10.0.0.9", "10.0.0.1", 9000, 80, SYN),
            tcp(0.01, "10.0.0.1", "10.0.0.9", 80, 9000, SYNACK),
            tcp(0.02, "10.0.0.9", "10.0.0.1", 9000, 80, ACK),
            tcp(0.03, "10.0.0.9", "10.0.0.1", 9000, 80, RSTACK),
        ]
        self.assertEqual(self._one(pk).flag, "RSTO")

    def test_udp_is_sf(self):
        r = self._one([PacketMeta(ts=0.0, proto="udp", src_ip="10.0.0.1",
                                  dst_ip="8.8.8.8", sport=5353, dport=53, length=40)])
        self.assertEqual(r.flag, "SF")
        self.assertEqual(r.service, "domain_u")

    def test_land_flag(self):
        r = self._one([tcp(0.0, "10.0.0.1", "10.0.0.1", 80, 80, SYN)])
        self.assertEqual(r.land, 1)

    def test_timeout_closes_flow(self):
        ft = FlowTracker(flow_timeout=2.0)
        recs = ft.ingest(tcp(0.0, "10.0.0.9", "10.0.0.1", 5000, 80, SYN))
        self.assertEqual(recs, [])
        # gói mới sau 3s của flow khác -> flow cũ hết hạn và được đóng
        recs = ft.ingest(tcp(3.0, "10.0.0.8", "10.0.0.1", 5001, 80, SYN))
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0].flag, "S0")


if __name__ == "__main__":
    unittest.main()
