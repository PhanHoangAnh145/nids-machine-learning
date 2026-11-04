"""Kiểm thử sinh 41 cột NSL-KDD từ ConnectionRecord."""
import unittest

from realtime.config import FEATURE_NAMES
from realtime.feature_adapter import FeatureAdapter
from realtime.flow_tracker import ConnectionRecord


def rec(ts, dst, sport, service, flag, proto="tcp"):
    return ConnectionRecord(ts=ts, end_ts=ts, proto=proto, src="10.0.0.9", dst=dst,
                            sport=sport, dport=80, service=service, flag=flag,
                            src_bytes=100, dst_bytes=200, land=0, urgent=0, logged_in=0)


class TestFeatureAdapter(unittest.TestCase):
    def test_columns_exact(self):
        fa = FeatureAdapter()
        df = fa.to_kdd_frame([rec(0.0, "10.0.0.1", 5000, "http", "SF")])
        self.assertEqual(list(df.columns), FEATURE_NAMES)
        self.assertEqual(len(df), 1)

    def test_synflood_counts_and_serror(self):
        # 50 kết nối S0 cùng dst trong < 2s -> count cao, serror_rate = 1.0
        fa = FeatureAdapter()
        recs = [rec(i * 0.001, "10.0.0.1", 1024 + i, "http", "S0") for i in range(50)]
        df = fa.to_kdd_frame(recs)
        last = df.iloc[-1]
        self.assertGreaterEqual(last["count"], 50)
        self.assertEqual(last["serror_rate"], 1.0)
        self.assertEqual(last["dst_host_serror_rate"], 1.0)

    def test_empty(self):
        fa = FeatureAdapter()
        df = fa.to_kdd_frame([])
        self.assertEqual(list(df.columns), FEATURE_NAMES)
        self.assertEqual(len(df), 0)


if __name__ == "__main__":
    unittest.main()
