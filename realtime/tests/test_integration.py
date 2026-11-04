"""
Kiểm thử tích hợp đầu-cuối: kịch bản -> .pcap -> RealtimeEngine (mô hình THẬT)
-> dự đoán. Kiểm tra tỷ lệ phát hiện của từng kịch bản nằm trong khoảng hợp lý.

Bỏ qua (skip) nếu chưa nạp được model (môi trường không có best_model.joblib).
"""
import os
import tempfile
import unittest

from realtime import pcap_io
from realtime.config import RealtimeConfig
from realtime.engine import RealtimeEngine
from traffic_generator.scenarios import build_scenario


def _engine():
    eng = RealtimeEngine(config=RealtimeConfig(flow_timeout=2.0))
    return eng if eng.predictor is not None else None


def _attack_rate(preds):
    n = len(preds)
    return (sum(1 for p in preds if p.is_attack) / n) if n else 0.0


def _run(name, **kw):
    eng = _engine()
    if eng is None:
        raise unittest.SkipTest("Chưa nạp được model best_model.joblib")
    pkts = build_scenario(name, **kw)
    fd, path = tempfile.mkstemp(suffix=".pcap")
    os.close(fd)
    try:
        pcap_io.write_pcap(path, pkts)
        preds = eng.replay_pcap(path)
    finally:
        os.remove(path)
    return preds


class TestIntegration(unittest.TestCase):
    def test_synflood_detected_as_dos(self):
        preds = _run("synflood", count=300)
        self.assertGreater(len(preds), 100)
        self.assertGreater(_attack_rate(preds), 0.8)
        dos = sum(1 for p in preds if p.category == "dos")
        self.assertGreater(dos / len(preds), 0.8)

    def test_synscan_detected_as_attack(self):
        preds = _run("synscan", count=300)
        self.assertGreater(_attack_rate(preds), 0.7)

    def test_pingflood_runs(self):
        preds = _run("pingflood", count=200)
        self.assertGreater(len(preds), 0)

    def test_normal_low_false_positive(self):
        preds = _run("normal", count=80)
        self.assertGreater(len(preds), 0)
        self.assertLess(_attack_rate(preds), 0.5)   # phần lớn phải là 'an toàn'


if __name__ == "__main__":
    unittest.main()
