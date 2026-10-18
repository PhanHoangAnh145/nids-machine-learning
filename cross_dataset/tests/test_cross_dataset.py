"""
Kiểm thử nhanh module cross_dataset (không cần tải UNSW-NB15 thật).

    python -m unittest discover -s cross_dataset/tests -t . -v
"""
import hashlib
import os
import shutil
import tempfile
import unittest

import numpy as np
import pandas as pd

from cross_dataset import config as C
from cross_dataset.adapters import get_adapter
from cross_dataset.kdd_feature_builder import build_traffic_features
from cross_dataset.kdd_schema import KDDSchema
from cross_dataset import run_inference

PREP_OK = os.path.exists(C.DEFAULT_PREPROCESSOR_PATH) and os.path.exists(C.DEFAULT_MODEL_PATH)


# ----------------------------------------------------------------------
# Sinh dữ liệu UNSW-NB15 giả lập theo đúng schema phát hành
# ----------------------------------------------------------------------
def make_fake_unsw_raw(n=3000, seed=0) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    cats = np.array(["", "Exploits", "Fuzzers", "Generic", "Reconnaissance", "DoS",
                     "Backdoors", "Analysis", "Shellcode", "Worms"])
    cat = rng.choice(cats, n, p=[.6, .1, .06, .1, .05, .03, .02, .02, .01, .01])
    label = (cat != "").astype(int)
    proto = rng.choice(["tcp", "udp", "icmp", "arp", "ospf"], n, p=[.6, .3, .05, .03, .02])
    df = pd.DataFrame({c: 0 for c in C.UNSW_RAW_COLUMNS}, index=range(n))
    df["srcip"] = rng.choice([f"175.45.176.{i}" for i in range(4)] + ["59.166.0.1"], n)
    df["dstip"] = rng.choice([f"149.171.126.{i}" for i in range(10)], n)
    df["sport"] = rng.integers(1024, 65535, n)
    df["dsport"] = rng.choice(["80", "53", "21", "25", "0x000b", "-", "1234", "443"], n)
    df["proto"] = proto
    df["state"] = rng.choice(["FIN", "INT", "CON", "REQ", "RST", "ECO"], n)
    df["dur"] = rng.exponential(1.0, n)
    df["sbytes"] = rng.integers(0, 5000, n)
    df["dbytes"] = rng.integers(0, 20000, n) * (rng.random(n) > .3)
    df["service"] = rng.choice(["-", "http", "dns", "ftp", "ftp-data", "smtp", "ssh", "pop3", "ssl"], n)
    df["spkts"] = rng.integers(1, 50, n)
    df["dpkts"] = rng.integers(0, 50, n)
    df["stime"] = 1421927414 + np.sort(rng.integers(0, 600, n))
    df["ltime"] = df["stime"] + 1
    df["is_ftp_login"] = (rng.random(n) > .97).astype(int)
    for c in ["ct_srv_src", "ct_srv_dst", "ct_dst_ltm", "ct_src_ltm",
              "ct_src_dport_ltm", "ct_dst_sport_ltm", "ct_dst_src_ltm"]:
        df[c] = rng.integers(1, 60, n)
    df["attack_cat"] = cat
    df["label"] = label
    return df


def make_fake_unsw_partitioned(n=2000, seed=1) -> pd.DataFrame:
    raw = make_fake_unsw_raw(n, seed)
    keep = [c for c in C.UNSW_RAW_COLUMNS
            if c not in ("srcip", "sport", "dstip", "dsport", "stime", "ltime")]
    df = raw[keep].copy()
    df.insert(0, "id", range(1, n + 1))
    df["attack_cat"] = df["attack_cat"].replace("", "Normal")
    return df


def _md5(path):
    with open(path, "rb") as f:
        return hashlib.md5(f.read()).hexdigest()


# ----------------------------------------------------------------------
class TestFeatureBuilder(unittest.TestCase):
    def test_hand_computed_window(self):
        conns = pd.DataFrame({
            "ts":      [0.0, 0.5, 1.0, 1.5, 5.0],
            "dst":     ["A", "A", "A", "B", "A"],
            "sport":   [1, 2, 1, 3, 1],
            "service": ["http", "http", "private", "http", "http"],
            "flag":    ["SF", "S0", "REJ", "SF", "SF"],
        })
        f = build_traffic_features(conns)
        r = f.iloc[2]                      # kết nối thứ 3 tới A lúc t=1.0
        self.assertEqual(r["count"], 3)
        self.assertAlmostEqual(r["serror_rate"], 0.33)
        self.assertAlmostEqual(r["rerror_rate"], 0.33)
        self.assertAlmostEqual(r["same_srv_rate"], 0.33)
        self.assertAlmostEqual(r["dst_host_same_src_port_rate"], 0.67)
        r = f.iloc[3]                      # B lúc t=1.5, service http
        self.assertEqual(r["count"], 1)
        self.assertEqual(r["srv_count"], 3)            # 3 kết nối http trong 2s
        self.assertAlmostEqual(r["srv_diff_host_rate"], 0.67)
        r = f.iloc[4]                      # A lúc t=5.0: cửa sổ 2s đã hết hạn
        self.assertEqual(r["count"], 1)
        self.assertEqual(r["dst_host_count"], 4)       # cửa sổ host vẫn nhớ 4 kết nối
        self.assertEqual(r["dst_host_srv_count"], 3)

    def test_order_independent(self):
        conns = pd.DataFrame({"ts": [3, 1, 2], "dst": ["A"] * 3, "sport": [1, 2, 3],
                              "service": ["http"] * 3, "flag": ["SF"] * 3})
        f = build_traffic_features(conns)
        self.assertListEqual(f["count"].tolist(), [3, 1, 2])


@unittest.skipUnless(PREP_OK, "Cần models/*.joblib")
class TestUNSWAdapter(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.raw_path = os.path.join(cls.tmp, "UNSW-NB15_1.csv")
        make_fake_unsw_raw().to_csv(cls.raw_path, header=False, index=False)
        cls.part_path = os.path.join(cls.tmp, "UNSW_NB15_testing-set.csv")
        make_fake_unsw_partitioned().to_csv(cls.part_path, index=False)
        cls.schema = KDDSchema.from_preprocessor(C.DEFAULT_PREPROCESSOR_PATH)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def _check(self, path, expected_format):
        ad = get_adapter("unsw-nb15")
        df = ad.run([path])
        self.assertEqual(ad.format, expected_format)
        aligned = self.schema.align(df)
        self.assertListEqual(list(aligned.columns), self.schema.feature_names)
        X = self.schema.transform(aligned)
        self.assertEqual(X.shape[1], 122)
        self.assertFalse(np.isnan(X).any())
        self.assertTrue(set(df["attack_category"]) <= set(self.schema.class_labels))
        self.assertTrue(set(df["service"]) <= set(self.schema.vocab["service"]))
        self.assertTrue(set(df["flag"]) <= set(self.schema.vocab["flag"]))
        self.assertEqual(set(ad.provenance), set(self.schema.feature_names))
        return df

    def test_raw_format(self):
        df = self._check(self.raw_path, "raw")
        self.assertTrue((df["source_label"] == "normal").any())
        self.assertLessEqual(df["dst_host_count"].max(), 255)

    def test_partitioned_format(self):
        self._check(self.part_path, "partitioned")

    def test_end_to_end_and_legacy_untouched(self):
        legacy = [os.path.join(C.PROJECT_ROOT, p) for p in (
            "models/best_model.joblib", "models/preprocessor.joblib",
            "models/evaluation_results.json", "src/preprocess.py", "src/train.py",
            "src/predictor.py", "main.py")]
        before = {p: _md5(p) for p in legacy if os.path.exists(p)}
        rep = run_inference.main(["--dataset", "unsw-nb15", "--input", self.raw_path,
                                  "--out", os.path.join(self.tmp, "reports"), "--no-plots"])
        self.assertIn("binary", rep["metrics"])
        after = {p: _md5(p) for p in before}
        self.assertEqual(before, after, "Luồng cũ bị thay đổi!")

    def test_refuse_writing_into_models(self):
        with self.assertRaises(SystemExit):
            run_inference.main(["--dataset", "unsw-nb15", "--input", self.raw_path,
                                "--out", C.LEGACY_MODELS_DIR, "--no-plots"])


if __name__ == "__main__":
    unittest.main()
