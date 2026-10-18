"""
Adapter UNSW-NB15 -> không gian đặc trưng NSL-KDD (41 cột).

Hỗ trợ 2 định dạng phát hành chính thức của UNSW-NB15 (tự nhận diện):

  [A] File GỐC  UNSW-NB15_1.csv ... UNSW-NB15_4.csv  (~2.54 triệu dòng, KHÔNG header,
      49 cột, có srcip/dstip/sport/dsport/stime)
      -> 19 đặc trưng traffic/host được TÍNH LẠI đúng định nghĩa KDD bằng
         kdd_feature_builder (độ trung thực CAO). Khuyến nghị dùng.

  [B] File CHIA SẴN  UNSW_NB15_training-set.csv / UNSW_NB15_testing-set.csv
      (~257 nghìn dòng, CÓ header, 45 cột, KHÔNG có IP/thời gian)
      -> 19 đặc trưng traffic/host được XẤP XỈ từ các cột ct_* (độ trung thực THẤP hơn).

Lưu ý quan trọng khi viết báo cáo:
  * 13 đặc trưng "content" của KDD (hot, num_failed_logins, root_shell, ...) cần
    phân tích payload/phiên đăng nhập, UNSW-NB15 không cung cấp -> gán 0.
  * Nhãn 9 nhóm tấn công UNSW được quy về 5 lớp KDD theo ngữ nghĩa (config.py);
    chỉ số NHỊ PHÂN (Normal vs Attack) là thước đo công bằng nhất.
"""
from typing import Sequence

import numpy as np
import pandas as pd

from .. import config as C
from ..kdd_feature_builder import TRAFFIC_FEATURES, build_traffic_features
from .base import (
    APPROX, COMPUTED, CONSTANT, EXACT, HEURISTIC, BaseAdapter, register_adapter,
)

# 13 đặc trưng content mà UNSW-NB15 không có thông tin tương ứng
_CONTENT_ZERO = [
    "wrong_fragment", "urgent", "hot", "num_failed_logins", "num_compromised",
    "root_shell", "su_attempted", "num_root", "num_file_creations", "num_shells",
    "num_access_files", "num_outbound_cmds", "is_host_login", "is_guest_login",
]


def _parse_port(series: pd.Series) -> pd.Series:
    """Cổng trong UNSW gốc có thể là số, hex ('0x000b') hoặc '-'."""
    def conv(v):
        try:
            return int(str(v).strip(), 0)
        except (ValueError, TypeError):
            try:
                return int(float(v))
            except (ValueError, TypeError):
                return -1
    return series.map(conv).astype("int64")


@register_adapter("unsw-nb15")
class UNSWNB15Adapter(BaseAdapter):
    """
    Tùy chọn (truyền qua get_adapter(..., **options)):
        unknown_service : service gán khi không suy ra được (mặc định 'other')
        logged_in_heuristic : bật/tắt luật suy luận logged_in (mặc định True)
    """

    def __init__(self, **options):
        super().__init__(**options)
        self.format = None

    # ------------------------------------------------------------------
    # 1. LOAD
    # ------------------------------------------------------------------
    @staticmethod
    def _detect_format(path: str) -> str:
        with open(path, "r", encoding="latin-1", errors="replace") as f:
            first = f.readline().lower()
        return "partitioned" if "attack_cat" in first else "raw"

    def load(self, paths: Sequence[str]) -> pd.DataFrame:
        if not paths:
            raise ValueError("Chưa truyền file UNSW-NB15 nào.")
        formats = {self._detect_format(p) for p in paths}
        if len(formats) > 1:
            raise ValueError("Không trộn file gốc [A] với file chia sẵn [B] trong cùng một lần chạy.")
        self.format = formats.pop()

        frames = []
        for p in paths:
            if self.format == "raw":
                df = pd.read_csv(p, header=None, names=C.UNSW_RAW_COLUMNS,
                                 low_memory=False, encoding="latin-1")
            else:
                df = pd.read_csv(p, low_memory=False, encoding="latin-1")
                df.columns = [c.strip().lower() for c in df.columns]
            frames.append(df)
        raw = pd.concat(frames, ignore_index=True)

        # Chuẩn hóa chuỗi
        raw["proto"] = raw["proto"].astype(str).str.strip().str.lower()
        raw["service"] = raw["service"].astype(str).str.strip().str.lower()
        raw["state"] = raw["state"].astype(str).str.strip().str.upper()
        num_cols = ["dur", "sbytes", "dbytes", "spkts", "dpkts", "is_ftp_login",
                    "is_sm_ips_ports", "label", "ct_srv_src", "ct_srv_dst",
                    "ct_dst_ltm", "ct_src_dport_ltm", "ct_dst_sport_ltm", "stime"]
        for c in num_cols:
            if c in raw.columns:
                raw[c] = pd.to_numeric(raw[c], errors="coerce").fillna(0)

        cat = raw["attack_cat"].astype(str).str.strip().str.lower()
        cat = cat.replace({"nan": "", "-": ""})
        cat = np.where((cat == "") | (raw["label"] == 0), "normal", cat)
        raw["attack_cat_norm"] = cat
        return raw

    # ------------------------------------------------------------------
    # 2. CÁC HÀM ÁNH XẠ TỪNG NHÓM
    # ------------------------------------------------------------------
    def _map_service(self, raw: pd.DataFrame) -> pd.Series:
        unknown_default = self.options.get("unknown_service", C.UNKNOWN_SERVICE_DEFAULT)
        ports = raw["dsport_int"] if "dsport_int" in raw.columns else pd.Series(-1, index=raw.index)
        out = []
        for svc, proto, port in zip(raw["service"], raw["proto"], ports):
            kdd = None
            if svc == "dns":
                kdd = "domain_u" if proto == "udp" else "domain"
            elif svc in C.UNSW_SERVICE_TO_KDD:
                kdd = C.UNSW_SERVICE_TO_KDD[svc]
            if kdd is None and port >= 0:
                kdd = C.PORT_TO_KDD_SERVICE_PROTO.get((proto, port)) or C.PORT_TO_KDD_SERVICE.get(port)
            if kdd is None:
                kdd = C.UNKNOWN_SERVICE_BY_PROTO.get(proto, unknown_default)
            out.append(kdd)
        return pd.Series(out, index=raw.index)

    @staticmethod
    def _map_flag(raw: pd.DataFrame) -> pd.Series:
        out = []
        for proto, state, dpkts, dbytes in zip(raw["proto"], raw["state"], raw["dpkts"], raw["dbytes"]):
            if proto != "tcp":
                out.append("SF")          # UDP/ICMP trong NSL-KDD gần như luôn SF
                continue
            if state in ("INT", "REQ"):
                out.append("S0" if dpkts == 0 else "S1")
            elif state == "RST":
                out.append("REJ" if dbytes == 0 and dpkts <= 1 else "RSTO")
            else:
                out.append(C.UNSW_TCP_STATE_TO_FLAG.get(state, "OTH"))
        return pd.Series(out, index=raw.index)

    def _logged_in(self, df: pd.DataFrame, raw: pd.DataFrame) -> pd.Series:
        """
        KDD logged_in = 1 nếu phiên đăng nhập/ứng dụng thành công. Luật suy luận:
          is_ftp_login > 0  HOẶC  (TCP, flag SF, service ứng dụng, server có trả dữ liệu)
        """
        if not self.options.get("logged_in_heuristic", True):
            return pd.Series(0, index=df.index)
        rule = (
            (df["protocol_type"] == "tcp") & (df["flag"] == "SF")
            & df["service"].isin(C.LOGIN_SERVICES) & (df["dst_bytes"] > 0)
        )
        return ((raw["is_ftp_login"] > 0) | rule).astype(int)

    def _approx_traffic_from_ct(self, raw: pd.DataFrame, flag: pd.Series) -> pd.DataFrame:
        """Chỉ dùng cho định dạng [B] (không có IP/thời gian)."""
        dst_ltm = raw["ct_dst_ltm"].clip(lower=1)
        same_srv = (raw["ct_srv_dst"] / dst_ltm).clip(0, 1).round(2)
        serr = flag.isin(C.SERROR_FLAGS).astype(float)
        rerr = flag.isin(C.RERROR_FLAGS).astype(float)
        t = pd.DataFrame(index=raw.index)
        t["count"] = raw["ct_dst_ltm"].clip(upper=C.KDD_COUNT_CAP)
        t["srv_count"] = raw["ct_srv_src"].clip(upper=C.KDD_COUNT_CAP)
        t["serror_rate"] = serr
        t["srv_serror_rate"] = serr
        t["rerror_rate"] = rerr
        t["srv_rerror_rate"] = rerr
        t["same_srv_rate"] = same_srv
        t["diff_srv_rate"] = (1 - same_srv).round(2)
        t["srv_diff_host_rate"] = 0.0
        t["dst_host_count"] = raw["ct_dst_ltm"].clip(upper=C.KDD_DST_HOST_CAP)
        t["dst_host_srv_count"] = raw["ct_srv_dst"].clip(upper=C.KDD_DST_HOST_CAP)
        t["dst_host_same_srv_rate"] = same_srv
        t["dst_host_diff_srv_rate"] = (1 - same_srv).round(2)
        t["dst_host_same_src_port_rate"] = (raw["ct_dst_sport_ltm"] / dst_ltm).clip(0, 1).round(2)
        t["dst_host_srv_diff_host_rate"] = 0.0
        t["dst_host_serror_rate"] = serr
        t["dst_host_srv_serror_rate"] = serr
        t["dst_host_rerror_rate"] = rerr
        t["dst_host_srv_rerror_rate"] = rerr
        return t[TRAFFIC_FEATURES]

    # ------------------------------------------------------------------
    # 3. TO_KDD
    # ------------------------------------------------------------------
    def to_kdd(self, raw: pd.DataFrame) -> pd.DataFrame:
        raw = raw.copy()
        is_raw = self.format == "raw"
        if is_raw:
            raw["dsport_int"] = _parse_port(raw["dsport"])
            raw["sport_int"] = _parse_port(raw["sport"])

        df = pd.DataFrame(index=raw.index)
        prov = {}

        # --- Nhóm basic --------------------------------------------------
        df["duration"] = raw["dur"].clip(lower=0).round().astype(int);      prov["duration"] = EXACT
        df["protocol_type"] = raw["proto"];                                 prov["protocol_type"] = EXACT
        df["service"] = self._map_service(raw)
        prov["service"] = COMPUTED if is_raw else APPROX
        df["flag"] = self._map_flag(raw);                                   prov["flag"] = HEURISTIC
        df["src_bytes"] = raw["sbytes"];                                    prov["src_bytes"] = EXACT
        df["dst_bytes"] = raw["dbytes"];                                    prov["dst_bytes"] = EXACT
        if is_raw:
            df["land"] = ((raw["srcip"].astype(str) == raw["dstip"].astype(str))
                          & (raw["sport_int"] == raw["dsport_int"])).astype(int)
            prov["land"] = COMPUTED
        else:
            df["land"] = (raw["is_sm_ips_ports"] > 0).astype(int);           prov["land"] = EXACT

        # --- Nhóm content (không có trong UNSW) --------------------------
        for c in _CONTENT_ZERO:
            df[c] = 0
            prov[c] = CONSTANT
        df["logged_in"] = self._logged_in(df, raw);                         prov["logged_in"] = HEURISTIC

        # --- Nhóm traffic + host-based -----------------------------------
        if is_raw:
            conns = pd.DataFrame({
                "ts": raw["stime"].astype(float),
                "dst": raw["dstip"].astype(str),
                "sport": raw["sport_int"],
                "service": df["service"],
                "flag": df["flag"],
            }, index=raw.index)
            traffic = build_traffic_features(conns)
            for c in TRAFFIC_FEATURES:
                prov[c] = COMPUTED
        else:
            traffic = self._approx_traffic_from_ct(raw, df["flag"])
            for c in TRAFFIC_FEATURES:
                prov[c] = APPROX
            for c in ("srv_diff_host_rate", "dst_host_srv_diff_host_rate"):
                prov[c] = CONSTANT
            self.notes.append(
                "Định dạng [B] không có IP/thời gian: 19 đặc trưng traffic được xấp xỉ "
                "từ ct_*; dùng file gốc UNSW-NB15_1..4.csv để có độ trung thực cao hơn."
            )
        df = pd.concat([df, traffic], axis=1)

        # --- Nhãn ----------------------------------------------------------
        df["source_label"] = raw["attack_cat_norm"].values
        unmapped = sorted(set(df["source_label"]) - set(C.UNSW_TO_KDD_CATEGORY))
        if unmapped:
            self.notes.append(f"Nhãn UNSW chưa có trong bảng ánh xạ (bị gán 'dos'): {unmapped}")
        df["attack_category"] = df["source_label"].map(C.UNSW_TO_KDD_CATEGORY).fillna("dos")

        self.provenance = prov
        self.notes.append(f"Định dạng nhận diện: {'[A] file gốc' if is_raw else '[B] file chia sẵn'}")
        return df
