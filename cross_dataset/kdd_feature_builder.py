"""
Tính lại 19 đặc trưng "traffic" + "host-based" của NSL-KDD từ một chuỗi bản ghi
kết nối (connection records) đã sắp xếp theo thời gian.

Dùng được cho MỌI nguồn có thông tin kết nối thô (UNSW-NB15 file gốc, PCAP sau
khi gom flow, Zeek conn.log ...). Đây là cách tái tạo trung thực nhất thay vì
"đoán" từ các đặc trưng ct_* của bộ dữ liệu khác.

Đầu vào: DataFrame có các cột
    ts       : thời điểm bắt đầu kết nối (giây, float)
    dst      : địa chỉ đích
    sport    : cổng nguồn
    service  : tên service đã quy về từ vựng NSL-KDD
    flag     : flag đã quy về từ vựng NSL-KDD
Định nghĩa (theo Lee & Stolfo, KDD'99):
  * Nhóm thời gian (cửa sổ 2 giây, gồm cả kết nối hiện tại)
      - cùng dst host  : count, serror_rate, rerror_rate, same_srv_rate, diff_srv_rate
      - cùng service   : srv_count, srv_serror_rate, srv_rerror_rate, srv_diff_host_rate
  * Nhóm host (N kết nối gần nhất tới cùng dst host, N = 255 = trần của NSL-KDD)
      - dst_host_count, dst_host_srv_count, dst_host_same_srv_rate,
        dst_host_diff_srv_rate, dst_host_same_src_port_rate,
        dst_host_srv_diff_host_rate, dst_host_*error_rate
Tất cả bộ đếm được cập nhật tăng/giảm (O(1) mỗi bản ghi), chạy được trên vài
triệu dòng.
"""
from collections import Counter, defaultdict, deque

import numpy as np
import pandas as pd

from .config import (
    KDD_COUNT_CAP, KDD_DST_HOST_CAP, KDD_TIME_WINDOW_SEC,
    SERROR_FLAGS, RERROR_FLAGS,
)

TRAFFIC_FEATURES = [
    "count", "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate",
    "srv_rerror_rate", "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate",
    "dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
    "dst_host_srv_serror_rate", "dst_host_rerror_rate", "dst_host_srv_rerror_rate",
]

_NONE, _SERR, _RERR = 0, 1, 2


class _Win:
    """Cửa sổ trượt với các bộ đếm cộng dồn."""
    __slots__ = ("q", "serr", "rerr", "by_srv", "by_dst", "by_sport", "serr_srv", "rerr_srv")

    def __init__(self):
        self.q = deque()
        self.serr = 0
        self.rerr = 0
        self.by_srv = Counter()
        self.by_dst = Counter()
        self.by_sport = Counter()
        self.serr_srv = Counter()
        self.rerr_srv = Counter()

    def push(self, ts, srv, dst, sport, err):
        self.q.append((ts, srv, dst, sport, err))
        self.by_srv[srv] += 1
        self.by_dst[dst] += 1
        self.by_sport[sport] += 1
        if err == _SERR:
            self.serr += 1
            self.serr_srv[srv] += 1
        elif err == _RERR:
            self.rerr += 1
            self.rerr_srv[srv] += 1

    def pop(self):
        _, srv, dst, sport, err = self.q.popleft()
        self.by_srv[srv] -= 1
        self.by_dst[dst] -= 1
        self.by_sport[sport] -= 1
        if err == _SERR:
            self.serr -= 1
            self.serr_srv[srv] -= 1
        elif err == _RERR:
            self.rerr -= 1
            self.rerr_srv[srv] -= 1

    def expire_before(self, t):
        q = self.q
        while q and q[0][0] < t:
            self.pop()

    def trim_to(self, n):
        while len(self.q) > n:
            self.pop()


def _rate(a, b):
    return round(a / b, 2) if b else 0.0


def build_traffic_features(
    conns: pd.DataFrame,
    time_window: float = KDD_TIME_WINDOW_SEC,
    host_window: int = KDD_DST_HOST_CAP,
) -> pd.DataFrame:
    """Trả về DataFrame 19 cột TRAFFIC_FEATURES, cùng index với `conns`."""
    required = ["ts", "dst", "sport", "service", "flag"]
    miss = [c for c in required if c not in conns.columns]
    if miss:
        raise ValueError(f"Thiếu cột cho feature builder: {miss}")

    order = np.argsort(conns["ts"].to_numpy(dtype=float), kind="stable")
    ts_a = conns["ts"].to_numpy(dtype=float)[order]
    dst_a = conns["dst"].astype(str).to_numpy()[order]
    sport_a = conns["sport"].astype(str).to_numpy()[order]
    srv_a = conns["service"].astype(str).to_numpy()[order]
    flag_a = conns["flag"].astype(str).to_numpy()[order]

    n = len(order)
    out = np.zeros((n, len(TRAFFIC_FEATURES)), dtype=float)

    t_host = defaultdict(_Win)   # 2s, theo dst host
    t_srv = defaultdict(_Win)    # 2s, theo service
    h_host = defaultdict(_Win)   # N kết nối gần nhất, theo dst host
    h_srv = defaultdict(_Win)    # N kết nối gần nhất, theo service

    for i in range(n):
        ts, dst, sp, srv, fl = ts_a[i], dst_a[i], sport_a[i], srv_a[i], flag_a[i]
        err = _SERR if fl in SERROR_FLAGS else (_RERR if fl in RERROR_FLAGS else _NONE)
        lo = ts - time_window

        w = t_host[dst]; w.expire_before(lo); w.push(ts, srv, dst, sp, err)
        s = t_srv[srv]; s.expire_before(lo); s.push(ts, srv, dst, sp, err)
        hh = h_host[dst]; hh.push(ts, srv, dst, sp, err); hh.trim_to(host_window)
        hs = h_srv[srv]; hs.push(ts, srv, dst, sp, err); hs.trim_to(host_window)

        cnt = len(w.q)
        scnt = len(s.q)
        hcnt = len(hh.q)
        hscnt = hh.by_srv[srv]
        same_srv = _rate(w.by_srv[srv], cnt)
        h_same_srv = _rate(hscnt, hcnt)

        out[i] = (
            min(cnt, KDD_COUNT_CAP),
            min(scnt, KDD_COUNT_CAP),
            _rate(w.serr, cnt),
            _rate(s.serr, scnt),
            _rate(w.rerr, cnt),
            _rate(s.rerr, scnt),
            same_srv,
            round(1.0 - same_srv, 2) if cnt else 0.0,
            _rate(scnt - s.by_dst[dst], scnt),
            min(hcnt, KDD_DST_HOST_CAP),
            min(hscnt, KDD_DST_HOST_CAP),
            h_same_srv,
            round(1.0 - h_same_srv, 2) if hcnt else 0.0,
            _rate(hh.by_sport[sp], hcnt),
            _rate(len(hs.q) - hs.by_dst[dst], len(hs.q)),
            _rate(hh.serr, hcnt),
            _rate(hh.serr_srv[srv], hscnt),
            _rate(hh.rerr, hcnt),
            _rate(hh.rerr_srv[srv], hscnt),
        )

    res = np.empty_like(out)
    res[order] = out
    return pd.DataFrame(res, columns=TRAFFIC_FEATURES, index=conns.index)
