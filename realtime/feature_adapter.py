"""
FeatureAdapter: danh sách ConnectionRecord -> DataFrame 41 cột NSL-KDD.

Tái sử dụng cross_dataset.kdd_feature_builder.build_traffic_features để tính 19
đặc trưng traffic/host theo ĐÚNG định nghĩa KDD (cửa sổ 2 giây, 255 kết nối/host)
— cùng một hàm, cùng unit test đã có. 13 đặc trưng content UNSW/PCAP không có
được gán 0, giống adapter UNSW-NB15.
"""
from __future__ import annotations

from typing import List, Sequence

import pandas as pd

from cross_dataset.kdd_feature_builder import build_traffic_features
from .config import FEATURE_NAMES, CONTENT_ZERO
from .flow_tracker import ConnectionRecord


class FeatureAdapter:
    def to_kdd_frame(self, records: Sequence[ConnectionRecord]) -> pd.DataFrame:
        """Trả về DataFrame đúng 41 cột FEATURE_NAMES (cùng thứ tự)."""
        if not records:
            return pd.DataFrame(columns=FEATURE_NAMES)

        base = pd.DataFrame({
            "duration": [r.duration for r in records],
            "protocol_type": [r.proto for r in records],
            "service": [r.service for r in records],
            "flag": [r.flag for r in records],
            "src_bytes": [r.src_bytes for r in records],
            "dst_bytes": [r.dst_bytes for r in records],
            "land": [r.land for r in records],
            "urgent": [r.urgent for r in records],
            "logged_in": [r.logged_in for r in records],
            "is_guest_login": [r.is_guest_login for r in records],
        })

        # 13 đặc trưng content + wrong_fragment: gán 0
        for col in CONTENT_ZERO:
            if col not in base.columns:
                base[col] = 0

        # 19 đặc trưng traffic/host: tính lại đúng định nghĩa KDD
        conns = pd.DataFrame({
            "ts": [r.ts for r in records],
            "dst": [r.dst for r in records],
            "sport": [r.sport for r in records],
            "service": [r.service for r in records],
            "flag": [r.flag for r in records],
        })
        traffic = build_traffic_features(conns)
        out = pd.concat([base.reset_index(drop=True), traffic.reset_index(drop=True)], axis=1)

        # Bổ sung cột còn thiếu (an toàn) rồi sắp đúng thứ tự 41 cột
        for col in FEATURE_NAMES:
            if col not in out.columns:
                out[col] = 0
        return out[FEATURE_NAMES]
