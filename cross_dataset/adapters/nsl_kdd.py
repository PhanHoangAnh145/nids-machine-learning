"""
Adapter ĐỐI CHỨNG: chạy lại chính tập NSL-KDD (vd. KDDTest+.txt) qua pipeline mới.

Mục đích: chứng minh pipeline cross_dataset cho ra KẾT QUẢ Y HỆT luồng cũ
(so với models/evaluation_results.json). Nếu khớp -> mọi chênh lệch khi chạy
trên UNSW-NB15 là do dữ liệu, không phải do lỗi code.
"""
import os
import sys
from typing import Sequence

import pandas as pd

from ..config import PROJECT_ROOT
from .base import BaseAdapter, EXACT, register_adapter


def _legacy_attack_mapper():
    """Import (chỉ đọc) hàm map nhãn của luồng cũ để đảm bảo đối chứng 1-1."""
    src_dir = os.path.join(PROJECT_ROOT, "src")
    if src_dir not in sys.path:
        sys.path.append(src_dir)
    from preprocess import map_attack_category, ALL_COLUMNS  # noqa: E402
    return map_attack_category, ALL_COLUMNS


@register_adapter("nsl-kdd")
class NSLKDDAdapter(BaseAdapter):
    def load(self, paths: Sequence[str]) -> pd.DataFrame:
        _, all_cols = _legacy_attack_mapper()
        frames = [pd.read_csv(p, header=None, names=all_cols) for p in paths]
        return pd.concat(frames, ignore_index=True)

    def to_kdd(self, raw: pd.DataFrame) -> pd.DataFrame:
        mapper, _ = _legacy_attack_mapper()
        df = raw.copy()
        df["source_label"] = df["label"].astype(str)
        df["attack_category"] = df["label"].apply(mapper)
        self.provenance = {c: EXACT for c in df.columns}
        return df
