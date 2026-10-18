"""
Lớp cơ sở cho mọi Adapter.

Một Adapter có đúng 1 nhiệm vụ: biến dữ liệu của bộ dataset X thành
DataFrame gồm
    * 41 cột thô theo định dạng NSL-KDD (tên cột trùng FEATURE_NAMES)
    * attack_category : nhãn thật đã quy về 5 lớp {normal, dos, probe, r2l, u2r}
    * source_label    : nhãn gốc của dataset X (để phân tích theo từng loại tấn công)
Phần còn lại (scaling, one-hot, predict, metrics) dùng chung, không phụ thuộc dataset.

Muốn thêm dataset mới (CICIDS2017, PCAP ...): tạo file mới trong adapters/,
kế thừa BaseAdapter, rồi đăng ký bằng decorator @register_adapter("ten").
"""
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Sequence, Type

import pandas as pd

# Mức độ tin cậy của từng đặc trưng sau khi ánh xạ (ghi vào báo cáo)
EXACT = "exact"            # cùng ngữ nghĩa, lấy trực tiếp
COMPUTED = "computed"      # tính lại đúng định nghĩa KDD từ dữ liệu thô
APPROX = "approx"          # xấp xỉ từ đặc trưng gần nghĩa
HEURISTIC = "heuristic"    # suy luận theo luật
CONSTANT = "constant_0"    # dataset không có thông tin -> gán 0

_REGISTRY: Dict[str, Type["BaseAdapter"]] = {}


def register_adapter(name: str):
    def deco(cls):
        cls.name = name
        _REGISTRY[name] = cls
        return cls
    return deco


def get_adapter(name: str, **options) -> "BaseAdapter":
    if name not in _REGISTRY:
        raise KeyError(f"Chưa có adapter '{name}'. Có sẵn: {sorted(_REGISTRY)}")
    return _REGISTRY[name](**options)


def list_adapters() -> List[str]:
    return sorted(_REGISTRY)


class BaseAdapter(ABC):
    name: str = "base"

    def __init__(self, **options):
        self.options = options
        self.provenance: Dict[str, str] = {}
        self.notes: List[str] = []

    # ---- phải cài đặt -------------------------------------------------
    @abstractmethod
    def load(self, paths: Sequence[str]) -> pd.DataFrame:
        """Đọc file gốc, trả về DataFrame thô (đã chuẩn hóa tên cột)."""

    @abstractmethod
    def to_kdd(self, raw: pd.DataFrame) -> pd.DataFrame:
        """Ánh xạ sang 41 cột NSL-KDD + attack_category + source_label."""

    # ---- dùng chung ---------------------------------------------------
    def run(self, paths: Sequence[str], sample: Optional[int] = None,
            random_state: int = 42) -> pd.DataFrame:
        raw = self.load(paths)
        kdd = self.to_kdd(raw)   # tính đặc trưng trên TOÀN BỘ luồng trước ...
        if sample and sample < len(kdd):
            # ... rồi mới lấy mẫu, để không phá các đặc trưng cửa sổ thời gian
            kdd = kdd.sample(n=sample, random_state=random_state)
        for col in ("attack_category", "source_label"):
            if col not in kdd.columns:
                raise ValueError(f"Adapter '{self.name}' phải sinh cột '{col}'")
        return kdd.reset_index(drop=True)
