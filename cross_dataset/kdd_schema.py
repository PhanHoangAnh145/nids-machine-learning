"""
"Hợp đồng" đầu vào của model cũ, đọc trực tiếp từ models/preprocessor.joblib.

Không import code trong src/ -> nếu luồng cũ có refactor thì module này vẫn
chạy miễn là artifact .joblib không đổi định dạng. Tên cột, thứ tự cột, từ
vựng One-Hot và tham số StandardScaler đều lấy từ artifact, không hard-code.
"""
from dataclasses import dataclass, field
from typing import Dict, List

import joblib
import numpy as np
import pandas as pd


@dataclass
class KDDSchema:
    feature_names: List[str]                 # 41 cột thô theo đúng thứ tự
    numerical_features: List[str]            # 38 cột số
    categorical_features: List[str]          # protocol_type, service, flag
    vocab: Dict[str, List[str]]              # từ vựng One-Hot đã học
    class_labels: List[str]                  # thứ tự lớp của LabelEncoder
    transformed_dim: int                     # số chiều sau transform (122)
    scaler_mean: Dict[str, float] = field(default_factory=dict)
    scaler_std: Dict[str, float] = field(default_factory=dict)
    column_transformer: object = None
    label_encoder: object = None

    # ------------------------------------------------------------------
    @classmethod
    def from_preprocessor(cls, preprocessor_path: str) -> "KDDSchema":
        data = joblib.load(preprocessor_path)
        ct = data["column_transformer"]
        le = data["label_encoder"]
        cat_feats = list(data["categorical_features"])
        num_feats = list(data["numerical_features"])

        ohe = ct.named_transformers_["cat"]
        vocab = {f: [str(v) for v in cats] for f, cats in zip(cat_feats, ohe.categories_)}

        scaler = ct.named_transformers_["num"]
        mean = dict(zip(num_feats, np.asarray(scaler.mean_, dtype=float)))
        std = dict(zip(num_feats, np.asarray(scaler.scale_, dtype=float)))

        return cls(
            feature_names=list(data["feature_names"]),
            numerical_features=num_feats,
            categorical_features=cat_feats,
            vocab=vocab,
            class_labels=[str(c) for c in le.classes_],
            transformed_dim=len(data["transformed_feature_names"]),
            scaler_mean=mean,
            scaler_std=std,
            column_transformer=ct,
            label_encoder=le,
        )

    # ------------------------------------------------------------------
    def align(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Trả về DataFrame có ĐÚNG 41 cột, ĐÚNG thứ tự, ĐÚNG kiểu mà
        ColumnTransformer đã fit. Ném lỗi nếu adapter quên sinh cột nào
        (thay vì âm thầm điền 0 như predict_batch cũ) để lỗi mapping lộ ra sớm.
        """
        missing = [c for c in self.feature_names if c not in df.columns]
        if missing:
            raise ValueError(f"Adapter chưa sinh đủ cột NSL-KDD, thiếu: {missing}")

        out = df[self.feature_names].copy()
        for c in self.numerical_features:
            out[c] = pd.to_numeric(out[c], errors="coerce")
        out[self.numerical_features] = (
            out[self.numerical_features].replace([np.inf, -np.inf], np.nan).fillna(0.0).astype(float)
        )
        for c in self.categorical_features:
            out[c] = out[c].astype(str)
        return out

    def transform(self, aligned_df: pd.DataFrame) -> np.ndarray:
        X = self.column_transformer.transform(aligned_df)
        if X.shape[1] != self.transformed_dim:
            raise RuntimeError(f"Sai số chiều: {X.shape[1]} != {self.transformed_dim}")
        return X

    # ------------------------------------------------------------------
    def coverage_report(self, aligned_df: pd.DataFrame) -> Dict[str, dict]:
        """
        Tỷ lệ giá trị phân loại KHÔNG có trong vocab NSL-KDD. Các giá trị này
        bị OneHotEncoder(handle_unknown='ignore') biến thành vector toàn 0
        -> model "mù" thông tin đó. Cần soi kỹ khi kết quả thấp.
        """
        rep = {}
        for c in self.categorical_features:
            known = aligned_df[c].isin(self.vocab[c])
            unknown_vals = aligned_df.loc[~known, c].value_counts().head(10)
            rep[c] = {
                "unknown_ratio": float(1.0 - known.mean()) if len(aligned_df) else 0.0,
                "top_unknown_values": {str(k): int(v) for k, v in unknown_vals.items()},
                "value_distribution_top10": {
                    str(k): float(v) for k, v in aligned_df[c].value_counts(normalize=True).head(10).items()
                },
            }
        return rep

    def drift_report(self, aligned_df: pd.DataFrame, top_k: int = 15) -> List[dict]:
        """
        So sánh trung bình từng đặc trưng số của dữ liệu mới với tập train NSL-KDD
        (lấy từ StandardScaler). |z| = |mean_new - mean_train| / std_train lớn
        nghĩa là phân phối lệch mạnh (covariate shift).
        """
        rows = []
        for c in self.numerical_features:
            std = self.scaler_std.get(c, 1.0) or 1.0
            m_new = float(aligned_df[c].mean())
            m_tr = float(self.scaler_mean.get(c, 0.0))
            rows.append({
                "feature": c,
                "train_mean": m_tr,
                "new_mean": m_new,
                "z_shift": (m_new - m_tr) / std,
                "new_zero_ratio": float((aligned_df[c] == 0).mean()),
            })
        rows.sort(key=lambda r: abs(r["z_shift"]), reverse=True)
        return rows[:top_k]
