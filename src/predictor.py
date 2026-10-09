"""
Module suy luận (Inference / Prediction) cho NIDS.
Cung cấp API đơn giản để:
- Dự đoán 1 mẫu lưu lượng mạng đơn lẻ (dành cho form nhập liệu hoặc test ngẫu nhiên)
- Dự đoán hàng loạt từ DataFrame / File CSV (dành cho batch scanning)
"""
import os
import sys
import joblib
import pandas as pd
import numpy as np

sys.path.append(os.path.dirname(__file__))
from preprocess import (
    NIDSDataProcessor, FEATURE_NAMES, CLASS_DISPLAY_NAMES,
    map_attack_category, load_dataset
)

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except Exception:
        pass

MODELS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "models")
DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")

class NIDSPredictor:
    def __init__(self, model_path: str = None, preprocessor_path: str = None):
        if model_path is None:
            model_path = os.path.join(MODELS_DIR, "best_model.joblib")
        if preprocessor_path is None:
            preprocessor_path = os.path.join(MODELS_DIR, "preprocessor.joblib")
            
        if not os.path.exists(model_path) or not os.path.exists(preprocessor_path):
            raise FileNotFoundError("Chưa tìm thấy model hoặc preprocessor. Hãy chạy src/train.py trước!")
            
        self.model = joblib.load(model_path)
        self.processor, self.prep_metadata = NIDSDataProcessor.load(preprocessor_path)
        self.classes = list(self.processor.label_encoder.classes_)
        self.sample_data = None
        
    def predict_single(self, sample_dict: dict) -> dict:
        """
        Dự đoán cho một gói tin đơn lẻ.
        sample_dict: dictionary chứa 41 đặc trưng mạng.
        """
        # Đảm bảo đủ các cột đặc trưng, nếu thiếu thì điền 0
        row_data = {}
        for feat in FEATURE_NAMES:
            row_data[feat] = [sample_dict.get(feat, 0)]
            
        df_single = pd.DataFrame(row_data)
        X_trans = self.processor.column_transformer.transform(df_single)
        
        pred_idx = self.model.predict(X_trans)[0]
        cat = self.processor.label_encoder.inverse_transform([pred_idx])[0]
        
        # Tính xác suất (Confidence)
        if hasattr(self.model, "predict_proba"):
            probs = self.model.predict_proba(X_trans)[0]
            conf = float(probs[pred_idx])
            prob_dict = {
                self.classes[i]: float(probs[i])
                for i in range(len(self.classes))
            }
        else:
            conf = 1.0
            prob_dict = {cat: 1.0}
            
        is_attack = (cat != 'normal')
        display_name = CLASS_DISPLAY_NAMES.get(cat, cat)
        
        return {
            "category": cat,
            "display_name": display_name,
            "is_attack": is_attack,
            "confidence": conf,
            "probabilities": prob_dict
        }

    def predict_batch(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Dự đoán hàng loạt cho DataFrame chứa các cột đặc trưng.
        """
        df_in = df.copy()
        # Đảm bảo có đủ 41 cột đặc trưng
        for col in FEATURE_NAMES:
            if col not in df_in.columns:
                df_in[col] = 0
                
        X_trans = self.processor.column_transformer.transform(df_in[FEATURE_NAMES])
        pred_indices = self.model.predict(X_trans)
        categories = self.processor.label_encoder.inverse_transform(pred_indices)
        
        result_df = df.copy()
        result_df['predicted_category'] = categories
        result_df['predicted_name'] = [CLASS_DISPLAY_NAMES.get(c, c) for c in categories]
        result_df['is_attack'] = (result_df['predicted_category'] != 'normal').astype(int)
        
        if hasattr(self.model, "predict_proba"):
            probs = self.model.predict_proba(X_trans)
            confidences = [probs[i, pred_indices[i]] for i in range(len(pred_indices))]
            result_df['confidence'] = confidences
        else:
            result_df['confidence'] = 1.0
            
        return result_df

    def get_random_sample(self, category_filter: str = None) -> dict:
        """
        Lấy một dòng mẫu ngẫu nhiên từ file test để test thử
        """
        if self.sample_data is None:
            csv_path = os.path.join(DATA_DIR, "sample_test.csv")
            if os.path.exists(csv_path):
                self.sample_data = pd.read_csv(csv_path)
            else:
                raw_test = os.path.join(DATA_DIR, "raw", "KDDTest+.txt")
                self.sample_data = load_dataset(raw_test).sample(n=500, random_state=42)
                
        df_pool = self.sample_data
        if category_filter and 'attack_category' in df_pool.columns:
            filtered = df_pool[df_pool['attack_category'] == category_filter]
            if len(filtered) > 0:
                df_pool = filtered
                
        sample_row = df_pool.sample(n=1).iloc[0]
        actual_label = sample_row.get('label', 'unknown')
        actual_category = sample_row.get('attack_category', 'unknown')
        
        sample_dict = sample_row[FEATURE_NAMES].to_dict()
        sample_dict['_actual_label'] = actual_label
        sample_dict['_actual_category'] = actual_category
        return sample_dict

if __name__ == "__main__":
    predictor = NIDSPredictor()
    print("[*] Thu nghiem du doan 5 mau ngau nhien:")
    print("-" * 75)
    for i in range(5):
        sample = predictor.get_random_sample()
        actual_cat = sample.get('_actual_category')
        actual_lbl = sample.get('_actual_label')
        res = predictor.predict_single(sample)
        
        status = "AN TOAN (NORMAL)" if not res['is_attack'] else f"TAN CONG [{res['category'].upper()}]"
        print(f"Mau {i+1}:")
        print(f"  - Thuc te     : {actual_lbl} ({actual_cat})")
        print(f"  - Du doan     : {res['display_name']} (Do tin cay: {res['confidence']*100:.1f}%)")
        print(f"  - Ket qua     : {status}")
        print()
