"""
Module tiền xử lý dữ liệu cho NIDS trên tập NSL-KDD.
Bao gồm:
- Định nghĩa 41 đặc trưng lưu lượng mạng
- Phân loại các nhãn tấn công cụ thể vào 5 nhóm lớn (Normal, DoS, Probe, R2L, U2R)
- Mã hóa One-Hot cho các biến phân loại và Chuẩn hóa StandardScaler cho các biến số
- Lưu lại pipeline để tái sử dụng khi suy luận (Inference / GUI)
"""
import os
import sys
import joblib
import pandas as pd
import numpy as np
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import StandardScaler, OneHotEncoder, LabelEncoder

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except Exception:
        pass

# 41 đặc trưng + 2 cột nhãn & độ khó
FEATURE_NAMES = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes',
    'dst_bytes', 'land', 'wrong_fragment', 'urgent', 'hot',
    'num_failed_logins', 'logged_in', 'num_compromised', 'root_shell',
    'su_attempted', 'num_root', 'num_file_creations', 'num_shells',
    'num_access_files', 'num_outbound_cmds', 'is_host_login',
    'is_guest_login', 'count', 'srv_count', 'serror_rate',
    'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate',
    'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count',
    'dst_host_srv_count', 'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
    'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate',
    'dst_host_serror_rate', 'dst_host_srv_serror_rate',
    'dst_host_rerror_rate', 'dst_host_srv_rerror_rate'
]

ALL_COLUMNS = FEATURE_NAMES + ['label', 'difficulty_level']

CATEGORICAL_FEATURES = ['protocol_type', 'service', 'flag']
NUMERICAL_FEATURES = [col for col in FEATURE_NAMES if col not in CATEGORICAL_FEATURES]

# Ánh xạ từ các loại tấn công cụ thể thành 5 nhóm lớn
ATTACK_MAPPING = {
    'normal': 'normal',
    
    # Denial of Service (DoS)
    'neptune': 'dos',
    'smurf': 'dos',
    'back': 'dos',
    'teardrop': 'dos',
    'pod': 'dos',
    'land': 'dos',
    'apache2': 'dos',
    'mailbomb': 'dos',
    'processtable': 'dos',
    'udpstorm': 'dos',
    'worm': 'dos',
    
    # Surveillance / Probe (Dò quét cổng & mạng)
    'ipsweep': 'probe',
    'nmap': 'probe',
    'portsweep': 'probe',
    'satan': 'probe',
    'mscan': 'probe',
    'saint': 'probe',
    
    # Remote to Local (R2L - Truy cập trái phép từ xa)
    'guess_passwd': 'r2l',
    'ftp_write': 'r2l',
    'imap': 'r2l',
    'phf': 'r2l',
    'multihop': 'r2l',
    'warezmaster': 'r2l',
    'warezclient': 'r2l',
    'spy': 'r2l',
    'xlock': 'r2l',
    'xsnoop': 'r2l',
    'snmpguess': 'r2l',
    'snmpgetattack': 'r2l',
    'httptunnel': 'r2l',
    'sendmail': 'r2l',
    'named': 'r2l',
    
    # User to Root (U2R - Leo thang đặc quyền)
    'buffer_overflow': 'u2r',
    'loadmodule': 'u2r',
    'rootkit': 'u2r',
    'perl': 'u2r',
    'sqlattack': 'u2r',
    'xterm': 'u2r',
    'ps': 'u2r'
}

CLASS_LABELS = ['normal', 'dos', 'probe', 'r2l', 'u2r']
CLASS_DISPLAY_NAMES = {
    'normal': 'Bình thường (Normal)',
    'dos': 'Từ chối dịch vụ (DoS)',
    'probe': 'Dò quét mạng (Probe)',
    'r2l': 'Xâm nhập từ xa (R2L)',
    'u2r': 'Leo thang đặc quyền (U2R)'
}

def map_attack_category(attack_name: str) -> str:
    cleaned = str(attack_name).strip().lower()
    return ATTACK_MAPPING.get(cleaned, 'dos')

def load_dataset(file_path: str):
    """Đọc file NSL-KDD và trả về dataframe với tên cột chuẩn"""
    df = pd.read_csv(file_path, header=None, names=ALL_COLUMNS)
    # Gán nhãn nhóm tấn công
    df['attack_category'] = df['label'].apply(map_attack_category)
    # Nhãn nhị phân: 0 là normal, 1 là attack
    df['is_attack'] = (df['attack_category'] != 'normal').astype(int)
    return df

class NIDSDataProcessor:
    def __init__(self):
        self.column_transformer = None
        self.label_encoder = None
        self.transformed_feature_names = []
        
    def fit_transform(self, train_df: pd.DataFrame):
        X_train = train_df[FEATURE_NAMES].copy()
        y_train = train_df['attack_category'].copy()
        
        # Thiết lập pipeline chuyển đổi dữ liệu
        numeric_transformer = StandardScaler()
        categorical_transformer = OneHotEncoder(handle_unknown='ignore', sparse_output=False)
        
        self.column_transformer = ColumnTransformer(
            transformers=[
                ('num', numeric_transformer, NUMERICAL_FEATURES),
                ('cat', categorical_transformer, CATEGORICAL_FEATURES)
            ]
        )
        
        X_train_transformed = self.column_transformer.fit_transform(X_train)
        
        # Lấy tên các đặc trưng sau One-Hot
        cat_encoder = self.column_transformer.named_transformers_['cat']
        encoded_cat_names = cat_encoder.get_feature_names_out(CATEGORICAL_FEATURES).tolist()
        self.transformed_feature_names = NUMERICAL_FEATURES + encoded_cat_names
        
        # Encode nhãn lớp mục tiêu
        self.label_encoder = LabelEncoder()
        self.label_encoder.fit(CLASS_LABELS)
        y_train_encoded = self.label_encoder.transform(y_train)
        
        return X_train_transformed, y_train_encoded
        
    def transform(self, df: pd.DataFrame):
        X = df[FEATURE_NAMES].copy()
        X_transformed = self.column_transformer.transform(X)
        
        if 'attack_category' in df.columns:
            y = df['attack_category'].copy()
            y_encoded = self.label_encoder.transform(y)
            return X_transformed, y_encoded
        return X_transformed, None

    def save(self, output_path: str):
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        joblib.dump({
            'column_transformer': self.column_transformer,
            'label_encoder': self.label_encoder,
            'feature_names': FEATURE_NAMES,
            'numerical_features': NUMERICAL_FEATURES,
            'categorical_features': CATEGORICAL_FEATURES,
            'transformed_feature_names': self.transformed_feature_names,
            'class_labels': CLASS_LABELS,
            'class_display_names': CLASS_DISPLAY_NAMES
        }, output_path)
        print(f"[+] Da luu bo tien xu ly tai: {output_path}")

    @staticmethod
    def load(model_path: str):
        data = joblib.load(model_path)
        processor = NIDSDataProcessor()
        processor.column_transformer = data['column_transformer']
        processor.label_encoder = data['label_encoder']
        processor.transformed_feature_names = data['transformed_feature_names']
        return processor, data

if __name__ == "__main__":
    from download_data import ensure_datasets
    train_path, test_path = ensure_datasets(use_full_train=False)
    
    print("[*] Doc du lieu huan luyen va kiem thu...")
    train_df = load_dataset(train_path)
    test_df = load_dataset(test_path)
    
    print(f"    Train shape: {train_df.shape}")
    print(f"    Test shape: {test_df.shape}")
    print("\n[i] Phan bo lop tren tap Huan luyen (KDDTrain+ 20%):")
    print(train_df['attack_category'].value_counts())
    
    print("\n[i] Phan bo lop tren tap Kiem thu (KDDTest+):")
    print(test_df['attack_category'].value_counts())
    
    processor = NIDSDataProcessor()
    X_train_trans, y_train_enc = processor.fit_transform(train_df)
    X_test_trans, y_test_enc = processor.transform(test_df)
    
    print(f"\n[+] So dac trung sau khi One-Hot & Scaling: {X_train_trans.shape[1]}")
    processor_save_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "models", "preprocessor.joblib")
    processor.save(processor_save_path)
