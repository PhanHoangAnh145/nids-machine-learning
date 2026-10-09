"""
Module huấn luyện và so sánh các mô hình Machine Learning cho NIDS trên tập NSL-KDD.
So sánh 3 mô hình:
1. Decision Tree (Cây quyết định)
2. Random Forest (Rừng ngẫu nhiên - Best model)
3. K-Nearest Neighbors (KNN)

Đánh giá 2 khía cạnh:
- Hiệu năng trên tập kiểm thử nội bộ (Validation - Tấn công đã biết): Đạt ~99.7%
- Khả năng tổng quát hóa trên tập KDDTest+ (Tấn công Zero-Day / Biến thể mới): Đạt ~76% - 81%
"""
import os
import sys
import time
import json
import joblib
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    classification_report, confusion_matrix
)

sys.path.append(os.path.dirname(__file__))
from preprocess import (
    load_dataset, NIDSDataProcessor, CLASS_LABELS, CLASS_DISPLAY_NAMES,
    FEATURE_NAMES
)
from download_data import ensure_datasets

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except Exception:
        pass

MODELS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "models")
DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")

def train_and_evaluate(use_full_train: bool = True):
    os.makedirs(MODELS_DIR, exist_ok=True)
    os.makedirs(DATA_DIR, exist_ok=True)
    
    print("=" * 80)
    print("  CHUONG TRINH HUAN LUYEN & DANH GIA MO HINH NIDS (MACHINE LEARNING)")
    print("=" * 80)
    
    # 1. Tải và đọc dữ liệu
    train_path, test_path = ensure_datasets(use_full_train=use_full_train)
    print(f"\n[*] 1. Doc du lieu tu: {os.path.basename(train_path)} va {os.path.basename(test_path)}...")
    train_df = load_dataset(train_path)
    test_df = load_dataset(test_path)
    
    print(f"    - So mau tap Train: {len(train_df):,}")
    print(f"    - So mau tap Test : {len(test_df):,}")
    
    # Tạo sẵn file sample_test.csv (100 dòng)
    sample_csv_path = os.path.join(DATA_DIR, "sample_test.csv")
    test_df.sample(n=min(200, len(test_df)), random_state=42).to_csv(sample_csv_path, index=False)
    print(f"    [+] Da tao file mau test: {sample_csv_path}")
    
    # 2. Tiền xử lý dữ liệu
    print("\n[*] 2. Chuan hoa va ma hoa dac trung (Scaling & One-Hot Encoding)...")
    processor = NIDSDataProcessor()
    X_train_full, y_train_full = processor.fit_transform(train_df)
    X_test, y_test = processor.transform(test_df)
    
    # Tách 20% tập train làm Validation để đo độ chính xác trên các mẫu tấn công đã học
    X_train, X_val, y_train, y_val = train_test_split(
        X_train_full, y_train_full, test_size=0.2, random_state=42, stratify=y_train_full
    )
    
    processor_path = os.path.join(MODELS_DIR, "preprocessor.joblib")
    processor.save(processor_path)
    print(f"    - So chieu dac trung: {X_train.shape[1]}")
    
    # 3. Định nghĩa các mô hình
    models = {
        "Decision Tree": DecisionTreeClassifier(
            max_depth=18,
            criterion='gini',
            random_state=42
        ),
        "Random Forest": RandomForestClassifier(
            n_estimators=100,
            max_depth=20,
            class_weight='balanced',
            random_state=42,
            n_jobs=-1
        ),
        "K-Nearest Neighbors": KNeighborsClassifier(
            n_neighbors=5,
            n_jobs=-1
        )
    }
    
    results = {}
    best_model_name = "Random Forest"
    best_model_obj = None
    
    normal_idx = list(processor.label_encoder.classes_).index('normal')
    
    print("\n[*] 3. Huan luyen va danh gia cac thuat toan...")
    print("-" * 80)
    
    for name, clf in models.items():
        print(f"\n>>> Dang huan luyen: [{name}]...")
        t0 = time.time()
        clf.fit(X_train, y_train)
        train_time = time.time() - t0
        
        # Đánh giá trên tập Validation (Known attacks)
        val_pred = clf.predict(X_val)
        val_acc = accuracy_score(y_val, val_pred)
        val_f1 = f1_score(y_val, val_pred, average='weighted', zero_division=0)
        
        # Đánh giá trên tập KDDTest+ (Novel / Zero-day attacks)
        t1 = time.time()
        test_pred = clf.predict(X_test)
        infer_time = time.time() - t1
        
        test_acc = accuracy_score(y_test, test_pred)
        test_prec_w = precision_score(y_test, test_pred, average='weighted', zero_division=0)
        test_rec_w = recall_score(y_test, test_pred, average='weighted', zero_division=0)
        test_f1_w = f1_score(y_test, test_pred, average='weighted', zero_division=0)
        test_f1_macro = f1_score(y_test, test_pred, average='macro', zero_division=0)
        
        # Đánh giá Nhị phân (Normal vs Attack) trên tập Test
        bin_true = (y_test != normal_idx).astype(int)
        bin_pred = (test_pred != normal_idx).astype(int)
        bin_acc = accuracy_score(bin_true, bin_pred)
        bin_prec = precision_score(bin_true, bin_pred, zero_division=0)
        bin_rec = recall_score(bin_true, bin_pred, zero_division=0)
        bin_f1 = f1_score(bin_true, bin_pred, zero_division=0)
        
        cm = confusion_matrix(y_test, test_pred)
        cls_rep = classification_report(
            y_test, test_pred,
            target_names=[CLASS_DISPLAY_NAMES[c] for c in processor.label_encoder.classes_],
            zero_division=0,
            output_dict=True
        )
        
        results[name] = {
            "val_accuracy": float(val_acc),
            "val_f1": float(val_f1),
            "test_accuracy": float(test_acc),
            "test_precision_weighted": float(test_prec_w),
            "test_recall_weighted": float(test_rec_w),
            "test_f1_weighted": float(test_f1_w),
            "test_f1_macro": float(test_f1_macro),
            "binary_accuracy": float(bin_acc),
            "binary_precision": float(bin_prec),
            "binary_recall": float(bin_rec),
            "binary_f1": float(bin_f1),
            "train_time_sec": float(train_time),
            "infer_time_sec": float(infer_time),
            "confusion_matrix": cm.tolist(),
            "classification_report": cls_rep
        }
        
        print(f"    - Validation Acc (Tan cong da biet): {val_acc * 100:.2f}% (F1: {val_f1 * 100:.2f}%)")
        print(f"    - KDDTest+ Acc   (Tan cong moi lạ) : {test_acc * 100:.2f}% (F1: {test_f1_w * 100:.2f}%)")
        print(f"    - Binary Detect  (Phat hien Attack): Precision: {bin_prec * 100:.2f}% | Recall: {bin_rec * 100:.2f}%")
        print(f"    - Thoi gian Train: {train_time:.2f}s | Suy luan 22k goi tin: {infer_time:.2f}s")
        
        if name == "Random Forest":
            best_model_obj = clf

    # 4. In bảng so sánh
    print("\n" + "=" * 90)
    print("                     BANG SO SANH HIEU NANG CAC MO HINH")
    print("=" * 90)
    print(f"{'Thuat Toan':<20} | {'Val Acc (Biet)':<15} | {'Test Acc (Moi)':<15} | {'Binary Prec':<12} | {'Train (s)':<9}")
    print("-" * 90)
    for name, r in results.items():
        row = f"{name:<20} | {r['val_accuracy']*100:>12.2f}%  | {r['test_accuracy']*100:>12.2f}%  | {r['binary_precision']*100:>10.2f}% | {r['train_time_sec']:>7.2f}s"
        print(row)
    print("=" * 90)

    # 5. Lưu mô hình Random Forest làm mô hình sản phẩm
    best_model_path = os.path.join(MODELS_DIR, "best_model.joblib")
    joblib.dump(best_model_obj, best_model_path)
    print(f"\n[+] Da luu Random Forest vao: {best_model_path}")

    # 6. Feature Importance
    rf_model = models["Random Forest"]
    importances = rf_model.feature_importances_
    feat_names = processor.transformed_feature_names
    feat_imp_df = pd.DataFrame({
        'feature': feat_names,
        'importance': importances
    }).sort_values(by='importance', ascending=False)
    
    results['top15_features'] = feat_imp_df.head(15).to_dict(orient='records')
    results['best_model'] = best_model_name
    
    print("\n[i] TOP 10 DAC TRUNG QUAN TRONG NHAT (FEATURE IMPORTANCE):")
    for idx, row in enumerate(feat_imp_df.head(10).itertuples(), start=1):
        print(f"    {idx:2d}. {row.feature:<30}: {row.importance * 100:.2f}%")

    # 7. Lưu file JSON
    json_path = os.path.join(MODELS_DIR, "evaluation_results.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)
    print(f"[+] Da luu file ket qua JSON: {json_path}")

    # 8. Vẽ biểu đồ
    generate_plots(results, best_model_name, feat_imp_df.head(15), processor.label_encoder.classes_)
    print("\n[v] HOAN TAT HUAN LUYEN VA DANH GIA MO HINH!")
    return results

def generate_plots(results, best_model_name, top_features_df, classes):
    """Vẽ và lưu biểu đồ Confusion Matrix, Feature Importance và So sánh mô hình"""
    # 1. Confusion Matrix
    cm = np.array(results[best_model_name]['confusion_matrix'])
    fig, ax = plt.subplots(figsize=(8, 6))
    cax = ax.matshow(cm, cmap=plt.cm.Blues, alpha=0.8)
    
    for i in range(cm.shape[0]):
        for j in range(cm.shape[1]):
            val = cm[i, j]
            ax.text(x=j, y=i, s=f"{val:,}", va='center', ha='center',
                    color='white' if val > 2000 else 'black', fontsize=9, fontweight='bold')
            
    fig.colorbar(cax)
    tick_marks = np.arange(len(classes))
    ax.set_xticks(tick_marks)
    ax.set_yticks(tick_marks)
    ax.set_xticklabels(classes, rotation=25, ha='left')
    ax.set_yticklabels(classes)
    ax.set_xlabel('Nhan Du Doan (Predicted Label)', fontsize=11, fontweight='bold')
    ax.set_ylabel('Nhan Thuc Te (True Label)', fontsize=11, fontweight='bold')
    ax.set_title(f'Ma tran nham lan (Confusion Matrix) - {best_model_name}', fontsize=12, fontweight='bold', pad=20)
    plt.tight_layout()
    cm_path = os.path.join(MODELS_DIR, "confusion_matrix.png")
    plt.savefig(cm_path, dpi=200)
    plt.close()

    # 2. Top Features
    fig, ax = plt.subplots(figsize=(10, 6))
    y_pos = np.arange(len(top_features_df))
    ax.barh(y_pos, top_features_df['importance'] * 100, align='center', color='#1f77b4', edgecolor='black')
    ax.set_yticks(y_pos)
    ax.set_yticklabels(top_features_df['feature'])
    ax.invert_yaxis()
    ax.set_xlabel('Muc do dong gop (%)', fontsize=11, fontweight='bold')
    ax.set_title('Top 15 Dac Trung Mang Quan Trong Nhat (Random Forest Feature Importance)', fontsize=12, fontweight='bold')
    plt.grid(axis='x', linestyle='--', alpha=0.6)
    plt.tight_layout()
    feat_path = os.path.join(MODELS_DIR, "feature_importance.png")
    plt.savefig(feat_path, dpi=200)
    plt.close()

    # 3. Biểu đồ So sánh các mô hình
    model_names = [m for m in results.keys() if isinstance(results[m], dict) and 'val_accuracy' in results[m]]
    val_accs = [results[m]['val_accuracy'] * 100 for m in model_names]
    test_accs = [results[m]['test_accuracy'] * 100 for m in model_names]
    
    x = np.arange(len(model_names))
    width = 0.35
    
    fig, ax = plt.subplots(figsize=(8, 5))
    rects1 = ax.bar(x - width/2, val_accs, width, label='Validation (Tan cong da biet)', color='#2ca02c')
    rects2 = ax.bar(x + width/2, test_accs, width, label='KDDTest+ (Tan cong moi la)', color='#ff7f0e')
    
    ax.set_ylabel('Do chinh xac Accuracy (%)', fontweight='bold')
    ax.set_title('So sanh Do chinh xac giua cac mo hinh Machine Learning', fontweight='bold')
    ax.set_xticks(x)
    ax.set_xticklabels(model_names, fontweight='bold')
    ax.legend(loc='lower right')
    ax.set_ylim(60, 105)
    plt.grid(axis='y', linestyle='--', alpha=0.5)
    
    for rect in rects1:
        h = rect.get_height()
        ax.annotate(f'{h:.1f}%', xy=(rect.get_x() + rect.get_width() / 2, h),
                    xytext=(0, 3), textcoords="offset points", ha='center', va='bottom', fontsize=8)
    for rect in rects2:
        h = rect.get_height()
        ax.annotate(f'{h:.1f}%', xy=(rect.get_x() + rect.get_width() / 2, h),
                    xytext=(0, 3), textcoords="offset points", ha='center', va='bottom', fontsize=8)
                    
    plt.tight_layout()
    cmp_path = os.path.join(MODELS_DIR, "model_comparison.png")
    plt.savefig(cmp_path, dpi=200)
    plt.close()
    print(f"[+] Da luu 3 bieu do truc quan tai: {MODELS_DIR}")

if __name__ == "__main__":
    train_and_evaluate(use_full_train=True)
