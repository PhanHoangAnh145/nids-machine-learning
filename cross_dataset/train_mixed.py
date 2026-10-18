"""
TRAIN MODEL MỚI TRÊN DỮ LIỆU TRỘN NSL-KDD + UNSW-NB15, rồi so sánh với model cũ.

Model cũ (models/best_model.joblib) chỉ học NSL-KDD nên gần như không nhận ra
tấn công trong UNSW-NB15 (Recall ~0,1%). Script này train một Random Forest mới
(cùng siêu tham số với src/train.py) trên:
    80% KDDTrain+  (đúng phần train của luồng cũ, random_state=42, stratify)
  + 80% UNSW-NB15  (tách stratify theo loại tấn công gốc, random_state=42)

rồi đánh giá CẢ HAI model trên cùng 3 tập kiểm thử không dùng để train:
    [1] NSL-KDD Validation 20%   [2] NSL-KDD KDDTest+   [3] UNSW-NB15 20% giữ lại

KHÔNG ghi đè model cũ: model mới lưu ở models/mixed/ (cùng định dạng .joblib
nên NIDSPredictor / cross_dataset đều nạp được). main.py vẫn dùng model cũ.

Chạy: python -m cross_dataset.train_mixed      (hoặc bấm Run file này trong IDE)
      thêm --download-unsw nếu máy chưa có dữ liệu UNSW-NB15.
"""
import argparse
import json
import os
import sys
import time
from datetime import datetime

if __package__ in (None, ""):
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

import joblib  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402
from sklearn.compose import ColumnTransformer  # noqa: E402
from sklearn.ensemble import RandomForestClassifier  # noqa: E402
from sklearn.model_selection import train_test_split  # noqa: E402
from sklearn.preprocessing import LabelEncoder, OneHotEncoder, StandardScaler  # noqa: E402

from cross_dataset import config as C  # noqa: E402
from cross_dataset.adapters import get_adapter  # noqa: E402
from cross_dataset.evaluate import (  # noqa: E402
    compute_metrics, predict_in_batches, print_summary, save_confusion_plots, save_json,
)
from cross_dataset.evaluate_all import (  # noqa: E402
    RAW_NSL_DIR, discover_unsw_files, download_unsw_testing, print_table, row_of,
)
from cross_dataset.kdd_schema import KDDSchema  # noqa: E402

MIXED_DIR = os.path.join(C.LEGACY_MODELS_DIR, "mixed")
RS = 42


def load_data(legacy: KDDSchema, download: bool):
    """Trả về các DataFrame 41 cột KDD + attack_category + source_label."""
    nsl = get_adapter("nsl-kdd")
    df_tr = nsl.run([os.path.join(RAW_NSL_DIR, "KDDTrain+.txt")])
    y = legacy.label_encoder.transform(df_tr["attack_category"])
    idx = np.arange(len(df_tr))
    i_tr, i_val = train_test_split(idx, test_size=0.2, random_state=RS, stratify=y)   # y hệt src/train.py
    nsl_train, nsl_val = df_tr.iloc[i_tr], df_tr.iloc[i_val]
    nsl_test = nsl.run([os.path.join(RAW_NSL_DIR, "KDDTest+.txt")])

    files, desc = discover_unsw_files()
    if not files and download:
        download_unsw_testing()
        files, desc = discover_unsw_files()
    if not files:
        raise SystemExit("[!] Chua co du lieu UNSW-NB15. Chay lai voi --download-unsw "
                         "hoac dat file vao data/external/unsw_nb15/")
    print(f"    UNSW-NB15: {desc}")
    unsw = get_adapter("unsw-nb15").run(files)
    u_tr, u_te = train_test_split(unsw, test_size=0.2, random_state=RS,
                                  stratify=unsw["source_label"])
    return nsl_train, nsl_val, nsl_test, u_tr, u_te, files


def fit_preprocessor(legacy: KDDSchema, train_df: pd.DataFrame):
    """ColumnTransformer giống hệt NIDSDataProcessor cũ, nhưng fit trên dữ liệu trộn."""
    ct = ColumnTransformer([
        ("num", StandardScaler(), legacy.numerical_features),
        ("cat", OneHotEncoder(handle_unknown="ignore", sparse_output=False), legacy.categorical_features),
    ])
    X = ct.fit_transform(legacy.align(train_df))
    cat_names = ct.named_transformers_["cat"].get_feature_names_out(legacy.categorical_features).tolist()
    le = LabelEncoder().fit(legacy.class_labels)
    return ct, le, X, legacy.numerical_features + cat_names


def evaluate(model, schema, df):
    y_pred, p_att = predict_in_batches(model, schema, schema.align(df))
    return compute_metrics(df["attack_category"], y_pred, schema.class_labels,
                           source_label=df["source_label"], p_attack=p_att)


def plot_old_vs_new(rows_old, rows_new, out_dir):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    sets = [r["Tap du lieu"] for r in rows_old]
    fig, axes = plt.subplots(1, 2, figsize=(13, 5))
    for ax, metric in zip(axes, ["F1 nhi phan", "Recall (DR)"]):
        x = np.arange(len(sets))
        old = [r[metric] * 100 for r in rows_old]
        new = [r[metric] * 100 for r in rows_new]
        for off, vals, lab, col in ((-0.2, old, "Model cu (NSL-KDD)", "#8a8f98"),
                                    (0.2, new, "Model moi (NSL-KDD + UNSW)", "#2a78d6")):
            bars = ax.bar(x + off, vals, 0.4, label=lab, color=col)
            for b in bars:
                ax.annotate(f"{b.get_height():.1f}", (b.get_x() + b.get_width() / 2, b.get_height()),
                            xytext=(0, 2), textcoords="offset points", ha="center", fontsize=8)
        ax.set_xticks(x)
        ax.set_xticklabels([s.replace(" (", "\n(") for s in sets], fontsize=8)
        ax.set_ylim(0, 110)
        ax.set_title(metric, fontweight="bold")
        ax.grid(axis="y", linestyle="--", alpha=0.4)
    fig.suptitle("Model cu vs model moi tren cung cac tap kiem thu", fontweight="bold")
    plt.tight_layout(rect=(0, 0.07, 1, 1))
    handles, labels = axes[0].get_legend_handles_labels()
    fig.legend(handles, labels, loc="lower center", ncol=2, frameon=False)
    path = os.path.join(out_dir, "old_vs_new.png")
    plt.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    return path


def main(argv=None):
    ap = argparse.ArgumentParser(description="Train RF tren NSL-KDD + UNSW-NB15 va so sanh voi model cu")
    ap.add_argument("--download-unsw", action="store_true")
    ap.add_argument("--n-estimators", type=int, default=100)
    args = ap.parse_args(argv)
    t0 = time.time()

    print("=" * 80)
    print("  TRAIN MODEL TREN DU LIEU TRON NSL-KDD + UNSW-NB15")
    print("=" * 80)
    legacy_model = joblib.load(C.DEFAULT_MODEL_PATH)
    legacy = KDDSchema.from_preprocessor(C.DEFAULT_PREPROCESSOR_PATH)

    print("[*] 1. Doc va anh xa du lieu...")
    nsl_train, nsl_val, nsl_test, u_tr, u_te, unsw_files = load_data(legacy, args.download_unsw)
    train_df = pd.concat([nsl_train, u_tr], ignore_index=True)
    print(f"    Train: {len(nsl_train):,} NSL-KDD + {len(u_tr):,} UNSW = {len(train_df):,} mau")
    print(f"    Phan bo lop train: {train_df['attack_category'].value_counts().to_dict()}")

    print("[*] 2. Fit preprocessor moi (StandardScaler + OneHot) tren du lieu tron...")
    ct, le, X_train, feat_names = fit_preprocessor(legacy, train_df)
    y_train = le.transform(train_df["attack_category"])
    print(f"    So chieu dac trung: {X_train.shape[1]}")

    print("[*] 3. Train Random Forest (cung sieu tham so src/train.py)...")
    t1 = time.time()
    model = RandomForestClassifier(n_estimators=args.n_estimators, max_depth=20,
                                   class_weight="balanced", random_state=RS, n_jobs=-1)
    model.fit(X_train, y_train)
    train_time = time.time() - t1
    print(f"    Xong sau {train_time:.1f}s")

    # Lưu theo đúng định dạng preprocessor.joblib cũ -> các module khác nạp được
    os.makedirs(MIXED_DIR, exist_ok=True)
    prep_path = os.path.join(MIXED_DIR, "preprocessor.joblib")
    model_path = os.path.join(MIXED_DIR, "best_model.joblib")
    legacy_meta = joblib.load(C.DEFAULT_PREPROCESSOR_PATH)
    joblib.dump({
        "column_transformer": ct, "label_encoder": le,
        "feature_names": legacy.feature_names,
        "numerical_features": legacy.numerical_features,
        "categorical_features": legacy.categorical_features,
        "transformed_feature_names": feat_names,
        "class_labels": legacy.class_labels,
        "class_display_names": legacy_meta.get("class_display_names", {}),
    }, prep_path)
    joblib.dump(model, model_path, compress=3)
    print(f"[+] Da luu: {model_path}")
    print(f"[+] Da luu: {prep_path}")
    new = KDDSchema.from_preprocessor(prep_path)

    print("[*] 4. Danh gia model CU va MOI tren cung 3 tap kiem thu...")
    tests = [("NSL-KDD Val 20% (da biet)", nsl_val),
             ("NSL-KDD KDDTest+ (moi la)", nsl_test),
             ("UNSW-NB15 20% giu lai", u_te)]
    rows_old, rows_new, details = [], [], {}
    for name, df in tests:
        m_old = evaluate(legacy_model, legacy, df)
        m_new = evaluate(model, new, df)
        rows_old.append(row_of(name, m_old))
        rows_new.append(row_of(name, m_new))
        details[name] = {"old": m_old, "new": m_new}
        print_summary(m_new, f"MODEL MOI - {name}")

    print("\n>>> MODEL CU (chi NSL-KDD)")
    t_old = print_table(rows_old)
    print("\n>>> MODEL MOI (NSL-KDD + UNSW-NB15)")
    t_new = print_table(rows_new)

    out_dir = os.path.join(C.REPORTS_DIR, f"mixed_train_{datetime.now():%Y%m%d_%H%M%S}")
    os.makedirs(out_dir, exist_ok=True)
    t_old.insert(0, "Model", "cu")
    t_new.insert(0, "Model", "moi")
    pd.concat([t_old, t_new]).to_csv(os.path.join(out_dir, "summary.csv"), index=False, encoding="utf-8-sig")
    chart = plot_old_vs_new(rows_old, rows_new, out_dir)
    for name, d in details.items():
        sub = os.path.join(out_dir, "".join(ch if ch.isalnum() else "_" for ch in name).strip("_"))
        os.makedirs(sub, exist_ok=True)
        save_json(d, os.path.join(sub, "metrics.json"))
        save_confusion_plots(d["new"], sub, f"Model moi - {name}")

    info = {
        "trained_at": datetime.now().isoformat(timespec="seconds"),
        "train_samples": {"nsl_kdd": len(nsl_train), "unsw_nb15": len(u_tr)},
        "unsw_files": [os.path.basename(p) for p in unsw_files],
        "random_state": RS, "train_time_sec": round(train_time, 1),
        "params": model.get_params(),
        "results_old_model": rows_old, "results_new_model": rows_new,
    }
    with open(os.path.join(MIXED_DIR, "evaluation_results.json"), "w", encoding="utf-8") as f:
        json.dump(info, f, ensure_ascii=False, indent=2, default=str)

    print(f"\n[+] Bao cao  : {out_dir}")
    print(f"[+] Bieu do  : {chart}")
    print(f"[v] HOAN TAT sau {time.time() - t0:.0f}s")
    return rows_old, rows_new


if __name__ == "__main__":
    main()
