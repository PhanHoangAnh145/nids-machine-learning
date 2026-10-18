"""
ĐÁNH GIÁ TỔNG HỢP: chạy model đã train trên CẢ dữ liệu cũ LẪN dữ liệu mới
trong một lần, rồi in bảng so sánh.

  [1] NSL-KDD Validation 20%  - tách lại ĐÚNG như src/train.py (random_state=42,
                                stratify) -> tấn công đã biết
  [2] NSL-KDD KDDTest+        - tấn công mới/biến thể
  [3] UNSW-NB15               - bộ dữ liệu ngoài (tự tìm trong data/external/unsw_nb15/)

KHÔNG sửa code cũ, KHÔNG ghi vào models/. Kết quả lưu ở
reports/cross_dataset/full_eval_<thời gian>/.

Cách chạy (từ thư mục gốc dự án):
    python -m cross_dataset.evaluate_all
    python -m cross_dataset.evaluate_all --download-unsw     # tải UNSW-NB15 testing-set (~15 MB) nếu chưa có
    python -m cross_dataset.evaluate_all --unsw-sample 200000 # chạy nhanh trên file gốc lớn
Hoặc mở file này trong IDE và bấm Run.
"""
import argparse
import glob
import json
import os
import sys
import time
from datetime import datetime

if __package__ in (None, ""):          # cho phép bấm Run trực tiếp file này trong IDE
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

from cross_dataset import config as C  # noqa: E402
from cross_dataset.adapters import get_adapter  # noqa: E402
from cross_dataset.evaluate import (  # noqa: E402
    compute_metrics, predict_in_batches, print_summary, save_confusion_plots, save_json,
)
from cross_dataset.kdd_schema import KDDSchema  # noqa: E402

RAW_NSL_DIR = os.path.join(C.PROJECT_ROOT, "data", "raw")
UNSW_DIR = os.path.join(C.EXTERNAL_DATA_DIR, "unsw_nb15")

# Nguồn tải UNSW-NB15 testing-set (bản sao công khai trên GitHub, phục vụ qua
# jsDelivr - cùng CDN mà src/download_data.py dùng cho NSL-KDD). Thử lần lượt.
UNSW_TESTING_MIRRORS = [
    "https://cdn.jsdelivr.net/gh/ishaak15/UNSW-IDS-Feature-Selection@main/UNSW_NB15_testing-set.csv",
    "https://cdn.jsdelivr.net/gh/Nir-J/ML-Projects@master/UNSW-Network_Packet_Classification/UNSW_NB15_testing-set.csv",
]
UNSW_TESTING_ROWS = 82_332            # số dòng chuẩn của bản phát hành chính thức
UNSW_REQUIRED_COLS = {"proto", "service", "state", "sbytes", "dbytes", "attack_cat", "label"}


# ----------------------------------------------------------------------
# Tải UNSW-NB15 (tùy chọn)
# ----------------------------------------------------------------------
def download_unsw_testing(dest_dir: str = UNSW_DIR) -> str:
    import requests
    os.makedirs(dest_dir, exist_ok=True)
    dest = os.path.join(dest_dir, "UNSW_NB15_testing-set.csv")
    if os.path.exists(dest) and os.path.getsize(dest) > 1_000_000:
        print(f"[i] Da co san: {dest}")
        return dest
    tmp = dest + ".part"
    for url in UNSW_TESTING_MIRRORS:
        print(f"[*] Dang tai UNSW-NB15 testing-set tu: {url}")
        try:
            with requests.get(url, stream=True, timeout=60) as r:
                r.raise_for_status()
                total = int(r.headers.get("content-length", 0))
                done = 0
                with open(tmp, "wb") as f:
                    for chunk in r.iter_content(1 << 16):
                        f.write(chunk)
                        done += len(chunk)
                        if total:
                            print(f"\r    {done / 1e6:6.2f} / {total / 1e6:.2f} MB", end="")
            print()
            # Kiểm tra tính toàn vẹn trước khi dùng
            df = pd.read_csv(tmp, low_memory=False)
            cols = {c.strip().lower() for c in df.columns}
            if not UNSW_REQUIRED_COLS <= cols:
                raise ValueError(f"thieu cot {UNSW_REQUIRED_COLS - cols}")
            if len(df) != UNSW_TESTING_ROWS:
                print(f"    [!] So dong {len(df):,} khac ban chuan {UNSW_TESTING_ROWS:,} - van dung, nhung hay kiem tra lai nguon")
            os.replace(tmp, dest)
            print(f"[+] Da luu: {dest} ({len(df):,} dong)")
            return dest
        except Exception as e:  # thử mirror tiếp theo
            print(f"    [-] That bai: {e}")
            if os.path.exists(tmp):
                os.remove(tmp)
    raise RuntimeError(
        "Khong tai duoc UNSW-NB15. Hay tai thu cong tu https://research.unsw.edu.au/projects/unsw-nb15-dataset "
        f"va dat file vao {dest_dir}"
    )


def discover_unsw_files(unsw_dir: str = UNSW_DIR):
    """Ưu tiên 4 file gốc (độ trung thực cao) > testing-set > training-set."""
    raw = sorted(glob.glob(os.path.join(unsw_dir, "UNSW-NB15_[1-4].csv")))
    if raw:
        return raw, "file goc UNSW-NB15_1..4 (do trung thuc cao)"
    for name in ("UNSW_NB15_testing-set.csv", "UNSW_NB15_training-set.csv"):
        p = os.path.join(unsw_dir, name)
        if os.path.exists(p):
            return [p], f"{name} (dac trung traffic xap xi)"
    return [], None


# ----------------------------------------------------------------------
# Các tập dữ liệu
# ----------------------------------------------------------------------
def nsl_validation_split(schema: KDDSchema):
    """
    Tái tạo tập Validation 20% y hệt src/train.py:
      train_df = KDDTrain+.txt ; X = preprocessor.transform ; train_test_split(test_size=0.2,
      random_state=42, stratify=y). preprocessor.joblib được fit trên chính KDDTrain+
      nên transform cho ra ma trận giống hệt lúc train.
    """
    from sklearn.model_selection import train_test_split
    adapter = get_adapter("nsl-kdd")               # dùng lại hàm đọc + gán nhãn của luồng cũ
    path = os.path.join(RAW_NSL_DIR, "KDDTrain+.txt")
    df = adapter.run([path])
    aligned = schema.align(df)
    X = schema.transform(aligned)
    y = schema.label_encoder.transform(df["attack_category"])
    idx = np.arange(len(df))
    _, idx_val = train_test_split(idx, test_size=0.2, random_state=42, stratify=y)
    return df.iloc[idx_val].reset_index(drop=True), X[idx_val]


def evaluate_frame(model, schema, df, X=None, batch_size=200_000):
    """Trả về (metrics, y_pred). Nếu đã có X (ma trận đã transform) thì dùng luôn."""
    if X is None:
        aligned = schema.align(df)
        y_pred, p_attack = predict_in_batches(model, schema, aligned, batch_size)
    else:
        proba = model.predict_proba(X)
        idx = np.asarray(model.classes_)[proba.argmax(axis=1)]
        y_pred = schema.label_encoder.inverse_transform(idx.astype(int))
        normal_col = list(model.classes_).index(schema.class_labels.index("normal"))
        p_attack = 1.0 - proba[:, normal_col]
    m = compute_metrics(df["attack_category"], y_pred, schema.class_labels,
                        source_label=df["source_label"], p_attack=p_attack)
    return m, y_pred


def row_of(name, m):
    b, mc = m["binary"], m["multiclass"]
    return {
        "Tap du lieu": name,
        "So mau": m["n_samples"],
        "Acc 5 lop": mc["accuracy"],
        "F1 5 lop (w)": mc["f1_weighted"],
        "Acc nhi phan": b["accuracy"],
        "Precision": b["precision"],
        "Recall (DR)": b["recall_detection_rate"],
        "F1 nhi phan": b["f1"],
        "FPR": b["false_positive_rate"],
        "ROC-AUC": b.get("roc_auc", float("nan")),
    }


def print_table(rows):
    df = pd.DataFrame(rows)
    pct_cols = [c for c in df.columns if c not in ("Tap du lieu", "So mau", "ROC-AUC")]
    show = df.copy()
    for c in pct_cols:
        show[c] = show[c].map(lambda v: f"{v * 100:6.2f}%")
    show["ROC-AUC"] = show["ROC-AUC"].map(lambda v: "  -  " if pd.isna(v) else f"{v:.4f}")
    show["So mau"] = show["So mau"].map(lambda v: f"{v:,}")
    print("\n" + "=" * 118)
    print("  BANG SO SANH TONG HOP - MODEL TRAIN TREN NSL-KDD, KIEM THU TREN DU LIEU CU + MOI")
    print("=" * 118)
    print(show.to_string(index=False))
    print("=" * 118)
    return df


def plot_comparison(df, out_dir):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    metrics = ["Acc 5 lop", "Acc nhi phan", "Precision", "Recall (DR)", "F1 nhi phan"]
    x = np.arange(len(metrics))
    w = 0.8 / max(len(df), 1)
    colors = ["#2a78d6", "#e08a1e", "#1f9e74", "#b84a8c"]
    fig, ax = plt.subplots(figsize=(11, 5.5))
    for i, (_, r) in enumerate(df.iterrows()):
        vals = [r[m] * 100 for m in metrics]
        bars = ax.bar(x + (i - (len(df) - 1) / 2) * w, vals, w, label=r["Tap du lieu"],
                      color=colors[i % len(colors)])
        for b in bars:
            ax.annotate(f"{b.get_height():.1f}", (b.get_x() + b.get_width() / 2, b.get_height()),
                        xytext=(0, 2), textcoords="offset points", ha="center", fontsize=7)
    ax.set_xticks(x)
    ax.set_xticklabels(metrics)
    ax.set_ylim(0, 108)
    ax.set_ylabel("%")
    ax.set_title("So sanh hieu nang model NSL-KDD tren du lieu cu va moi", fontweight="bold")
    ax.legend(loc="upper center", bbox_to_anchor=(0.5, -0.08), ncol=len(df), fontsize=8, frameon=False)
    ax.grid(axis="y", linestyle="--", alpha=0.4)
    plt.tight_layout()
    path = os.path.join(out_dir, "comparison.png")
    plt.savefig(path, dpi=150)
    plt.close(fig)
    return path


# ----------------------------------------------------------------------
def main(argv=None):
    ap = argparse.ArgumentParser(description="Danh gia tong hop du lieu cu + moi")
    ap.add_argument("--model", default=C.DEFAULT_MODEL_PATH)
    ap.add_argument("--preprocessor", default=C.DEFAULT_PREPROCESSOR_PATH)
    ap.add_argument("--unsw", nargs="*", default=None,
                    help="File UNSW-NB15 cu the (mac dinh: tu tim trong data/external/unsw_nb15/)")
    ap.add_argument("--download-unsw", action="store_true",
                    help="Tai UNSW_NB15_testing-set.csv (~15 MB) neu chua co")
    ap.add_argument("--unsw-sample", type=int, default=None,
                    help="Lay mau N dong UNSW (sau khi tinh dac trung) de chay nhanh")
    ap.add_argument("--out", default=C.REPORTS_DIR)
    args = ap.parse_args(argv)

    if os.path.realpath(args.out).startswith(os.path.realpath(C.LEGACY_MODELS_DIR)):
        raise SystemExit("[!] Tu choi ghi vao models/.")

    t0 = time.time()
    out_dir = os.path.join(args.out, f"full_eval_{datetime.now():%Y%m%d_%H%M%S}")
    os.makedirs(out_dir, exist_ok=True)

    print("[*] Nap model va preprocessor (chi doc)...")
    model = joblib.load(args.model)
    schema = KDDSchema.from_preprocessor(args.preprocessor)

    rows, details = [], {}

    # [1] Validation 20%
    print("\n[1/3] NSL-KDD Validation 20% (tach lai giong src/train.py)...")
    df_val, X_val = nsl_validation_split(schema)
    m, _ = evaluate_frame(model, schema, df_val, X=X_val)
    name = "NSL-KDD Val 20% (da biet)"
    print_summary(m, name)
    rows.append(row_of(name, m)); details[name] = m

    # [2] KDDTest+
    print("\n[2/3] NSL-KDD KDDTest+ ...")
    df_test = get_adapter("nsl-kdd").run([os.path.join(RAW_NSL_DIR, "KDDTest+.txt")])
    m, _ = evaluate_frame(model, schema, df_test)
    name = "NSL-KDD KDDTest+ (moi la)"
    print_summary(m, name)
    rows.append(row_of(name, m)); details[name] = m

    # [3] UNSW-NB15
    print("\n[3/3] UNSW-NB15 (du lieu ngoai)...")
    unsw_files, desc = (args.unsw, "do nguoi dung chi dinh") if args.unsw else discover_unsw_files()
    if not unsw_files and args.download_unsw:
        download_unsw_testing()
        unsw_files, desc = discover_unsw_files()
    if unsw_files:
        print(f"    Nguon: {desc}")
        for p in unsw_files:
            print(f"      - {p}")
        adapter = get_adapter("unsw-nb15")
        df_unsw = adapter.run(unsw_files, sample=args.unsw_sample)
        for note in adapter.notes:
            print(f"    [i] {note}")
        m, _ = evaluate_frame(model, schema, df_unsw)
        name = "UNSW-NB15 (bo du lieu ngoai)"
        print_summary(m, name)
        rows.append(row_of(name, m)); details[name] = m
        details[name]["feature_provenance"] = adapter.provenance
    else:
        print("    [!] CHUA CO DU LIEU UNSW-NB15 -> bo qua.")
        print(f"        Dat file vao {UNSW_DIR} hoac chay lai voi --download-unsw")

    # Đối chiếu với luồng cũ
    base_path = os.path.join(C.LEGACY_MODELS_DIR, "evaluation_results.json")
    check = {}
    if os.path.exists(base_path):
        with open(base_path, encoding="utf-8") as f:
            rf = json.load(f).get("Random Forest", {})
        check = {
            "val_accuracy": (rows[0]["Acc 5 lop"], rf.get("val_accuracy")),
            "test_accuracy": (rows[1]["Acc 5 lop"], rf.get("test_accuracy")),
        }
        print("\n[Doi chieu voi models/evaluation_results.json cua luong cu]")
        for k, (new, old) in check.items():
            ok = old is not None and abs(new - old) < 1e-9
            print(f"  {k:<14}: moi={new:.6f}  cu={old:.6f}  {'KHOP' if ok else 'LECH'}")

    table = print_table(rows)
    table.to_csv(os.path.join(out_dir, "summary.csv"), index=False, encoding="utf-8-sig")
    chart = plot_comparison(table, out_dir)
    for name, m in details.items():
        sub = os.path.join(out_dir, "".join(ch if ch.isalnum() else "_" for ch in name).strip("_"))
        os.makedirs(sub, exist_ok=True)
        save_json(m, os.path.join(sub, "metrics.json"))
        save_confusion_plots(m, sub, name)
    save_json({"run_at": datetime.now().isoformat(timespec="seconds"),
               "elapsed_sec": round(time.time() - t0, 1),
               "baseline_check": check, "summary": rows}, os.path.join(out_dir, "summary.json"))
    print(f"\n[+] Bang so sanh : {os.path.join(out_dir, 'summary.csv')}")
    print(f"[+] Bieu do      : {chart}")
    print(f"[+] Chi tiet     : {out_dir}  ({time.time() - t0:.0f}s)")
    return rows


if __name__ == "__main__":
    main()
