"""
Script INFERENCE độc lập: nạp model NSL-KDD đã train, chạy trên dataset khác
và in / lưu chỉ số đánh giá. KHÔNG ghi gì vào models/ hay src/.

Chạy từ thư mục gốc dự án (nids-machine-learning/):

  # 0) Đối chứng: chạy lại KDDTest+ qua pipeline mới -> phải khớp evaluation_results.json
  python -m cross_dataset.run_inference --dataset nsl-kdd --input data/raw/KDDTest+.txt --compare-baseline

  # 1) UNSW-NB15 file gốc (khuyến nghị) - có thể truyền 1..4 file
  python -m cross_dataset.run_inference --dataset unsw-nb15 \
      --input data/external/unsw_nb15/UNSW-NB15_1.csv data/external/unsw_nb15/UNSW-NB15_2.csv

  # 2) UNSW-NB15 file chia sẵn
  python -m cross_dataset.run_inference --dataset unsw-nb15 \
      --input data/external/unsw_nb15/UNSW_NB15_testing-set.csv
"""
import argparse
import os
import sys
import time
from datetime import datetime

if __package__ in (None, ""):          # cho phép chạy: python cross_dataset/run_inference.py
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

import joblib  # noqa: E402
import pandas as pd  # noqa: E402

from cross_dataset import config as C  # noqa: E402
from cross_dataset.adapters import get_adapter, list_adapters  # noqa: E402
from cross_dataset.evaluate import (  # noqa: E402
    compute_metrics, predict_in_batches, print_summary, save_confusion_plots, save_json,
)
from cross_dataset.kdd_schema import KDDSchema  # noqa: E402


def parse_args(argv=None):
    p = argparse.ArgumentParser(description="Đánh giá chéo model NIDS (train trên NSL-KDD) với dataset khác")
    p.add_argument("--dataset", required=True, choices=list_adapters())
    p.add_argument("--input", required=True, nargs="+", help="Một hoặc nhiều file dữ liệu")
    p.add_argument("--model", default=C.DEFAULT_MODEL_PATH)
    p.add_argument("--preprocessor", default=C.DEFAULT_PREPROCESSOR_PATH)
    p.add_argument("--sample", type=int, default=None,
                   help="Lấy ngẫu nhiên N dòng SAU khi đã tính đặc trưng (để chạy nhanh)")
    p.add_argument("--batch-size", type=int, default=200_000)
    p.add_argument("--out", default=C.REPORTS_DIR, help="Thư mục gốc lưu báo cáo")
    p.add_argument("--save-predictions", action="store_true",
                   help="Lưu predictions.csv (41 đặc trưng + nhãn thật + dự đoán)")
    p.add_argument("--no-plots", action="store_true")
    p.add_argument("--compare-baseline", action="store_true",
                   help="So sánh với models/evaluation_results.json (dùng cho --dataset nsl-kdd)")
    p.add_argument("--unknown-service", default=None,
                   help="Service NSL-KDD gán khi không suy ra được (mặc định 'other')")
    p.add_argument("--no-logged-in-heuristic", action="store_true")
    return p.parse_args(argv)


def _guard_output_dir(out_dir: str):
    """Không cho phép ghi đè vào thư mục models/ của luồng cũ."""
    legacy = os.path.realpath(C.LEGACY_MODELS_DIR)
    target = os.path.realpath(out_dir)
    if target == legacy or target.startswith(legacy + os.sep):
        raise SystemExit("[!] Từ chối ghi vào models/ - hãy chọn thư mục --out khác.")


def main(argv=None):
    args = parse_args(argv)
    _guard_output_dir(args.out)          # kiểm tra sớm, trước khi tốn thời gian xử lý
    t0 = time.time()

    # 1. Nạp artifacts cũ (CHỈ ĐỌC)
    print(f"[*] Nap model        : {args.model}")
    print(f"[*] Nap preprocessor : {args.preprocessor}")
    model = joblib.load(args.model)
    schema = KDDSchema.from_preprocessor(args.preprocessor)
    if getattr(model, "n_features_in_", schema.transformed_dim) != schema.transformed_dim:
        raise SystemExit("[!] Model và preprocessor không khớp số chiều.")
    print(f"    -> {len(schema.feature_names)} cot tho -> {schema.transformed_dim} chieu, lop: {schema.class_labels}")

    # 2. Adapter: dataset mới -> 41 cột NSL-KDD
    opts = {}
    if args.unknown_service:
        opts["unknown_service"] = args.unknown_service
    if args.no_logged_in_heuristic:
        opts["logged_in_heuristic"] = False
    adapter = get_adapter(args.dataset, **opts)
    print(f"[*] Doc & anh xa du lieu ({args.dataset}) tu {len(args.input)} file...")
    kdd_df = adapter.run(args.input, sample=args.sample)
    for note in adapter.notes:
        print(f"    [i] {note}")
    print(f"    -> {len(kdd_df):,} mau sau anh xa ({time.time() - t0:.1f}s)")

    aligned = schema.align(kdd_df)
    coverage = schema.coverage_report(aligned)
    for feat, r in coverage.items():
        if r["unknown_ratio"] > 0:
            print(f"    [!] {feat}: {r['unknown_ratio'] * 100:.2f}% gia tri ngoai tu vung NSL-KDD "
                  f"(vd: {list(r['top_unknown_values'])[:5]}) -> one-hot = 0")

    # 3. Dự đoán
    print("[*] Dang du doan...")
    y_pred, p_attack = predict_in_batches(model, schema, aligned, args.batch_size)

    # 4. Đánh giá
    metrics = compute_metrics(kdd_df["attack_category"], y_pred, schema.class_labels,
                              source_label=kdd_df["source_label"], p_attack=p_attack)
    print_summary(metrics, args.dataset)

    report = {
        "dataset": args.dataset,
        "inputs": [os.path.abspath(p) for p in args.input],
        "model": os.path.abspath(args.model),
        "preprocessor": os.path.abspath(args.preprocessor),
        "sample": args.sample,
        "run_at": datetime.now().isoformat(timespec="seconds"),
        "elapsed_sec": round(time.time() - t0, 2),
        "adapter_notes": adapter.notes,
        "feature_provenance": adapter.provenance,
        "categorical_coverage": coverage,
        "top_feature_drift_vs_nslkdd_train": schema.drift_report(aligned),
        "metrics": metrics,
    }

    if args.compare_baseline:
        report["baseline_comparison"] = compare_with_baseline(metrics)

    # 5. Lưu báo cáo vào thư mục RIÊNG
    out_dir = os.path.join(args.out, f"{args.dataset}_{datetime.now():%Y%m%d_%H%M%S}")
    _guard_output_dir(out_dir)
    os.makedirs(out_dir, exist_ok=True)
    save_json(report, os.path.join(out_dir, "metrics.json"))
    aligned.head(200).assign(attack_category=kdd_df["attack_category"].head(200).values,
                             source_label=kdd_df["source_label"].head(200).values) \
        .to_csv(os.path.join(out_dir, "mapped_features_sample.csv"), index=False)
    if args.save_predictions:
        pred_df = aligned.copy()
        pred_df["true_category"] = kdd_df["attack_category"].values
        pred_df["source_label"] = kdd_df["source_label"].values
        pred_df["predicted_category"] = y_pred
        if p_attack is not None:
            pred_df["p_attack"] = p_attack
        pred_df.to_csv(os.path.join(out_dir, "predictions.csv"), index=False)
    if not args.no_plots:
        save_confusion_plots(metrics, out_dir, args.dataset)
    print(f"[+] Da luu bao cao tai: {out_dir}")
    return report


def compare_with_baseline(metrics):
    """Đối chiếu với kết quả Random Forest do src/train.py lưu (chỉ đọc)."""
    path = os.path.join(C.LEGACY_MODELS_DIR, "evaluation_results.json")
    if not os.path.exists(path):
        print("[!] Khong tim thay evaluation_results.json de doi chieu.")
        return None
    base = pd.read_json(path, typ="series")
    rf = base.get(base.get("best_model", "Random Forest"))
    pairs = {
        "accuracy": (metrics["multiclass"]["accuracy"], rf["test_accuracy"]),
        "f1_weighted": (metrics["multiclass"]["f1_weighted"], rf["test_f1_weighted"]),
        "binary_precision": (metrics["binary"]["precision"], rf["binary_precision"]),
        "binary_recall": (metrics["binary"]["recall_detection_rate"], rf["binary_recall"]),
    }
    print("\n[Doi chieu voi luong cu - models/evaluation_results.json]")
    ok = True
    for k, (new, old) in pairs.items():
        match = abs(new - old) < 1e-9
        ok &= match
        print(f"  {k:<18}: moi={new:.6f}  cu={old:.6f}  {'KHOP' if match else 'LECH'}")
    print(f"  => {'PIPELINE MOI TAI LAP CHINH XAC LUONG CU' if ok else 'CO CHENH LECH - kiem tra lai!'}")
    return {k: {"new": v[0], "legacy": v[1]} for k, v in pairs.items()} | {"exact_match": bool(ok)}


if __name__ == "__main__":
    main()
