"""
Dự đoán theo lô + tính chỉ số đánh giá cho dữ liệu đã ánh xạ về NSL-KDD.
Độc lập với dataset: chỉ cần DataFrame từ Adapter.
"""
import json
import os
from typing import Dict, Optional

import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score, classification_report, confusion_matrix, f1_score,
    precision_score, recall_score, roc_auc_score,
)

from .kdd_schema import KDDSchema


# ----------------------------------------------------------------------
# DỰ ĐOÁN
# ----------------------------------------------------------------------
def predict_in_batches(model, schema: KDDSchema, aligned: pd.DataFrame,
                       batch_size: int = 200_000):
    """
    Transform + predict theo lô để chạy được hàng triệu dòng
    (2,5 triệu dòng x 122 chiều float64 ~ 2,4 GB nếu làm một lần).
    Trả về (nhãn dự đoán dạng chuỗi, xác suất là tấn công hoặc None).
    """
    preds, p_attack = [], []
    has_proba = hasattr(model, "predict_proba")
    normal_idx = schema.class_labels.index("normal")
    for start in range(0, len(aligned), batch_size):
        X = schema.transform(aligned.iloc[start:start + batch_size])
        if has_proba:
            proba = model.predict_proba(X)
            idx = np.asarray(model.classes_)[proba.argmax(axis=1)]
            p_attack.append(1.0 - proba[:, list(model.classes_).index(normal_idx)])
        else:
            idx = model.predict(X)
        preds.append(schema.label_encoder.inverse_transform(idx.astype(int)))
    y_pred = np.concatenate(preds) if preds else np.array([], dtype=str)
    return y_pred, (np.concatenate(p_attack) if has_proba and p_attack else None)


# ----------------------------------------------------------------------
# CHỈ SỐ
# ----------------------------------------------------------------------
def compute_metrics(y_true, y_pred, class_labels, source_label=None,
                    p_attack: Optional[np.ndarray] = None) -> Dict:
    y_true = np.asarray(y_true).astype(str)
    y_pred = np.asarray(y_pred).astype(str)
    present = [c for c in class_labels if c in set(y_true) | set(y_pred)]

    res = {"n_samples": int(len(y_true))}

    # Đa lớp (5 lớp KDD)
    res["multiclass"] = {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision_weighted": float(precision_score(y_true, y_pred, average="weighted", zero_division=0)),
        "recall_weighted": float(recall_score(y_true, y_pred, average="weighted", zero_division=0)),
        "f1_weighted": float(f1_score(y_true, y_pred, average="weighted", zero_division=0)),
        "f1_macro": float(f1_score(y_true, y_pred, labels=present, average="macro", zero_division=0)),
        "labels": list(class_labels),
        "confusion_matrix": confusion_matrix(y_true, y_pred, labels=class_labels).tolist(),
        "classification_report": classification_report(
            y_true, y_pred, labels=present, zero_division=0, output_dict=True),
        "true_distribution": pd.Series(y_true).value_counts().to_dict(),
        "pred_distribution": pd.Series(y_pred).value_counts().to_dict(),
    }

    # Nhị phân (Normal vs Attack) - thước đo chính khi đánh giá chéo
    bt = (y_true != "normal").astype(int)
    bp = (y_pred != "normal").astype(int)
    tn, fp, fn, tp = confusion_matrix(bt, bp, labels=[0, 1]).ravel()
    binary = {
        "accuracy": float(accuracy_score(bt, bp)),
        "precision": float(precision_score(bt, bp, zero_division=0)),
        "recall_detection_rate": float(recall_score(bt, bp, zero_division=0)),
        "f1": float(f1_score(bt, bp, zero_division=0)),
        "false_positive_rate": float(fp / (fp + tn)) if (fp + tn) else 0.0,
        "confusion_matrix": [[int(tn), int(fp)], [int(fn), int(tp)]],
    }
    if p_attack is not None and len(set(bt)) == 2:
        binary["roc_auc"] = float(roc_auc_score(bt, p_attack))
    res["binary"] = binary

    # Theo từng nhãn gốc của dataset mới (vd. Exploits, Fuzzers ...)
    if source_label is not None:
        per = {}
        df = pd.DataFrame({"src": np.asarray(source_label).astype(str), "pred": y_pred})
        for lbl, g in df.groupby("src"):
            per[lbl] = {
                "n": int(len(g)),
                "predicted_as_attack_rate": float((g["pred"] != "normal").mean()),
                "pred_distribution": g["pred"].value_counts(normalize=True).round(4).to_dict(),
            }
        res["per_source_label"] = dict(sorted(per.items(), key=lambda kv: -kv[1]["n"]))
    return res


# ----------------------------------------------------------------------
# IN & LƯU
# ----------------------------------------------------------------------
def print_summary(metrics: Dict, title: str):
    m, b = metrics["multiclass"], metrics["binary"]
    print("=" * 78)
    print(f"  KET QUA DANH GIA CHEO: {title}   (n = {metrics['n_samples']:,})")
    print("=" * 78)
    print("[Da lop - 5 lop NSL-KDD]")
    print(f"  Accuracy        : {m['accuracy'] * 100:6.2f}%")
    print(f"  F1 (weighted)   : {m['f1_weighted'] * 100:6.2f}%")
    print(f"  F1 (macro)      : {m['f1_macro'] * 100:6.2f}%")
    print("  Confusion Matrix (hang = thuc te, cot = du doan):")
    labels = m["labels"]
    print("    " + " " * 8 + "".join(f"{l:>10}" for l in labels))
    for l, row in zip(labels, m["confusion_matrix"]):
        print(f"    {l:<8}" + "".join(f"{v:>10,}" for v in row))
    print("\n[Nhi phan - Normal vs Attack]")
    print(f"  Accuracy        : {b['accuracy'] * 100:6.2f}%")
    print(f"  Precision       : {b['precision'] * 100:6.2f}%")
    print(f"  Recall (DR)     : {b['recall_detection_rate'] * 100:6.2f}%")
    print(f"  F1-Score        : {b['f1'] * 100:6.2f}%")
    print(f"  False Pos. Rate : {b['false_positive_rate'] * 100:6.2f}%")
    if "roc_auc" in b:
        print(f"  ROC-AUC         : {b['roc_auc']:.4f}")
    (tn, fp), (fn, tp) = b["confusion_matrix"]
    print(f"  CM: TN={tn:,}  FP={fp:,}  FN={fn:,}  TP={tp:,}")
    if "per_source_label" in metrics:
        print("\n[Ty le bi danh dau la TAN CONG theo nhan goc]")
        for lbl, r in metrics["per_source_label"].items():
            print(f"  {lbl:<18} n={r['n']:>9,}   -> attack: {r['predicted_as_attack_rate'] * 100:6.2f}%")
    print("=" * 78)


def save_confusion_plots(metrics: Dict, out_dir: str, title: str):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    def _plot(cm, labels, fname, subtitle):
        cm = np.asarray(cm)
        fig, ax = plt.subplots(figsize=(7, 5.5))
        im = ax.imshow(cm, cmap=plt.cm.Blues)
        thr = cm.max() / 2 if cm.size else 0
        for i in range(cm.shape[0]):
            for j in range(cm.shape[1]):
                ax.text(j, i, f"{cm[i, j]:,}", ha="center", va="center", fontsize=9,
                        color="white" if cm[i, j] > thr else "black", fontweight="bold")
        ax.set_xticks(range(len(labels)))
        ax.set_yticks(range(len(labels)))
        ax.set_xticklabels(labels)
        ax.set_yticklabels(labels)
        ax.set_xlabel("Nhan du doan (Predicted)")
        ax.set_ylabel("Nhan thuc te (True)")
        ax.set_title(f"{subtitle} - {title}", fontweight="bold")
        fig.colorbar(im)
        plt.tight_layout()
        plt.savefig(os.path.join(out_dir, fname), dpi=150)
        plt.close(fig)

    _plot(metrics["multiclass"]["confusion_matrix"], metrics["multiclass"]["labels"],
          "confusion_matrix_multiclass.png", "Confusion Matrix 5 lop")
    _plot(metrics["binary"]["confusion_matrix"], ["normal", "attack"],
          "confusion_matrix_binary.png", "Confusion Matrix nhi phan")


def save_json(obj, path):
    def default(o):
        if isinstance(o, (np.integer,)):
            return int(o)
        if isinstance(o, (np.floating,)):
            return float(o)
        return str(o)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2, default=default)
