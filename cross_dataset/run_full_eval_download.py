"""
Bấm Run file này trong IDE để: tải UNSW-NB15 testing-set (nếu chưa có) rồi chạy
đánh giá tổng hợp trên NSL-KDD Val 20% + KDDTest+ + UNSW-NB15.
Tương đương: python -m cross_dataset.evaluate_all --download-unsw
"""
import os
import sys

if __package__ in (None, ""):
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cross_dataset.evaluate_all import main  # noqa: E402

if __name__ == "__main__":
    main(["--download-unsw"] + sys.argv[1:])
