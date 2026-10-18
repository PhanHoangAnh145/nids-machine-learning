# cross_dataset — Đánh giá chéo model NIDS trên bộ dữ liệu khác

Module **độc lập hoàn toàn** với luồng cũ:

- **Không sửa** `src/`, `main.py`, `models/` hay `.gitignore` gốc.
- **Chỉ đọc** `models/best_model.joblib` và `models/preprocessor.joblib`.
- **Ghi kết quả** vào `reports/cross_dataset/`. Script tự từ chối nếu `--out` trỏ vào `models/`.
- **Không thêm thư viện mới**: chỉ dùng numpy, pandas, scikit-learn, joblib, matplotlib, vốn đã có trong `requirements.txt`.

## Kiến trúc

```
nids-machine-learning/
├── main.py, src/, models/          # LUỒNG CŨ - giữ nguyên
├── data/
│   ├── raw/                        # NSL-KDD (cũ)
│   └── external/                   # MỚI: dữ liệu ngoài (đã gitignore)
│       └── unsw_nb15/
├── reports/cross_dataset/          # MỚI: báo cáo mỗi lần chạy (đã gitignore)
└── cross_dataset/                  # MỚI
    ├── config.py                   # đường dẫn + mọi bảng ánh xạ (port→service, state→flag, nhãn)
    ├── kdd_schema.py               # "hợp đồng" đầu vào đọc từ preprocessor.joblib
    ├── kdd_feature_builder.py      # tính lại 19 đặc trưng traffic/host KDD từ bản ghi kết nối
    ├── adapters/
    │   ├── base.py                 # BaseAdapter + registry
    │   ├── nsl_kdd.py              # adapter ĐỐI CHỨNG (tái lập kết quả luồng cũ)
    │   └── unsw_nb15.py            # UNSW-NB15 → 41 cột NSL-KDD
    ├── evaluate.py                 # predict theo lô + metrics + vẽ confusion matrix
    ├── run_inference.py            # CLI
    └── tests/                      # unit test, dùng dữ liệu UNSW giả lập
```

Luồng dữ liệu:

```
file UNSW ─► Adapter ─► 41 cột thô NSL-KDD ─► preprocessor.joblib (giữ nguyên) ─► 122 chiều ─► best_model.joblib ─► metrics
```

Adapter chỉ cần sinh **đúng 41 cột thô, đúng từ vựng** `protocol_type`/`service`/`flag`. Việc scale và one-hot do chính preprocessor cũ đảm nhận, nên đầu vào luôn khớp `input_shape` (122) của model.

## Chuẩn bị dữ liệu UNSW-NB15

Tải bộ dữ liệu từ trang chính thức của UNSW Canberra rồi đặt vào `data/external/unsw_nb15/`. Có hai định dạng, script tự nhận diện:

| Định dạng | File | Đặc trưng traffic/host | Độ trung thực |
|---|---|---|---|
| **[A] file gốc** (khuyến nghị) | `UNSW-NB15_1.csv` … `_4.csv` (không header, 49 cột, ~2,54 triệu dòng) | **Tính lại** đúng định nghĩa KDD từ `stime`, `dstip`, `sport` | Cao |
| [B] file chia sẵn | `UNSW_NB15_training-set.csv`, `UNSW_NB15_testing-set.csv` | **Xấp xỉ** từ các cột `ct_*` | Thấp hơn |

## Chạy

Mọi lệnh chạy từ thư mục `nids-machine-learning/`.

### Đánh giá tổng hợp cũ + mới trong một lần (khuyến nghị)

Mở `cross_dataset/evaluate_all.py` trong IDE rồi bấm Run, hoặc chạy:

```bash
python -m cross_dataset.evaluate_all                  # Val 20% + KDDTest+ + UNSW-NB15 (nếu có file)
python -m cross_dataset.evaluate_all --download-unsw  # tự tải UNSW_NB15_testing-set.csv (~15 MB) nếu chưa có
```

Script chạy lần lượt 3 tập:
1. **NSL-KDD Validation 20%**: tách lại giống hệt `src/train.py`.
2. **NSL-KDD KDDTest+**.
3. **UNSW-NB15**: tự tìm file trong `data/external/unsw_nb15/`.

Sau đó script in bảng so sánh và đối chiếu với `evaluation_results.json`. Kết quả lưu trong `reports/cross_dataset/full_eval_<thời gian>/` gồm `summary.csv`, `comparison.png` và chi tiết từng tập.

### Train model mới trên dữ liệu trộn NSL-KDD + UNSW-NB15

Model cũ chỉ học NSL-KDD nên gần như không nhận ra tấn công UNSW-NB15 (Recall khoảng 0,1%). Mở `cross_dataset/train_mixed.py` trong IDE rồi bấm Run, hoặc chạy:

```bash
python -m cross_dataset.train_mixed
```

- **Dữ liệu train:** 80% KDDTrain+ (tách đúng như `src/train.py`) cộng 80% UNSW-NB15.
- **Model:** Random Forest, cùng siêu tham số với `src/train.py`.
- **Nơi lưu:** model mới nằm ở `models/mixed/`, **không ghi đè** `models/best_model.joblib`. `main.py` vẫn dùng model cũ.
- **Đánh giá:** cả model cũ lẫn model mới được chạy trên cùng 3 tập không dùng để train (NSL Val 20%, KDDTest+, UNSW 20% giữ lại). Kết quả lưu ở `reports/cross_dataset/mixed_train_<thời gian>/`.

Muốn đánh giá model mới trên dữ liệu khác:

```bash
python -m cross_dataset.run_inference --dataset unsw-nb15 --input <file> \
    --model models/mixed/best_model.joblib --preprocessor models/mixed/preprocessor.joblib
```

Lưu ý: tập UNSW 20% giữ lại được tách từ cùng một file với phần train, nên nó cùng phân phối với dữ liệu train. Để đánh giá khắt khe hơn, hãy train trên `UNSW_NB15_training-set.csv` và kiểm thử trên `UNSW_NB15_testing-set.csv`.

### Chạy riêng từng tập

```bash
# 0) Đối chứng: chạy lại KDDTest+ qua pipeline mới, kết quả phải KHỚP evaluation_results.json
python -m cross_dataset.run_inference --dataset nsl-kdd --input data/raw/KDDTest+.txt --compare-baseline

# 1) UNSW-NB15 file gốc (truyền 1 đến 4 file, theo thứ tự thời gian)
python -m cross_dataset.run_inference --dataset unsw-nb15 \
    --input data/external/unsw_nb15/UNSW-NB15_1.csv data/external/unsw_nb15/UNSW-NB15_2.csv \
            data/external/unsw_nb15/UNSW-NB15_3.csv data/external/unsw_nb15/UNSW-NB15_4.csv

# 2) Chạy nhanh: đặc trưng vẫn tính trên toàn bộ luồng, sau đó mới lấy mẫu 200k dòng
python -m cross_dataset.run_inference --dataset unsw-nb15 --input data/external/unsw_nb15/UNSW-NB15_1.csv --sample 200000

# 3) File chia sẵn, kèm lưu dự đoán từng dòng
python -m cross_dataset.run_inference --dataset unsw-nb15 \
    --input data/external/unsw_nb15/UNSW_NB15_testing-set.csv --save-predictions

# Unit test (không cần dữ liệu thật)
python -m unittest discover -s cross_dataset/tests -t . -v
```

Kết quả nằm trong `reports/cross_dataset/<dataset>_<thời gian>/`:

- **`metrics.json`** gồm:
  - chỉ số đa lớp và nhị phân, confusion matrix;
  - tỷ lệ bị phát hiện theo **từng nhóm tấn công gốc** (Exploits, Fuzzers, …);
  - `feature_provenance`: mức tin cậy của từng đặc trưng;
  - `categorical_coverage`: tỷ lệ giá trị nằm ngoài từ vựng;
  - `top_feature_drift_vs_nslkdd_train`: độ lệch phân phối so với tập train.
- **`confusion_matrix_multiclass.png`** và **`confusion_matrix_binary.png`**.
- **`mapped_features_sample.csv`**: 200 dòng sau ánh xạ, dùng để soi lỗi mapping.
- **`predictions.csv`**: chỉ có khi chạy với `--save-predictions`.

## Ánh xạ UNSW-NB15 → NSL-KDD (tóm tắt)

| Nhóm KDD | Cách lấy | Mức |
|---|---|---|
| `duration`, `protocol_type`, `src_bytes`, `dst_bytes` | `dur`, `proto`, `sbytes`, `dbytes` | exact |
| `service` | cột `service` của UNSW; nếu là `-` thì suy theo cổng đích (`PORT_TO_KDD_SERVICE`) | computed |
| `flag` | `state` của Argus kết hợp `dpkts`/`dbytes` → SF/S0/S1/REJ/RSTO/OTH; UDP/ICMP → SF | heuristic |
| `land` | so `srcip==dstip` và `sport==dsport` (định dạng [A]) hoặc `is_sm_ips_ports` (định dạng [B]) | exact |
| `logged_in` | `is_ftp_login`, hoặc phiên TCP SF thuộc service ứng dụng mà server có trả dữ liệu | heuristic |
| 13 đặc trưng content (`hot`, `root_shell`, …) | UNSW không cung cấp | 0 |
| 19 đặc trưng traffic/host | [A]: `kdd_feature_builder` (cửa sổ 2 giây + 255 kết nối/host); [B]: xấp xỉ từ `ct_*` | computed / approx |

Ánh xạ nhãn (sửa trong `config.UNSW_TO_KDD_CATEGORY`):

- Normal → normal
- DoS, Generic, Fuzzers, Worms → dos
- Reconnaissance, Analysis → probe
- Exploits, Backdoor → r2l
- Shellcode → u2r

## Đọc kết quả cho đúng

1. **Chỉ số nhị phân (Normal và Attack) là thước đo chính.** Nhãn 5 lớp chỉ là ánh xạ ngữ nghĩa gần đúng, vì UNSW-NB15 có những nhóm tấn công mà KDD không có.
2. **Kết quả thấp là chuyện bình thường và đáng đưa vào báo cáo.** Có ba nguyên nhân chính:
   - 13 đặc trưng content bằng 0;
   - lưu lượng của năm 2015 khác xa lưu lượng của năm 1998–1999;
   - cách đo byte và flag giữa Argus/Bro và công cụ gốc của KDD không giống nhau.

   Hai trường `top_feature_drift_vs_nslkdd_train` và `categorical_coverage` trong `metrics.json` dùng để định lượng các nguyên nhân này.
3. **Luôn chạy đối chứng `nsl-kdd --compare-baseline` trước.** Nếu kết quả KHỚP, thì mọi chênh lệch trên UNSW đến từ dữ liệu chứ không phải từ code.

## Thêm dataset mới (CICIDS2017, PCAP, …)

1. Tạo file `cross_dataset/adapters/<ten>.py` chứa một lớp kế thừa `BaseAdapter` và gắn `@register_adapter("<ten>")`.
2. Cài đặt hai hàm:
   - `load(paths)`: đọc file gốc của dataset;
   - `to_kdd(raw)`: trả về 41 cột NSL-KDD cùng hai cột `attack_category` và `source_label`.
3. Nếu dataset có bản ghi kết nối thô (IP đích, cổng nguồn, thời gian), gọi lại `build_traffic_features()` để tính 19 đặc trưng traffic/host.
4. Thêm một dòng import vào `adapters/__init__.py`. Lúc này CLI tự nhận `--dataset <ten>`.
