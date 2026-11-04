# Module `realtime/` — Giám sát & phát hiện xâm nhập THỜI GIAN THỰC

Mở rộng NIDS SHIELD từ "phòng thủ tĩnh" (nhận bộ test có sẵn) sang **bắt gói tin
trực tiếp trên card mạng, gom thành kết nối, tính lại 41 đặc trưng NSL-KDD và dự
đoán theo thời gian thực** bằng ĐÚNG mô hình cũ.

> Nguyên tắc: KHÔNG sửa/ghi đè bất kỳ tệp nào của luồng cũ. Module chỉ **đọc**
> `models/best_model.joblib` + `models/preprocessor.joblib` và **tái dùng**
> `cross_dataset/kdd_feature_builder.py`. Đặt cạnh `src/`, `cross_dataset/`.

## Luồng xử lý
```
Gói tin → PacketMeta → FlowTracker → ConnectionRecord
        → (gộp lịch sử gần đây) → FeatureAdapter → 41 cột NSL-KDD
        → NIDSPredictor (model cũ) → Cảnh báo
```
| Tệp | Vai trò |
|-----|---------|
| `packet.py` | `PacketMeta`: gói tin rút gọn. Ranh giới cô lập Scapy (chỉ `from_scapy()` cần Scapy) |
| `pcap_io.py` | Đọc/ghi `.pcap` thuần Python — phát lại & kiểm thử không cần Scapy |
| `flow_tracker.py` | Máy trạng thái 5-tuple → cờ NSL-KDD (SF, S0, S1, REJ, RSTO, RSTR, SH, OTH) |
| `feature_adapter.py` | ConnectionRecord → 41 cột (dùng lại `build_traffic_features`) |
| `engine.py` | Điều phối: `ingest_packet`, `replay_pcap`, `live_capture` (Scapy) |
| `cli.py` / `__main__.py` | Dòng lệnh |
| `monitor_app.py` | Cửa sổ giám sát CustomTkinter độc lập (không đụng `main.py`) |

## Cài đặt & chạy
```bash
# Cần Scapy để BẮT GÓI TRỰC TIẾP (phát lại .pcap thì không cần)
pip install -r realtime/requirements-realtime.txt
# Windows: cài thêm Npcap (https://npcap.com) và chạy terminal bằng Administrator

# Phát lại một file pcap (offline, không cần Scapy, không cần quyền)
python -m realtime --replay capture.pcap

# Bắt gói trực tiếp
python -m realtime --list                 # xem tên card mạng
python -m realtime --iface "Wi-Fi"        # Ctrl+C để dừng

# Giao diện đồ hoạ giám sát (độc lập main.py)
python -m realtime.monitor_app
```

## Kiểm thử
```bash
python -m unittest discover -s realtime/tests -t .
python -m unittest discover -s traffic_generator/tests -t .
```

## Kết quả kiểm thử end-to-end (mô hình gốc, dữ liệu do `traffic_generator` sinh)
| Kịch bản | Số kết nối | Tỷ lệ cảnh báo | Nhóm dự đoán chính |
|----------|-----------:|---------------:|--------------------|
| synflood (SYN flood)      | 300 | **100%** | dos |
| smurf (ICMP echo reply)   | 300 | **100%** | dos |
| synscan (quét SYN)        | 300 | 83,7% | dos/probe |
| connectscan (quét connect)| 200 | 75,5% | dos/probe |
| pingflood (ICMP request)  | 300 | 0% | normal |
| normal (lưu lượng sạch)   |  80 | **0% báo động giả** | normal |

## Hạn chế (trung thực, nên ghi vào báo cáo)
- 13 đặc trưng "content" của NSL-KDD không suy được từ gói tin → gán 0; mô hình
  do đó yếu với R2L/U2R realtime (đúng như kết quả trên KDDTest+).
- `pingflood` (echo **request**) bị xem gần với lưu lượng thường — vì "smurf"
  trong KDD là echo **reply** (`ecr_i`). Đây là khác biệt phân phối đã phân tích
  ở Phần 6 của báo cáo, không phải lỗi gom luồng.
- Bản chia sẵn chỉ xấp xỉ đặc trưng cửa sổ; muốn chính xác hơn cần huấn luyện
  thêm bằng dữ liệu bắt trong chính mạng lab (mô hình trộn).
