# Phần 2 — Traffic Generator & Sender (`traffic_sender/`)

Ứng dụng giao diện **sinh biến thể pcap từ kho mẫu** và **phát ra card mạng** để
kiểm thử Phần 1 (hệ thống bắt gói + mô hình phát hiện). Hoàn toàn độc lập với
luồng cũ: đặt cạnh `src/`, `realtime/`.

> ⚠️ **Chỉ dùng trong phòng lab.** Chỉ phát gói tới máy/mạng do chính bạn sở hữu
> và được phép thử nghiệm. Không quét/flood mạng của người khác.

## Cấu trúc (tách Logic ↔ Giao diện)
```
traffic_sender/
├── pcap_tools.py     # LOGIC: đọc mẫu, làm mới (time/IP/checksum), ghi output, gửi
├── app.py            # GIAO DIỆN CustomTkinter (gửi chạy ở luồng phụ)
├── __main__.py       # python -m traffic_sender
├── templates/        # KHO MẪU pcap
│   ├── dos_attack.pcap     (A - DoS / SYN Flood)
│   ├── port_scan.pcap      (B - Port Scanning)
│   └── web_attack.pcap     (C - Web Request/HTTP, payload là chuỗi đánh dấu vô hại)
├── output/           # nơi ghi file sinh ra: generated_{loại}_{thời gian}.pcap
└── tests/test_pcap_tools.py
```

## Cài đặt
```bash
pip install scapy customtkinter
# Windows: cài thêm Npcap (https://npcap.com) để GỬI/BẮT gói. Chạy bằng Administrator.
# Linux: chạy bằng sudo để sendp() mở được raw socket.
```

## Chạy
```bash
python -m traffic_sender
```
Ba bước trên giao diện:
1. **Kho mẫu & Sinh gói tin** — chọn loại tấn công (A/B/C), đặt IP nguồn (ngẫu
   nhiên hoặc nhập tay) và **IP đích = IP máy chạy Phần 1**, bấm **Sinh gói tin**.
   App đọc mẫu, dời timestamp về hiện tại, đổi IP đúng chiều, xoá & tính lại
   checksum, ghi `output/generated_*.pcap` và hiện đường dẫn.
2. **Gửi gói tin** — chọn **card mạng**, chọn file (mặc định là file vừa sinh),
   đặt giãn cách/lặp lại, bấm **Gửi gói tin**. Việc gửi chạy luồng phụ, có
   **thanh tiến trình** và **log** số gói đã gửi; nút **Dừng** để ngắt.

## Nối với Phần 1 (demo 2 máy)
| Máy A (nạn nhân) | Máy B (máy này) |
|---|---|
| `python -m realtime --iface "Wi-Fi"` | mở `traffic_sender`, đặt IP đích = IP máy A, Sinh rồi Gửi |
| → terminal Phần 1 in cảnh báo đỏ | → thanh tiến trình chạy hết |

## Kết quả kiểm thử vòng lặp (file sinh ra → Phần 1 phát lại)
| Loại | Mô hình Phần 1 nhận diện |
|------|--------------------------|
| A — DoS / SYN Flood | 60/60 kết nối → **dos** |
| B — Port Scanning | 55/60 → **probe/dos** |
| C — Web Request | 1 kết nối → normal (đúng: mô hình NSL-KDD xét theo kết nối, không đọc payload) |

## Ghi chú
- Mẫu C là một phiên HTTP có chuỗi đánh dấu `NIDS_LAB_TEST_MARKER` — chỉ để
  detector có gói HTTP mà quan sát, **không phải payload khai thác**. Mô hình
  Phần 1 phân loại theo đặc trưng kết nối nên không cần nội dung khai thác thật.
- Muốn mẫu sát thực tế hơn, bạn có thể **tự bắt lưu lượng bằng Wireshark**, lưu
  `.pcap` và thả vào `templates/` (đổi tên theo `pcap_tools.TEMPLATES`).
