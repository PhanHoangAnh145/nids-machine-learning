# Phần 3 — NET SHIELD: IPS mạng + dashboard web

Hệ thống **ngăn chặn xâm nhập (IPS)** có giao diện chạy trên **trình duyệt**. Bấm
**Bắt đầu** → máy bắt gói trực tiếp trên card mạng → mô hình phát hiện tấn công
(DoS/Probe) → **tự chặn IP nguồn bằng Windows Firewall** → hiển thị cảnh báo và
danh sách IP bị chặn realtime. Không phải tự gửi gói thủ công — nó giám sát lưu
lượng thật đi qua máy.

Độc lập với luồng cũ (đặt cạnh `src/`, `realtime/`). Lõi web dùng thư viện chuẩn.

```
Lưu lượng mạng ─▶ [ NET SHIELD ]
                  bắt gói (Npcap) → mô hình NSL-KDD → phát hiện
                  → TỰ CHẶN IP tấn công (Windows Firewall)
                  → dashboard web: cảnh báo + IP đã chặn
```

## Yêu cầu
- `pip install scapy scikit-learn pandas joblib`
- **Npcap** (https://npcap.com) để bắt gói.
- **Chạy bằng Administrator** để (a) bắt gói, (b) thêm luật chặn vào Firewall.
  Không có quyền Admin → vẫn chạy nhưng chỉ **cảnh báo** (chặn ở chế độ "logic").

## Chạy
```bash
python -m net_shield          # mở dashboard tại http://127.0.0.1:8081
```
(nhấp đúp `MO_PHAN3_NETSHIELD.bat` — nên "Run as administrator").

Trên dashboard: chọn **card mạng** → **▶ Bắt đầu**. Khi có tấn công, bảng "Cảnh
báo gần đây" đổ dòng đỏ, ô "IP đã chặn" tăng; mỗi IP có nút **Gỡ chặn**.

## Demo (2 máy — đúng kịch bản thật)
| Máy A — NẠN NHÂN (chạy NET SHIELD) | Máy B — KẺ TẤN CÔNG |
|---|---|
| `python -m net_shield` → chọn card Wi-Fi → **Bắt đầu** | Dùng Phần 2: **🚀 Phát ra card mạng** nhắm IP máy A (hoặc công cụ nmap/hping3) |
| Dashboard phát hiện → **tự chặn IP máy B** → các gói sau bị Firewall chặn | |

Cơ chế chặn là **luật Windows Firewall thật**, nên sau khi chặn, lưu lượng từ IP
đó bị loại ở tầng hệ điều hành — đúng tinh thần IPS.

> 1 máy đơn thường không "tự bắt" được gói mình gửi, nên để thấy rõ cơ chế nên
> dùng 2 máy, hoặc để máy A làm gateway. Ngưỡng chặn mặc định: 1 IP gây ≥ 3 kết
> nối tấn công thì bị chặn (chỉnh trong `config.py`).

## Kiểm thử
```bash
python -m unittest discover -s net_shield/tests -t .
```

## An toàn
- Không bao giờ chặn loopback hay IP của chính máy (whitelist tự thêm IP máy).
- Gọi tường lửa bằng danh sách tham số (không qua shell), chỉ nhận IP hợp lệ.
- Gỡ toàn bộ luật bằng nút "Gỡ chặn" trên dashboard, hoặc xoá các luật tên
  `NIDS_SHIELD_*` trong Windows Firewall.

## Hạn chế (ghi vào báo cáo)
- Bắt gói + chặn cần Npcap + quyền Admin.
- Mô hình NSL-KDD mạnh với DoS/Probe; R2L/U2R và tấn công nội dung web không bắt
  tốt ở tầng gói (xem Phần 6) — phần web do lá chắn `web_shield` đảm nhiệm.
