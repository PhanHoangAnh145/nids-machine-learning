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

## Dashboard
- **Tấn công phát hiện**: chỉ các kết nối mô hình phân loại là tấn công (dòng đỏ =
  được tính, dòng vàng = xác suất thấp nên bỏ qua). Lưu lượng bình thường nằm ở
  mục "Lưu lượng gần đây" (bấm để mở), không còn đẩy trôi cảnh báo.
- **Thiết bị trong mạng**: IP nội bộ (10/8, 172.16/12, 192.168/16) có kết nối
  TRỰC TIẾP (unicast) với máy shield hoặc đi qua shield, + nguồn tấn công bên
  ngoài. Máy chỉ thấy qua gói quảng bá/multicast (SSDP, mDNS, NetBIOS...) bị ẩn,
  tick "hiện cả máy chỉ thấy qua quảng bá" để xem. Mỗi dòng có kèm số kết nối, số lần tấn công gửi đi / bị tấn công, trạng thái
  (bình thường / nghi vấn / đã chặn). Khi máy chạy shield làm gateway (Mobile
  Hotspot), bảng này là toàn bộ các máy trong mạng.
- **IP đang bị chặn**: thời điểm chặn, cách chặn, thời gian còn lại trước khi tự gỡ.

## Chính sách chặn thông minh (`config.py`)
| Tham số | Mặc định | Ý nghĩa |
|---|---|---|
| `min_attack_prob` | 0.60 | Chỉ tính 1 kết nối là tấn công khi P(tấn công) = 1 − P(normal) ≥ 60% |
| `block_threshold` / `block_window` | 20 / 5s | Chặn khi 1 IP có ≥ 20 kết nối tấn công trong 5 giây (cửa sổ trượt) = yêu cầu tốc độ tấn công |
| `count_self_outbound` | False | Kết nối do chính máy shield mở ra ngoài: hiện ở bảng (dòng vàng) nhưng không tính |
| `block_ttl` | 600s | Tự gỡ chặn sau 10 phút (0 = vĩnh viễn) |

Dùng 1 − P(normal) thay vì xác suất lớp cao nhất vì với port scan mô hình thường
phân vân giữa dos/probe (mỗi lớp ~40–50%) dù gần như chắc chắn là tấn công.
**Vì sao cần ngưỡng tốc độ:** khi bắt gói thật, trình duyệt mở kết nối tới trang
bị chặn/không phản hồi sẽ gửi SYN mà không được trả lời (cờ `S0`). Trong NSL-KDD
đây chính là dấu hiệu SYN flood (neptune) nên mô hình phán DOS — báo nhầm. Tấn
công thật (traffic_generator, nmap) tạo hàng trăm–hàng nghìn kết nối/giây, còn
trình duyệt chỉ vài kết nối/giây, nên ngưỡng tốc độ tách được hai trường hợp.
Hạn chế: quét cổng rất chậm (vd `nmap -T1`) sẽ lọt ngưỡng.

Khi khởi động lại, các luật `NIDS_SHIELD_*` còn trong Windows Firewall được đọc
lại và hiện trên dashboard.

## Mở dashboard cho máy khác cùng mạng (LAN)
Mặc định dashboard chỉ mở ở `127.0.0.1` (chỉ máy chạy shield xem). Để máy khác
trong cùng mạng mở được bằng trình duyệt:
```bash
python -m net_shield --lan            # hoặc nhấp CHAY_NET_SHIELD_LAN.bat (Run as administrator)
# tùy chọn: --pass=matkhau  --port=8081
```
Lõi (bắt gói, chặn IP) VẪN chạy trên máy này — chỉ giao diện được mở ra. Khi bật
`--lan`:
- Bind `0.0.0.0`; máy khác mở `http://<IP-máy-shield>:8081` (console in sẵn các
  địa chỉ dùng được).
- BẮT BUỘC đăng nhập (HTTP Basic Auth): user bất kỳ, mật khẩu in ra console
  (hoặc đặt bằng `--pass=`). Dashboard có nút điều khiển thật nên không để mở trần.
- Lần đầu Windows Firewall hỏi "Allow access" -> tick **Private networks**.

> Basic Auth trên HTTP KHÔNG mã hoá đường truyền (chưa có HTTPS) — chỉ dùng trong
> mạng lab, không mở ra Internet công khai. Không thể đưa lõi lên host đám mây
> (Vercel/VPS...) vì máy chủ đó không thấy card mạng và không điều khiển được
> firewall của bạn.

## Demo 1 máy: phát lại pcap
Chọn file ở ô "Demo 1 máy" → **⏯ Phát lại pcap**. File đi qua đúng luồng gom kết
nối → mô hình → chặn, nhưng chặn ở chế độ **mô phỏng** (không đụng tường lửa, vì
IP trong pcap là giả). **🧹 Xoá dữ liệu** để làm lại. Nguồn file:
`traffic_sender/templates/`, `pcaps/` ở gốc dự án, `net_shield/pcaps/`.

Kết quả với mô hình hiện tại: `dos_attack.pcap` 60/60 kết nối là tấn công → chặn
10.0.0.9; `port_scan.pcap` 51/60 tính là tấn công (4 bỏ qua vì xác suất thấp) →
chặn; `web_attack.pcap` không phát hiện (đúng giới hạn: mô hình không đọc payload,
phần này do `web_shield`).

## Demo (2 máy — đúng kịch bản thật)
| Máy A — NẠN NHÂN (chạy NET SHIELD) | Máy B — KẺ TẤN CÔNG |
|---|---|
| `python -m net_shield` → chọn card Wi-Fi → **Bắt đầu** | Dùng Phần 2: **🚀 Phát ra card mạng** nhắm IP máy A (hoặc công cụ nmap/hping3) |
| Dashboard phát hiện → **tự chặn IP máy B** → các gói sau bị Firewall chặn | |

Cơ chế chặn là **luật Windows Firewall thật**, nên sau khi chặn, lưu lượng từ IP
đó bị loại ở tầng hệ điều hành — đúng tinh thần IPS.

> 1 máy đơn thường không "tự bắt" được gói mình gửi, nên để thấy rõ cơ chế nên
> dùng 2 máy, hoặc để máy A làm gateway (Mobile Hotspot). Ngưỡng chặn: xem bảng
> chính sách ở trên.

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
