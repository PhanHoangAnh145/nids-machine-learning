# Phần 3 — Web Shield (reverse proxy)

Lá chắn web đứng **giữa** trình duyệt và web server thật. Mọi request đi qua lá
chắn: request **nguy hiểm bị chặn ngay (HTTP 403) + cảnh báo**, request sạch được
chuyển tiếp tới web server rồi trả kết quả về. Độc lập với luồng cũ (đặt cạnh
`src/`, `realtime/`). Lõi chỉ dùng **thư viện chuẩn Python**, không cần cài thêm.

```
Trình duyệt ──▶  [ Web Shield :8080 ]  ──▶  Web server thật :8000
                 kiểm tra từng request
                 ├─ nguy hiểm → chặn 403 + ghi cảnh báo
                 └─ sạch       → chuyển tiếp & trả lời
```

## Hai lớp phát hiện
1. **WAF theo chữ ký** (nội dung HTTP): SQL Injection, XSS, Path Traversal, Command
   Injection, và User-Agent của công cụ quét (sqlmap, nikto, nmap…).
2. **Giới hạn tần suất**: quá nhiều request/giây từ cùng một IP → HTTP flood (DoS)
   → chặn IP đó trong một khoảng thời gian.

> Đây là lá chắn tầng **ứng dụng** (đọc nội dung HTTP), **bổ trợ** cho mô hình
> NSL-KDD tầng **mạng** ở Phần 1 — hai lớp phòng thủ theo chiều sâu. Mô hình
> NSL-KDD không đọc nội dung HTTP nên không dùng để bắt SQLi/XSS; việc đó do WAF
> đảm nhiệm.

## Chạy thử (1 máy)
```bash
pip install customtkinter          # chỉ cần cho giao diện

# cửa sổ 1: web server mẫu (đóng vai web thật)
python -m web_shield.demo_backend          # http://127.0.0.1:8000

# cửa sổ 2: lá chắn
python -m web_shield                        # giao diện; Bật lá chắn (cổng 8080 -> 8000)
# hoặc không giao diện:
python -m web_shield.cli --listen 8080 --upstream 127.0.0.1:8000
```
Mở trình duyệt vào **http://127.0.0.1:8080** (đi qua lá chắn):
- Sạch: `http://127.0.0.1:8080/search?q=hello` → thấy trang web.
- Tấn công (bị chặn 403): `http://127.0.0.1:8080/search?q=1' OR '1'='1`,
  `.../search?q=<script>alert(1)</script>`, `.../../../etc/passwd`.

Trong giao diện, mỗi request hiện 1 dòng: dòng **đỏ = đã chặn** kèm loại tấn công;
các ô đếm Tổng / Cho qua / Đã chặn / IP bị chặn cập nhật realtime.

## Dùng 2 máy
Lá chắn nghe trên mọi card (`0.0.0.0`). Máy khác mở trình duyệt vào
`http://<IP máy chạy lá chắn>:8080`. Request độc hại từ máy đó cũng bị chặn, cột
"IP nguồn" hiện đúng IP máy kia.

## Kiểm thử
```bash
python -m unittest discover -s web_shield/tests -t .
```

## Hạn chế (ghi vào báo cáo)
- WAF theo chữ ký bắt các mẫu tấn công phổ biến; kẻ tấn công né bằng biến thể lạ
  vẫn có thể lọt (đánh đổi của mọi WAF dựa trên luật).
- Chưa xử lý HTTPS (giải mã TLS) — chỉ áp dụng cho HTTP. Muốn HTTPS cần đặt chứng
  chỉ ở lá chắn (TLS termination), nằm ngoài phạm vi bài tập lớn.
