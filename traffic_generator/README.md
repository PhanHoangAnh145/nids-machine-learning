# Module `traffic_generator/` — Sinh lưu lượng theo kịch bản

Dùng để thử bộ giám sát `realtime/`. Hai chế độ:

## Offline — ghi `.pcap` (không cần mạng, không cần Scapy)
```bash
python -m traffic_generator --scenario synflood --pcap syn.pcap
python -m traffic_generator --scenario all --outdir pcaps --target 10.0.0.1
# rồi: python -m realtime --replay pcaps/synflood.pcap
```

## Live — gửi gói thật sang máy đích (demo 2 máy)
```bash
# Cần Scapy + quyền quản trị:
python -m traffic_generator --scenario synflood  --target 192.168.1.5 --send
python -m traffic_generator --scenario smurf     --target 192.168.1.5 --send
# Không cần quyền (dùng socket thường):
python -m traffic_generator --scenario connectscan --target 192.168.1.5 --send
python -m traffic_generator --scenario normal      --target 192.168.1.5 --send
```

| Kịch bản | Mô phỏng | Nhóm KDD kỳ vọng |
|----------|----------|------------------|
| `synflood`    | SYN flood (SYN không hồi đáp) | dos (cờ S0) |
| `smurf`       | Dội ICMP echo reply | dos (service ecr_i) |
| `synscan`     | Quét SYN nhiều cổng | probe/dos (REJ) |
| `connectscan` | Quét kiểu connect | probe/dos |
| `pingflood`   | Ping flood (echo request) | eco_i (thường bị xem là normal) |
| `normal`      | Duyệt web/DNS bình thường | normal (đo báo động giả) |

> Chỉ chạy trong phòng lab, trên máy của nhóm. KHÔNG quét/flood mạng người khác.
