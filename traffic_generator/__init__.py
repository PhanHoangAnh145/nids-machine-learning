"""
traffic_generator: sinh lưu lượng theo KỊCH BẢN để thử bộ giám sát realtime.

Hai chế độ:
  * offline  : dựng danh sách gói tin rồi ghi ra .pcap (dùng realtime.pcap_io).
               Không cần mạng, dùng để kiểm thử tự động và minh họa trong báo cáo.
  * live     : gửi gói thật sang máy đích (sender.py) để demo end-to-end.
               Kịch bản SYN flood / quét SYN cần Scapy + quyền quản trị; quét
               kiểu "connect" và lưu lượng bình thường có bản dùng socket thuần.

Các kịch bản (scenarios.py):
  synflood   -> DoS (kỳ vọng mô hình: 'dos',  cờ S0)
  synscan    -> Probe (quét cổng nửa mở,       cờ REJ/S0)
  connectscan-> Probe (quét cổng kiểu connect, cờ REJ/SF)
  pingflood  -> DoS/ICMP
  normal     -> lưu lượng bình thường (cờ SF)  -> đo báo động giả
"""
from .scenarios import (
    SCENARIOS, build_scenario,
    synflood, synscan, connectscan, pingflood, smurf, normal,
)

__all__ = [
    "SCENARIOS", "build_scenario",
    "synflood", "synscan", "connectscan", "pingflood", "smurf", "normal",
]
