"""
Cấu hình đường dẫn & bảng ánh xạ cho module cross_dataset.

Mọi "giả định" khi chuyển dữ liệu khác về không gian đặc trưng NSL-KDD đều được
gom ở đây để dễ chỉnh / dễ trình bày trong báo cáo, không rải rác trong code.
"""
import os

# --------------------------------------------------------------------------
# Đường dẫn (chỉ ĐỌC artifacts cũ, GHI ra thư mục riêng)
# --------------------------------------------------------------------------
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LEGACY_MODELS_DIR = os.path.join(PROJECT_ROOT, "models")
DEFAULT_MODEL_PATH = os.path.join(LEGACY_MODELS_DIR, "best_model.joblib")
DEFAULT_PREPROCESSOR_PATH = os.path.join(LEGACY_MODELS_DIR, "preprocessor.joblib")

EXTERNAL_DATA_DIR = os.path.join(PROJECT_ROOT, "data", "external")
REPORTS_DIR = os.path.join(PROJECT_ROOT, "reports", "cross_dataset")

# --------------------------------------------------------------------------
# Ngưỡng của NSL-KDD (giá trị bị "cắt trần" trong dữ liệu gốc)
# --------------------------------------------------------------------------
KDD_COUNT_CAP = 511          # count, srv_count
KDD_DST_HOST_CAP = 255       # dst_host_count, dst_host_srv_count
KDD_TIME_WINDOW_SEC = 2.0    # cửa sổ thời gian cho nhóm traffic features
# Nhóm host-based dùng cửa sổ N kết nối gần nhất tới cùng dst host, N = KDD_DST_HOST_CAP

# Cờ (flag) được tính là lỗi SYN / lỗi REJ khi tính *_serror_rate, *_rerror_rate
SERROR_FLAGS = frozenset({"S0", "S1", "S2", "S3"})
RERROR_FLAGS = frozenset({"REJ"})

# --------------------------------------------------------------------------
# Ánh xạ cổng đích -> tên service kiểu NSL-KDD (chỉ dùng tên có trong vocab)
# key: (proto, port) ưu tiên trước, sau đó port
# --------------------------------------------------------------------------
PORT_TO_KDD_SERVICE_PROTO = {
    ("udp", 53): "domain_u",
    ("tcp", 53): "domain",
    ("udp", 123): "ntp_u",
    ("udp", 69): "tftp_u",
}
PORT_TO_KDD_SERVICE = {
    5: "rje", 7: "echo", 9: "discard", 11: "systat", 13: "daytime", 15: "netstat",
    20: "ftp_data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 37: "time",
    42: "name", 43: "whois", 57: "mtp", 70: "gopher", 79: "finger", 80: "http",
    95: "supdup", 101: "hostnames", 102: "iso_tsap", 105: "csnet_ns",
    109: "pop_2", 110: "pop_3", 111: "sunrpc", 113: "auth", 117: "uucp_path",
    119: "nntp", 137: "netbios_ns", 138: "netbios_dgm", 139: "netbios_ssn",
    143: "imap4", 150: "sql_net", 179: "bgp", 194: "IRC", 210: "Z39_50",
    245: "link", 389: "ldap", 433: "nnsp", 443: "http_443", 512: "exec",
    513: "login", 514: "shell", 515: "printer", 530: "courier", 540: "uucp",
    543: "klogin", 544: "kshell", 6000: "X11", 6667: "IRC", 8001: "http_8001",
}

# Service mặc định khi không suy ra được (giá trị trung tính, có trong vocab)
UNKNOWN_SERVICE_BY_PROTO = {"icmp": "eco_i"}
UNKNOWN_SERVICE_DEFAULT = "other"

# Service của NSL-KDD coi là "phiên ứng dụng" -> dùng cho heuristic logged_in
LOGIN_SERVICES = frozenset({
    "http", "http_443", "http_8001", "ftp", "ftp_data", "smtp", "ssh", "telnet",
    "pop_2", "pop_3", "imap4", "login", "shell", "exec", "klogin", "kshell",
})

# --------------------------------------------------------------------------
# UNSW-NB15
# --------------------------------------------------------------------------
# 49 cột của 4 file gốc UNSW-NB15_1..4.csv (không có header)
UNSW_RAW_COLUMNS = [
    "srcip", "sport", "dstip", "dsport", "proto", "state", "dur", "sbytes",
    "dbytes", "sttl", "dttl", "sloss", "dloss", "service", "sload", "dload",
    "spkts", "dpkts", "swin", "dwin", "stcpb", "dtcpb", "smean", "dmean",
    "trans_depth", "response_body_len", "sjit", "djit", "stime", "ltime",
    "sinpkt", "dinpkt", "tcprtt", "synack", "ackdat", "is_sm_ips_ports",
    "ct_state_ttl", "ct_flw_http_mthd", "is_ftp_login", "ct_ftp_cmd",
    "ct_srv_src", "ct_srv_dst", "ct_dst_ltm", "ct_src_ltm", "ct_src_dport_ltm",
    "ct_dst_sport_ltm", "ct_dst_src_ltm", "attack_cat", "label",
]

# Tên cột UNSW (service) -> service NSL-KDD
UNSW_SERVICE_TO_KDD = {
    "http": "http", "ftp": "ftp", "ftp-data": "ftp_data", "smtp": "smtp",
    "ssh": "ssh", "pop3": "pop_3", "dns": None,  # None = phụ thuộc proto (domain/domain_u)
    "ssl": "http_443", "irc": "IRC", "snmp": "other", "dhcp": "other",
    "radius": "other",
}

# Trạng thái kết nối Argus (cột `state`) -> flag NSL-KDD, chỉ áp dụng cho TCP.
# UDP/ICMP trong NSL-KDD gần như luôn là 'SF' nên được gán SF.
# INT/REQ cần thêm thông tin dpkts -> xử lý trong adapter.
UNSW_TCP_STATE_TO_FLAG = {
    "FIN": "SF", "CLO": "SF",
    "CON": "S1", "ACC": "S1",
    "REQ": "S0",
    "RST": "RSTO",
}

# Nhóm tấn công UNSW-NB15 -> 5 lớp NSL-KDD.
# ĐÂY LÀ ÁNH XẠ NGỮ NGHĨA GẦN ĐÚNG -> chỉ số nhị phân (Normal vs Attack)
# mới là thước đo đáng tin cậy nhất khi đánh giá chéo.
UNSW_TO_KDD_CATEGORY = {
    "normal": "normal",
    "dos": "dos",
    "generic": "dos",          # tấn công chung lên block-cipher, chủ yếu lưu lượng DNS/UDP dồn dập
    "fuzzers": "dos",          # gửi dữ liệu ngẫu nhiên nhằm làm treo dịch vụ
    "worms": "dos",            # đồng nhất với 'worm' -> 'dos' trong src/preprocess.py
    "reconnaissance": "probe",
    "analysis": "probe",       # quét cổng, dò HTML/spam
    "exploits": "r2l",         # khai thác lỗ hổng từ xa
    "backdoor": "r2l",
    "backdoors": "r2l",
    "shellcode": "u2r",
}
