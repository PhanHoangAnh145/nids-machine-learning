"""
Bộ điều khiển IPS: bắt gói trực tiếp (realtime engine) -> phát hiện tấn công ->
TỰ CHẶN IP nguồn bằng tường lửa, đồng thời ghi cảnh báo cho dashboard.

Tách khỏi web server để kiểm thử được logic tự-chặn mà không cần HTTP/Npcap.

Chính sách chặn (xem config.py):
  * Một kết nối được TÍNH là tấn công khi mô hình phân loại != normal VÀ
    P(tấn công) = 1 - P(normal) >= min_attack_prob.
  * Chặn IP nguồn khi nó có >= block_threshold kết nối tấn công đã tính trong
    block_window giây (cửa sổ trượt theo thời điểm kết nối).
  * Tự gỡ chặn sau block_ttl giây.
Ngoài ra: bảng thiết bị trong mạng, bảng tấn công riêng, chế độ phát lại pcap.
"""
from __future__ import annotations

import ipaddress
import os
import sys
import threading
import time
from collections import deque
from typing import Deque, Dict, List, Optional

from .blocker import FirewallBlocker
from .config import IPSConfig


def _ensure_project_root():
    """Tìm thư mục gốc dự án (chứa src/ và models/) và thêm vào sys.path.

    Nhờ vậy net_shield chạy được dù nằm lồng trong thư mục con (vd sau khi giải
    nén thành net_shield_phan3/net_shield/), không cần đặt đúng cạnh src/.
    """
    d = os.path.dirname(os.path.abspath(__file__))
    for _ in range(8):
        d = os.path.dirname(d)
        if not d:
            break
        if os.path.isdir(os.path.join(d, "src")) and os.path.isdir(os.path.join(d, "models")):
            if d not in sys.path:
                sys.path.insert(0, d)
            return d
    return None


_PROJECT_ROOT = _ensure_project_root()


def _load_predictor():
    try:
        from src.predictor import NIDSPredictor
        return NIDSPredictor()
    except Exception as exc:  # noqa: BLE001
        print(f"[net_shield] Chưa nạp được model: {exc}")
        if _PROJECT_ROOT is None:
            print("[net_shield] -> Không tìm thấy thư mục gốc có src/ và models/. "
                  "Hãy đặt net_shield cạnh src/, hoặc chạy trong thư mục dự án.")
        return None


def local_ips() -> List[str]:
    """IP của chính máy này (đưa vào whitelist để không tự chặn mình)."""
    import socket
    ips = {"127.0.0.1"}
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ips.add(s.getsockname()[0])
        s.close()
    except Exception:  # noqa: BLE001
        pass
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            ips.add(info[4][0])
    except Exception:  # noqa: BLE001
        pass
    return [ip for ip in ips if ":" not in ip]


def list_ifaces() -> Dict[str, str]:
    """{nhãn dễ đọc -> tên card để bắt gói}."""
    mapping: Dict[str, str] = {}
    try:
        from scapy.arch.windows import get_windows_if_list
        rows = []
        for d in get_windows_if_list():
            desc = d.get("description") or d.get("name") or "?"
            ips = [ip for ip in (d.get("ips") or []) if ":" not in ip]
            lbl = f"{desc}  [{ips[0] if ips else 'không IP'}]"
            # Ưu tiên GUID (ổn định, khớp được với conf.ifaces của scapy)
            mapping[lbl] = d.get("guid") or d.get("name")
            rows.append((lbl, bool(ips)))
        rows.sort(key=lambda x: (not x[1]))
        return {lbl: mapping[lbl] for lbl, _ in rows}
    except Exception:  # noqa: BLE001
        try:
            from scapy.arch import get_if_list
            return {n: n for n in get_if_list()}
        except Exception:  # noqa: BLE001
            return {}


def list_pcaps() -> Dict[str, str]:
    """{tên hiển thị -> đường dẫn} các file .pcap mẫu để phát lại (chỉ đọc)."""
    root = _PROJECT_ROOT or os.getcwd()
    here = os.path.dirname(os.path.abspath(__file__))
    folders = [os.path.join(here, "pcaps"),
               os.path.join(root, "traffic_sender", "templates"),
               os.path.join(root, "pcaps")]
    out: Dict[str, str] = {}
    for folder in folders:
        if not os.path.isdir(folder):
            continue
        for name in sorted(os.listdir(folder)):
            if name.lower().endswith(".pcap"):
                rel = os.path.relpath(os.path.join(folder, name), root).replace("\\", "/")
                out[rel] = os.path.join(folder, name)
    return out


_LAN_NETS = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]


def is_lan_ip(ip: str) -> bool:
    """IP thuộc mạng nội bộ (thiết bị trong mạng), bỏ multicast/broadcast/link-local."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if a.version != 4 or a.is_loopback or a.is_link_local or a.is_multicast or a.is_unspecified:
        return False
    if ip.endswith(".255"):          # thường là địa chỉ quảng bá của mạng con
        return False
    return any(a in n for n in _LAN_NETS)


def is_unicast(ip: str) -> bool:
    """Địa chỉ đích "thật" (không phải multicast/broadcast)."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (a.is_multicast or a.is_unspecified or ip.endswith(".255"))


def attack_prob(pred) -> float:
    """P(tấn công) = 1 - P(normal). Không có xác suất -> dùng confidence."""
    probs = getattr(pred, "probabilities", None) or {}
    if "normal" in probs:
        return max(0.0, min(1.0, 1.0 - float(probs["normal"])))
    return float(pred.confidence) if pred.is_attack else 1.0 - float(pred.confidence)


class IPSController:
    def __init__(self, cfg: Optional[IPSConfig] = None, predictor=None):
        self.cfg = cfg or IPSConfig()
        self.self_ips = set(local_ips())
        wl = set(self.cfg.whitelist) | self.self_ips
        self.blocker = FirewallBlocker(whitelist=wl)
        self.predictor = predictor if predictor is not None else _load_predictor()
        self.engine = None
        self.running = False
        self.mode = None            # "live" | "replay" | None
        self.iface = None
        self._simulate = False      # True khi phát lại pcap -> chặn mô phỏng
        self._stop = threading.Event()
        self._thread = None
        self._lock = threading.RLock()
        self.alerts: Deque[dict] = deque(maxlen=self.cfg.max_alerts)    # mọi lưu lượng
        self.attacks: Deque[dict] = deque(maxlen=self.cfg.max_attacks)  # chỉ tấn công
        self.devices: Dict[str, dict] = {}
        self._hits: Dict[str, Deque[float]] = {}
        self.stats = self._empty_stats()
        restored = self.blocker.load_existing()
        if restored:
            self._note(f"Khôi phục {len(restored)} IP đang bị chặn trong Firewall: "
                       + ", ".join(sorted(restored)))

    @staticmethod
    def _empty_stats() -> dict:
        return {"packets": 0, "connections": 0, "attacks": 0, "suspects": 0,
                "blocked": 0, "devices": 0, "broadcast_only": 0}

    # ---- chẩn đoán / chọn card ----------------------------------------
    def _write_diag(self, scapy_iface):
        """Ghi thông tin chẩn đoán ra net_shield_diag.log ở thư mục gốc dự án."""
        import platform
        L = [f"time={time.strftime('%Y-%m-%d %H:%M:%S')}",
             f"python={platform.python_version()} ({platform.machine()})",
             f"is_admin={self.blocker.admin}",
             f"predictor_loaded={self.predictor is not None}"]
        try:
            import scapy
            L.append(f"scapy={scapy.__version__}")
        except Exception as e:  # noqa: BLE001
            L.append(f"scapy_import_error={e!r}")
        try:
            from scapy.all import conf
            L.append(f"conf.iface={conf.iface!r}")
            for i in conf.ifaces.values():
                L.append(f"IFACE name={getattr(i,'name',None)!r} "
                         f"desc={getattr(i,'description',None)!r} "
                         f"guid={getattr(i,'guid',None)!r} ip={getattr(i,'ip',None)!r}")
        except Exception as e:  # noqa: BLE001
            L.append(f"ifaces_error={e!r}")
        L.append(f"selected_resolved={scapy_iface!r}")
        try:
            from scapy.all import sniff
            pk = sniff(iface=scapy_iface, count=5, timeout=6)
            L.append(f"TEST_SNIFF_count={len(pk)}")
        except Exception as e:  # noqa: BLE001
            L.append(f"TEST_SNIFF_error={e!r}")
        try:
            root = _PROJECT_ROOT or os.getcwd()
            with open(os.path.join(root, "net_shield_diag.log"), "w", encoding="utf-8") as f:
                f.write("\n".join(str(x) for x in L))
        except Exception:  # noqa: BLE001
            pass

    @staticmethod
    def _resolve_scapy_iface(token: str):
        """Đổi GUID/tên card thành ĐỐI TƯỢNG interface mà scapy chắc chắn nhận.

        Trả về None nếu không khớp.
        """
        if not token:
            return None
        try:
            from scapy.all import conf
            t = str(token).lower().strip("{}")
            for i in conf.ifaces.values():
                for attr in ("guid", "name", "network_name", "description"):
                    val = getattr(i, attr, None)
                    if val and str(val).lower().strip("{}") == t:
                        return i
        except Exception:  # noqa: BLE001
            pass
        return None

    def _new_engine(self):
        from realtime.engine import RealtimeEngine
        from realtime.config import RealtimeConfig
        return RealtimeEngine(config=RealtimeConfig(flow_timeout=self.cfg.flow_timeout),
                              predictor=self.predictor, load_model=False)

    # ---- vòng đời: bắt gói trực tiếp ----------------------------------
    def start(self, iface: str) -> tuple:
        if self.running:
            return False, "Đang chạy rồi."
        if self.predictor is None:
            return False, "Chưa nạp được mô hình (cài scikit-learn, pandas, joblib)."
        scapy_iface = self._resolve_scapy_iface(iface)
        if iface and scapy_iface is None:
            # Không âm thầm rơi về card mặc định (dễ bắt nhầm card VPN/ảo)
            return False, f"Không tìm thấy card mạng: {iface}. Bấm 'Card mạng' để nạp lại."
        self.engine = self._new_engine()
        label = getattr(scapy_iface, "description", None) or getattr(scapy_iface, "name", None) or "card mặc định"
        self.iface = label
        self.mode = "live"
        self._simulate = False
        self._stop.clear()
        self.running = True
        self._note(f"Bắt đầu bắt gói trên: {label} (chờ lưu lượng...)")

        def worker():
            self._write_diag(scapy_iface)
            try:
                self.engine.live_capture(iface=scapy_iface, on_prediction=self.on_prediction,
                                         stop_event=self._stop)
            except Exception as exc:  # noqa: BLE001
                self._note(f"Lỗi bắt gói: {exc} (cần Npcap + quyền Admin)")
            finally:
                self.running = False

        self._thread = threading.Thread(target=worker, daemon=True)
        self._thread.start()
        return True, f"Đang giám sát trên {label}"

    # ---- vòng đời: phát lại pcap (demo 1 máy) --------------------------
    def replay(self, path: str, wait: bool = False) -> tuple:
        """Đưa 1 file .pcap qua ĐÚNG luồng: gom kết nối -> mô hình -> chặn.
        Chặn ở chế độ MÔ PHỎNG (không đụng tường lửa) vì IP trong pcap là giả."""
        if self.running:
            return False, "Đang chạy — bấm Dừng trước khi phát lại pcap."
        if self.predictor is None:
            return False, "Chưa nạp được mô hình (cài scikit-learn, pandas, joblib)."
        if not os.path.isfile(path):
            return False, f"Không thấy file: {path}"
        from realtime import pcap_io
        self.engine = self._new_engine()
        name = os.path.basename(path)
        self.iface = f"Phát lại {name}"
        self.mode = "replay"
        self._simulate = True
        self._stop.clear()
        self.running = True
        self._note(f"Phát lại {name} (chặn mô phỏng, không đụng tường lửa)")

        def emit(preds):
            for p in preds:
                if self._stop.is_set():
                    return
                self.on_prediction(p)
                if self.cfg.replay_delay > 0:
                    time.sleep(self.cfg.replay_delay)

        def worker():
            try:
                for meta in pcap_io.iter_pcap(path):
                    if self._stop.is_set():
                        break
                    emit(self.engine.ingest_packet(meta))
                emit(self.engine.flush())
                self._note(f"Phát lại xong {name}.")
            except Exception as exc:  # noqa: BLE001
                self._note(f"Lỗi phát lại pcap: {exc}")
            finally:
                self.running = False
                self._simulate = False

        if wait:
            worker()
        else:
            self._thread = threading.Thread(target=worker, daemon=True)
            self._thread.start()
        return True, f"Đang phát lại {name}"

    def stop(self):
        self._stop.set()
        self.running = False

    def reset(self) -> tuple:
        """Xoá số liệu/bảng để demo lại. Không gỡ các luật tường lửa thật."""
        if self.running:
            return False, "Đang chạy — bấm Dừng trước."
        with self._lock:
            self.alerts.clear()
            self.attacks.clear()
            self.devices.clear()
            self._hits.clear()
            self.blocker.clear_simulated()
            self.stats = self._empty_stats()
            self.stats["blocked"] = len(self.blocker.list_blocked())
        return True, "Đã xoá dữ liệu hiển thị."

    # ---- thiết bị trong mạng -------------------------------------------
    def _device(self, ip: str, now: float) -> dict:
        d = self.devices.get(ip)
        if d is None:
            d = {"ip": ip, "lan": is_lan_ip(ip), "self": ip in self.self_ips,
                 "first_seen": now, "last_seen": now, "connections": 0,
                 "attacks_sent": 0, "attacks_recv": 0, "last_attack": 0.0,
                 "unicast": False}
            self.devices[ip] = d
        d["last_seen"] = now
        return d

    def _touch_devices(self, conn, counted: bool, now: float):
        for ip, role, other in ((conn.src, "src", conn.dst), (conn.dst, "dst", conn.src)):
            # Bảng thiết bị: máy trong mạng nội bộ + nguồn tấn công bên ngoài
            if not (is_lan_ip(ip) or (counted and role == "src")):
                continue
            d = self._device(ip, now)
            d["connections"] += 1
            # "unicast" = có kết nối thật tới 1 địa chỉ cụ thể (máy shield, hoặc
            # đi qua shield khi shield làm gateway). Máy chỉ phát quảng bá/
            # multicast (SSDP, mDNS, NetBIOS...) thì không.
            if is_unicast(other):
                d["unicast"] = True
            if counted:
                if role == "src":
                    d["attacks_sent"] += 1
                    d["last_attack"] = now
                else:
                    d["attacks_recv"] += 1

    def _device_status(self, d: dict, now: float) -> str:
        if self.blocker.is_blocked(d["ip"]):
            return "đã chặn"
        if d["last_attack"] and now - d["last_attack"] <= max(self.cfg.block_window, 60):
            return "nghi vấn"
        return "bình thường"

    # ---- xử lý mỗi kết nối được phát hiện -----------------------------
    def on_prediction(self, pred):
        with self._lock:
            now = time.time()
            if self.engine:
                self.stats["packets"] = self.engine.stats.get("packets", self.stats["packets"])
            self.stats["connections"] += 1
            conn = pred.conn
            p_atk = attack_prob(pred)
            self_out = (conn.src in self.self_ips and not self.cfg.count_self_outbound
                        and not self._simulate)
            counted = bool(pred.is_attack) and p_atk >= self.cfg.min_attack_prob and not self_out
            action = "cho qua"
            if pred.is_attack and self_out:
                self.stats["suspects"] += 1
                action = "lưu lượng đi ra của máy shield (không tính)"
            elif pred.is_attack and not counted:
                self.stats["suspects"] += 1
                action = f"bỏ qua (P tấn công {round(p_atk * 100)}% < {round(self.cfg.min_attack_prob * 100)}%)"
            elif counted:
                self.stats["attacks"] += 1
                action = self._count_hit(conn.src, float(now if conn.ts is None else conn.ts))
            self._touch_devices(conn, counted, now)
            self.stats["devices"] = sum(1 for d in self.devices.values() if d["lan"] and d["unicast"])
            self.stats["broadcast_only"] = sum(1 for d in self.devices.values()
                                               if d["lan"] and not d["unicast"])

            row = {
                "ts": time.strftime("%H:%M:%S"),
                "src": f"{conn.src}:{conn.sport}", "dst": f"{conn.dst}:{conn.dport}",
                "service": conn.service, "flag": conn.flag,
                "category": pred.category, "confidence": round(pred.confidence * 100),
                "attack_prob": round(p_atk * 100),
                "is_attack": bool(pred.is_attack), "counted": counted, "action": action,
            }
            self.alerts.append(row)
            if pred.is_attack:
                self.attacks.append(row)

    def _count_hit(self, ip: str, ts: float) -> str:
        """Ghi 1 lần tấn công của `ip` vào cửa sổ trượt; chặn nếu vượt ngưỡng."""
        if self.blocker.is_blocked(ip):
            return "đã chặn trước đó"
        if self.blocker.should_skip(ip):
            return "CẢNH BÁO (IP trong whitelist, không chặn)"
        lo = ts - self.cfg.block_window
        # Lọc theo cửa sổ [ts - window, ts]; không giả định thứ tự đến của kết nối
        q = deque(t for t in self._hits.get(ip, ()) if lo <= t <= ts)
        q.append(ts)
        self._hits[ip] = q
        n = len(q)
        if not self.cfg.auto_block:
            return f"CẢNH BÁO ({n} lần/{int(self.cfg.block_window)}s, tắt tự chặn)"
        if n < self.cfg.block_threshold:
            return f"CẢNH BÁO ({n}/{self.cfg.block_threshold} lần trong {int(self.cfg.block_window)}s)"
        ok, how = self.blocker.block(ip, simulate=self._simulate)
        self._hits.pop(ip, None)
        self.stats["blocked"] = len(self.blocker.list_blocked())
        return f"CHẶN IP ({how})" if ok else f"CẢNH BÁO (chưa chặn: {how})"

    def _note(self, msg: str):
        self.alerts.append({"ts": time.strftime("%H:%M:%S"), "src": "-", "dst": "-",
                            "service": "-", "flag": "-", "category": "hệ thống",
                            "confidence": 0, "attack_prob": 0, "is_attack": False,
                            "counted": False, "action": msg, "system": True})

    def unblock(self, ip: str) -> bool:
        with self._lock:
            ok = self.blocker.unblock(ip)
            self._hits.pop(ip, None)
            self.stats["blocked"] = len(self.blocker.list_blocked())
            return ok

    def _maintain(self, now: float):
        """Tự gỡ chặn các IP đã hết thời hạn."""
        for ip in self.blocker.expire(self.cfg.block_ttl, now):
            self._note(f"Tự gỡ chặn {ip} (hết {int(self.cfg.block_ttl // 60)} phút)")
        self.stats["blocked"] = len(self.blocker.list_blocked())

    # ---- ảnh chụp trạng thái cho dashboard ----------------------------
    def snapshot(self) -> dict:
        with self._lock:
            now = time.time()
            self._maintain(now)
            # Cập nhật số gói ngay cả khi chưa có kết nối nào đóng (để thấy sớm
            # rằng việc bắt gói đang chạy).
            if self.engine is not None:
                self.stats["packets"] = self.engine.stats.get("packets", self.stats["packets"])
            ttl = self.cfg.block_ttl
            blocked = []
            for b in self.blocker.list_blocked():
                left = max(0, int(ttl - (now - b["ts"]))) if ttl and ttl > 0 else None
                blocked.append({"ip": b["ip"], "method": b["method"],
                                "simulated": bool(b.get("simulated")),
                                "since": time.strftime("%H:%M:%S", time.localtime(b["ts"])),
                                "expires_in": left})
            devs = []
            for d in self.devices.values():
                devs.append({"ip": d["ip"], "lan": d["lan"], "self": d["self"],
                             "unicast": d["unicast"] or not d["lan"],
                             "connections": d["connections"],
                             "attacks_sent": d["attacks_sent"],
                             "attacks_recv": d["attacks_recv"],
                             "last_seen": time.strftime("%H:%M:%S", time.localtime(d["last_seen"])),
                             "status": self._device_status(d, now)})
            order = {"đã chặn": 0, "nghi vấn": 1, "bình thường": 2}
            devs.sort(key=lambda x: (order[x["status"]], not x["unicast"],
                                     -x["attacks_sent"], -x["connections"]))
            return {
                "running": self.running,
                "mode": self.mode,
                "iface": self.iface,
                "admin": self.blocker.admin,
                "auto_block": self.cfg.auto_block,
                "policy": {"min_attack_prob": round(self.cfg.min_attack_prob * 100),
                           "threshold": self.cfg.block_threshold,
                           "window": int(self.cfg.block_window),
                           "ttl_min": round(self.cfg.block_ttl / 60, 1) if ttl else 0},
                "stats": dict(self.stats),
                "alerts": list(self.alerts)[-80:][::-1],
                "attacks": list(self.attacks)[-150:][::-1],
                "devices": devs[:200],
                "blocked": blocked,
            }
