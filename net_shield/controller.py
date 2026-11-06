"""
Bộ điều khiển IPS: bắt gói trực tiếp (realtime engine) -> phát hiện tấn công ->
TỰ CHẶN IP nguồn bằng tường lửa, đồng thời ghi cảnh báo cho dashboard.

Tách khỏi web server để kiểm thử được logic tự-chặn mà không cần HTTP/Npcap.
"""
from __future__ import annotations

import os
import sys
import threading
import time
from collections import Counter, deque
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


class IPSController:
    def __init__(self, cfg: Optional[IPSConfig] = None, predictor=None):
        self.cfg = cfg or IPSConfig()
        wl = set(self.cfg.whitelist) | set(local_ips())
        self.blocker = FirewallBlocker(whitelist=wl)
        self.predictor = predictor if predictor is not None else _load_predictor()
        self.engine = None
        self.running = False
        self.iface = None
        self._stop = threading.Event()
        self._thread = None
        self._lock = threading.Lock()
        self.alerts: Deque[dict] = deque(maxlen=self.cfg.max_alerts)
        self.ip_hits: Counter = Counter()
        self.stats = {"packets": 0, "connections": 0, "attacks": 0, "blocked": 0}

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

        Trả về None nếu không khớp -> để scapy tự bắt trên card mặc định.
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

    # ---- vòng đời -----------------------------------------------------
    def start(self, iface: str) -> tuple:
        if self.running:
            return False, "Đang chạy rồi."
        if self.predictor is None:
            return False, "Chưa nạp được mô hình (cài scikit-learn, pandas, joblib)."
        from realtime.engine import RealtimeEngine
        from realtime.config import RealtimeConfig
        self.engine = RealtimeEngine(
            config=RealtimeConfig(flow_timeout=self.cfg.flow_timeout),
            predictor=self.predictor, load_model=False)
        scapy_iface = self._resolve_scapy_iface(iface)
        label = getattr(scapy_iface, "description", None) or getattr(scapy_iface, "name", None) or "card mặc định"
        self.iface = label
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

    def stop(self):
        self._stop.set()
        self.running = False

    # ---- xử lý mỗi kết nối được phát hiện -----------------------------
    def on_prediction(self, pred):
        with self._lock:
            if self.engine:
                self.stats["packets"] = self.engine.stats.get("packets", self.stats["packets"])
            self.stats["connections"] += 1
            conn = pred.conn
            action = "cho qua"
            if pred.is_attack:
                self.stats["attacks"] += 1
                ip = conn.src
                self.ip_hits[ip] += 1
                if (self.cfg.auto_block and self.ip_hits[ip] >= self.cfg.block_threshold
                        and not self.blocker.should_skip(ip)
                        and ip not in {b["ip"] for b in self.blocker.list_blocked()}):
                    ok, how = self.blocker.block(ip)
                    self.stats["blocked"] = len(self.blocker.list_blocked())
                    action = f"CHẶN IP ({how})" if ok else f"CẢNH BÁO (chưa chặn: {how})"
                else:
                    action = "CẢNH BÁO"
            self.alerts.append({
                "ts": time.strftime("%H:%M:%S"),
                "src": f"{conn.src}:{conn.sport}", "dst": f"{conn.dst}:{conn.dport}",
                "service": conn.service, "flag": conn.flag,
                "category": pred.category, "confidence": round(pred.confidence * 100),
                "is_attack": bool(pred.is_attack), "action": action,
            })

    def _note(self, msg: str):
        self.alerts.append({"ts": time.strftime("%H:%M:%S"), "src": "-", "dst": "-",
                            "service": "-", "flag": "-", "category": "hệ thống",
                            "confidence": 0, "is_attack": False, "action": msg})

    def unblock(self, ip: str) -> bool:
        ok = self.blocker.unblock(ip)
        self.ip_hits[ip] = 0
        self.stats["blocked"] = len(self.blocker.list_blocked())
        return ok

    # ---- ảnh chụp trạng thái cho dashboard ----------------------------
    def snapshot(self) -> dict:
        with self._lock:
            # Cập nhật số gói ngay cả khi chưa có kết nối nào đóng (để thấy sớm
            # rằng việc bắt gói đang chạy).
            if self.engine is not None:
                self.stats["packets"] = self.engine.stats.get("packets", self.stats["packets"])
            return {
                "running": self.running,
                "iface": self.iface,
                "admin": self.blocker.admin,
                "auto_block": self.cfg.auto_block,
                "stats": dict(self.stats),
                "alerts": list(self.alerts)[-120:][::-1],
                "blocked": self.blocker.list_blocked(),
            }
