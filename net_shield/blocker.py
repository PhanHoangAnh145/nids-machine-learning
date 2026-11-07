"""
Chặn IP bằng tường lửa hệ điều hành (Windows Firewall / iptables).

- Windows: thêm luật  netsh advfirewall firewall add rule ... action=block remoteip=<ip>
- Linux:   iptables -A INPUT -s <ip> -j DROP   (và OUTPUT -d)
Cần quyền Administrator/root. Nếu KHÔNG đủ quyền -> chạy chế độ "logic" (chỉ ghi
vào danh sách chặn nội bộ để cảnh báo), không gọi tường lửa.

Bổ sung:
- Chặn "mô phỏng" (simulate=True): dùng khi phát lại pcap — chỉ ghi danh sách,
  không đụng tường lửa (IP trong pcap là IP giả).
- Tự gỡ chặn sau một thời gian (expire()).
- Khôi phục danh sách từ các luật NIDS_SHIELD_* còn trong Windows Firewall khi
  khởi động lại (load_existing()).

An toàn:
- Chỉ nhận IP hợp lệ (chống chèn lệnh); gọi subprocess bằng DANH SÁCH tham số,
  không qua shell.
- Không bao giờ chặn loopback hoặc IP trong whitelist (tránh tự khoá máy).
"""
from __future__ import annotations

import ipaddress
import os
import re
import subprocess
import time
from typing import Dict, List, Tuple

RULE_PREFIX = "NIDS_SHIELD_"
SIMULATED = "mô phỏng (phát lại pcap)"


def is_admin() -> bool:
    try:
        if os.name == "nt":
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:  # noqa: BLE001
        return False


def _valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


class FirewallBlocker:
    def __init__(self, whitelist=None, force_dry_run: bool = False):
        self.admin = is_admin()
        self.dry_run = force_dry_run or not self.admin
        self.whitelist = set(whitelist or [])
        self._blocked: Dict[str, dict] = {}   # ip -> {ts, method, simulated}

    # ---- công khai ----------------------------------------------------
    def should_skip(self, ip: str) -> bool:
        return (not _valid_ip(ip) or ip in self.whitelist
                or ip.startswith("127.") or ip in ("0.0.0.0", "255.255.255.255"))

    def is_blocked(self, ip: str) -> bool:
        return ip in self._blocked

    def block(self, ip: str, simulate: bool = False) -> Tuple[bool, str]:
        if not _valid_ip(ip):
            return False, "IP không hợp lệ"
        if self.should_skip(ip):
            return False, "bỏ qua (whitelist/loopback)"
        if ip in self._blocked:
            return True, self._blocked[ip]["method"]
        if simulate:
            ok, how = True, SIMULATED
        else:
            ok, how = self._apply(ip, block=True)
        self._blocked[ip] = {"ts": time.time(), "method": how, "simulated": simulate}
        return ok, how

    def unblock(self, ip: str) -> bool:
        info = self._blocked.get(ip)
        if info is None:
            return False
        if not info.get("simulated"):
            self._apply(ip, block=False)
        del self._blocked[ip]
        return True

    def list_blocked(self) -> List[dict]:
        return [{"ip": ip, **info} for ip, info in self._blocked.items()]

    def clear_all(self):
        for ip in list(self._blocked):
            self.unblock(ip)

    def clear_simulated(self):
        for ip, info in list(self._blocked.items()):
            if info.get("simulated"):
                self.unblock(ip)

    def expire(self, ttl: float, now: float = None) -> List[str]:
        """Gỡ các IP đã bị chặn quá `ttl` giây. Trả về danh sách IP vừa gỡ."""
        if not ttl or ttl <= 0:
            return []
        now = time.time() if now is None else now
        old = [ip for ip, info in self._blocked.items() if now - info["ts"] >= ttl]
        for ip in old:
            self.unblock(ip)
        return old

    def load_existing(self) -> List[str]:
        """Đọc lại các luật NIDS_SHIELD_* còn trong Windows Firewall (vd sau khi
        chương trình bị tắt đột ngột) để dashboard hiển thị và gỡ được."""
        if self.dry_run or os.name != "nt":
            return []
        try:
            out = subprocess.run(
                ["netsh", "advfirewall", "firewall", "show", "rule", "name=all"],
                capture_output=True, timeout=30).stdout
            text = out.decode("latin-1")   # tên luật là ASCII, bảng mã nào cũng đọc được
        except Exception:  # noqa: BLE001
            return []
        found = []
        for ip in set(re.findall(re.escape(RULE_PREFIX) + r"([0-9.]+)_(?:in|out)", text)):
            if _valid_ip(ip) and ip not in self._blocked:
                self._blocked[ip] = {"ts": time.time(), "method": "firewall (khôi phục)",
                                     "simulated": False}
                found.append(ip)
        return found

    # ---- nội bộ -------------------------------------------------------
    def _apply(self, ip: str, block: bool) -> Tuple[bool, str]:
        if self.dry_run:
            return False, "logic (chưa có quyền Admin)"
        try:
            if os.name == "nt":
                if block:
                    for d in ("in", "out"):
                        subprocess.run(
                            ["netsh", "advfirewall", "firewall", "add", "rule",
                             f"name={RULE_PREFIX}{ip}_{d}", f"dir={d}", "action=block",
                             f"remoteip={ip}"],
                            check=True, capture_output=True, timeout=10)
                else:
                    for d in ("in", "out"):
                        subprocess.run(
                            ["netsh", "advfirewall", "firewall", "delete", "rule",
                             f"name={RULE_PREFIX}{ip}_{d}"],
                            check=False, capture_output=True, timeout=10)
            else:
                if block:
                    subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                                   check=True, capture_output=True, timeout=10)
                    subprocess.run(["iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP"],
                                   check=False, capture_output=True, timeout=10)
                else:
                    subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                                   check=False, capture_output=True, timeout=10)
                    subprocess.run(["iptables", "-D", "OUTPUT", "-d", ip, "-j", "DROP"],
                                   check=False, capture_output=True, timeout=10)
            return True, "firewall"
        except Exception as exc:  # noqa: BLE001
            return False, f"lỗi firewall: {exc}"
