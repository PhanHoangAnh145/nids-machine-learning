"""
Chặn IP bằng tường lửa hệ điều hành (Windows Firewall / iptables).

- Windows: thêm luật  netsh advfirewall firewall add rule ... action=block remoteip=<ip>
- Linux:   iptables -A INPUT -s <ip> -j DROP   (và OUTPUT -d)
Cần quyền Administrator/root. Nếu KHÔNG đủ quyền -> chạy chế độ "logic" (chỉ ghi
vào danh sách chặn nội bộ để cảnh báo), không gọi tường lửa.

An toàn:
- Chỉ nhận IP hợp lệ (chống chèn lệnh); gọi subprocess bằng DANH SÁCH tham số,
  không qua shell.
- Không bao giờ chặn loopback hoặc IP trong whitelist (tránh tự khoá máy).
"""
from __future__ import annotations

import ipaddress
import os
import subprocess
import time
from typing import Dict, List, Tuple

RULE_PREFIX = "NIDS_SHIELD_"


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
        self._blocked: Dict[str, dict] = {}   # ip -> {ts, method}

    # ---- công khai ----------------------------------------------------
    def should_skip(self, ip: str) -> bool:
        return (not _valid_ip(ip) or ip in self.whitelist
                or ip.startswith("127.") or ip in ("0.0.0.0", "255.255.255.255"))

    def block(self, ip: str) -> Tuple[bool, str]:
        if not _valid_ip(ip):
            return False, "IP không hợp lệ"
        if self.should_skip(ip):
            return False, "bỏ qua (whitelist/loopback)"
        if ip in self._blocked:
            return True, self._blocked[ip]["method"]
        ok, how = self._apply(ip, block=True)
        self._blocked[ip] = {"ts": time.time(), "method": how}
        return ok, how

    def unblock(self, ip: str) -> bool:
        if ip not in self._blocked:
            return False
        self._apply(ip, block=False)
        del self._blocked[ip]
        return True

    def list_blocked(self) -> List[dict]:
        return [{"ip": ip, **info} for ip, info in self._blocked.items()]

    def clear_all(self):
        for ip in list(self._blocked):
            self.unblock(ip)

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
