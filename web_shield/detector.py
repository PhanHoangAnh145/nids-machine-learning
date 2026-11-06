"""
Bộ phát hiện tấn công WEB cho lá chắn (reverse proxy).

Hai lớp:
  1) Luật (chữ ký) — quét URL, tham số, thân request và User-Agent để nhận ra
     SQL Injection, XSS, Path Traversal và công cụ quét lỗ hổng.
  2) Tần suất — đếm request mỗi IP trong cửa sổ thời gian để bắt HTTP flood (DoS).

Đây là bộ phát hiện tầng ỨNG DỤNG (nội dung HTTP), bổ trợ cho mô hình NSL-KDD
tầng mạng ở Phần 1. Mọi mẫu chữ ký ở đây để NHẬN DIỆN tấn công, không phải để
thực hiện tấn công.
"""
from __future__ import annotations

import re
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Deque, Dict, List, Tuple
from urllib.parse import unquote_plus

# --- Chữ ký nhận dạng (regex, không phân biệt hoa thường) --------------------
_SIG: List[Tuple[str, str, str]] = [
    # (category, severity, pattern)
    ("SQLi", "cao", r"(?:'|%27)\s*(?:or|and)\s+[\w'\"]+\s*=\s*[\w'\"]+"),
    ("SQLi", "cao", r"\bunion\s+select\b"),
    ("SQLi", "cao", r"\b(?:select|insert|update|delete|drop)\b.*\bfrom\b|\bdrop\s+table\b"),
    ("SQLi", "vừa", r"(?:sleep|benchmark|pg_sleep|waitfor\s+delay)\s*\("),
    ("SQLi", "vừa", r"(?:--|#|/\*).*(?:or|and|select)"),
    ("XSS", "cao", r"<\s*script\b|%3cscript"),
    ("XSS", "vừa", r"on(?:error|load|mouseover|click)\s*=|javascript:"),
    ("XSS", "vừa", r"<\s*(?:img|svg|iframe)\b[^>]*="),
    ("Path Traversal", "cao", r"(?:\.\./|\.\.\\|%2e%2e[/\\]){2,}|/etc/passwd|boot\.ini|win\.ini"),
    ("Command Injection", "cao", r";\s*(?:cat|ls|id|whoami|pwd|curl|wget|nc)\b|\$\((?:.|\n)*\)|`[^`]+`"),
]
_SIG_RE = [(cat, sev, re.compile(pat, re.IGNORECASE)) for cat, sev, pat in _SIG]

# Công cụ quét/khai thác hay gặp trong User-Agent
_SCANNER_UA = re.compile(
    r"\b(sqlmap|nikto|nmap|masscan|acunetix|nessus|dirbuster|gobuster|wpscan|"
    r"fuzz|hydra|zgrab|nuclei|openvas)\b", re.IGNORECASE)


@dataclass
class Verdict:
    allowed: bool
    category: str = "Sạch"
    severity: str = ""
    reason: str = ""
    matched: str = ""          # đoạn khớp (để hiển thị/log)


@dataclass
class _RateState:
    hits: Deque[float] = field(default_factory=deque)


class WebDetector:
    def __init__(self, rate_window: float = 10.0, rate_max: int = 80,
                 block_seconds: float = 60.0):
        self.rate_window = rate_window
        self.rate_max = rate_max
        self.block_seconds = block_seconds
        self._rate: Dict[str, _RateState] = defaultdict(_RateState)
        self._blocked_until: Dict[str, float] = {}

    # ---- chặn theo IP (sau khi đã phát hiện flood) --------------------
    def is_ip_blocked(self, ip: str, now: float = None) -> bool:
        now = now or time.time()
        until = self._blocked_until.get(ip)
        if until is None:
            return False
        if now >= until:
            del self._blocked_until[ip]
            return False
        return True

    def block_ip(self, ip: str, now: float = None) -> None:
        now = now or time.time()
        self._blocked_until[ip] = now + self.block_seconds

    def blocked_ips(self) -> List[str]:
        now = time.time()
        return [ip for ip, until in self._blocked_until.items() if until > now]

    # ---- kiểm tra tần suất (HTTP flood) -------------------------------
    def _check_rate(self, ip: str, now: float) -> bool:
        st = self._rate[ip]
        st.hits.append(now)
        lo = now - self.rate_window
        while st.hits and st.hits[0] < lo:
            st.hits.popleft()
        return len(st.hits) > self.rate_max

    # ---- quét chữ ký --------------------------------------------------
    @staticmethod
    def _scan_signatures(text: str) -> Verdict | None:
        decoded = unquote_plus(text or "")
        for cat, sev, rx in _SIG_RE:
            m = rx.search(decoded)
            if m:
                return Verdict(allowed=False, category=cat, severity=sev,
                               reason=f"Khớp chữ ký {cat}", matched=m.group(0)[:80])
        return None

    def inspect(self, ip: str, method: str, path: str, query: str,
                headers: Dict[str, str], body: bytes = b"", now: float = None) -> Verdict:
        """Quyết định cho qua hay chặn một request."""
        now = now or time.time()

        # 1) IP đang trong danh sách chặn
        if self.is_ip_blocked(ip, now):
            return Verdict(False, "Đã chặn", "cao", "IP đang bị chặn tạm thời")

        # 2) User-Agent của công cụ quét
        ua = headers.get("user-agent", "")
        m = _SCANNER_UA.search(ua)
        if m:
            self.block_ip(ip, now)
            return Verdict(False, "Scanner", "cao",
                           f"Công cụ quét: {m.group(0)}", matched=m.group(0))

        # 3) Chữ ký trên URL + query + thân request
        for chunk in (path, query, body.decode("utf-8", "ignore")):
            v = self._scan_signatures(chunk)
            if v:
                return v

        # 4) Tần suất (HTTP flood -> DoS)
        if self._check_rate(ip, now):
            self.block_ip(ip, now)
            return Verdict(False, "DoS/Flood", "cao",
                           f"Vượt {self.rate_max} request/{self.rate_window:.0f}s")

        return Verdict(True, "Sạch")
