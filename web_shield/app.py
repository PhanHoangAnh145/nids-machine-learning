"""
GIAO DIỆN Phần 3 — Web Shield (reverse proxy).

Bật lá chắn trước một web server; bảng hiển thị từng request đi qua, request nguy
hiểm bị chặn (dòng đỏ). Server chạy ở LUỒNG NỀN, cập nhật UI qua self.after.

Chạy:  python -m web_shield
"""
from __future__ import annotations

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from web_shield.config import ShieldConfig
from web_shield.proxy import ShieldServer, ShieldEvent

try:
    import customtkinter as ctk
    from tkinter import ttk
except ImportError:
    ctk = None

C_GREEN, C_GREEN_H = "#2ca02c", "#227d22"
C_RED, C_RED_H = "#c0392b", "#a5281b"
C_MUTED = "gray"


class ShieldApp(ctk.CTk if ctk else object):
    def __init__(self):
        super().__init__()
        self.title("NIDS SHIELD · Web Shield (Phần 3)")
        self.geometry("980x720")
        self.minsize(820, 640)
        self.server = None
        self._build()

    def _mini(self, parent, col, title, val, color=None):
        f = ctk.CTkFrame(parent, fg_color=("gray85", "gray20"))
        f.grid(row=0, column=col, padx=8, pady=10, sticky="nsew")
        ctk.CTkLabel(f, text=title, font=ctk.CTkFont(size=12)).pack(pady=(8, 2))
        lbl = ctk.CTkLabel(f, text=val, font=ctk.CTkFont(size=20, weight="bold"), text_color=color)
        lbl.pack(pady=(0, 8))
        return lbl

    def _build(self):
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", padx=16, pady=(14, 8))
        ctk.CTkLabel(header, text="🛡️  Web Shield",
                     font=ctk.CTkFont(size=22, weight="bold")).pack(side="left")
        ctk.CTkLabel(header, text="  Phần 3 · Lá chắn web (reverse proxy)",
                     text_color=C_MUTED, font=ctk.CTkFont(size=13)).pack(side="left")

        # ---- Cấu hình ---------------------------------------------------
        cfg = ctk.CTkFrame(self)
        cfg.pack(fill="x", padx=16, pady=(0, 12))
        row = ctk.CTkFrame(cfg, fg_color="transparent")
        row.pack(fill="x", padx=16, pady=12)
        ctk.CTkLabel(row, text="Cổng lá chắn").pack(side="left", padx=(0, 6))
        self.ent_listen = ctk.CTkEntry(row, width=80)
        self.ent_listen.insert(0, "8080")
        self.ent_listen.pack(side="left", padx=(0, 16))
        ctk.CTkLabel(row, text="Web thật (host:cổng)").pack(side="left", padx=(0, 6))
        self.ent_up_host = ctk.CTkEntry(row, width=130)
        self.ent_up_host.insert(0, "127.0.0.1")
        self.ent_up_host.pack(side="left", padx=(0, 4))
        self.ent_up_port = ctk.CTkEntry(row, width=70)
        self.ent_up_port.insert(0, "8000")
        self.ent_up_port.pack(side="left", padx=(0, 16))
        self.btn_start = ctk.CTkButton(row, text="▶ Bật lá chắn", fg_color=C_GREEN,
                                       hover_color=C_GREEN_H, font=ctk.CTkFont(weight="bold"),
                                       command=self.start)
        self.btn_start.pack(side="left", padx=4)
        self.btn_stop = ctk.CTkButton(row, text="⏹ Tắt", fg_color=C_RED, hover_color=C_RED_H,
                                      command=self.stop, state="disabled")
        self.btn_stop.pack(side="left", padx=4)
        self.lbl_status = ctk.CTkLabel(cfg, text="Lá chắn đang tắt.", anchor="w", text_color=C_MUTED)
        self.lbl_status.pack(fill="x", padx=16, pady=(0, 12))

        # ---- Thống kê ---------------------------------------------------
        stat = ctk.CTkFrame(self)
        stat.pack(fill="x", padx=16, pady=(0, 12))
        stat.grid_columnconfigure((0, 1, 2, 3), weight=1)
        self.card_total = self._mini(stat, 0, "Tổng request", "0", "gray")
        self.card_pass = self._mini(stat, 1, "Cho qua", "0", C_GREEN)
        self.card_block = self._mini(stat, 2, "Đã chặn", "0", C_RED)
        self.card_ips = self._mini(stat, 3, "IP bị chặn", "0", "#ff7f0e")

        # ---- Bảng request ----------------------------------------------
        tbl = ctk.CTkFrame(self)
        tbl.pack(fill="both", expand=True, padx=16, pady=(0, 14))
        tbl.grid_rowconfigure(0, weight=1)
        tbl.grid_columnconfigure(0, weight=1)
        cols = ("time", "ip", "method", "path", "verdict", "action")
        self.tree = ttk.Treeview(tbl, columns=cols, show="headings", selectmode="browse")
        for c, t, w, a in [
            ("time", "Thời gian", 90, "center"), ("ip", "IP nguồn", 150, "w"),
            ("method", "Method", 80, "center"), ("path", "Đường dẫn", 320, "w"),
            ("verdict", "Phán định", 160, "w"), ("action", "Hành động", 110, "center"),
        ]:
            self.tree.heading(c, text=t)
            self.tree.column(c, width=w, anchor=a)
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except Exception:  # noqa: BLE001
            pass
        style.configure("Treeview", rowheight=24, font=("Segoe UI", 10))
        style.configure("Treeview.Heading", font=("Segoe UI", 10, "bold"))
        sc = ttk.Scrollbar(tbl, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sc.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        sc.grid(row=0, column=1, sticky="ns")
        self.tree.tag_configure("block", background="#ffd6d6", foreground="#8b0000")
        self.tree.tag_configure("pass", background="#eef7ee", foreground="#145a14")

    # ---- điều khiển -------------------------------------------------------
    def start(self):
        if self.server:
            return
        try:
            cfg = ShieldConfig(
                listen_host="0.0.0.0", listen_port=int(self.ent_listen.get()),
                upstream_host=self.ent_up_host.get().strip() or "127.0.0.1",
                upstream_port=int(self.ent_up_port.get()))
            self.server = ShieldServer(cfg, on_event=self._on_event)
            self.server.start_background()
        except Exception as exc:  # noqa: BLE001
            self.lbl_status.configure(text=f"Lỗi bật lá chắn: {exc}", text_color=C_RED)
            self.server = None
            return
        self.btn_start.configure(state="disabled")
        self.btn_stop.configure(state="normal")
        self.lbl_status.configure(
            text=(f"● Đang bảo vệ: trình duyệt trỏ tới http://<IP máy này>:{cfg.listen_port}  "
                  f"→  web thật {cfg.upstream_host}:{cfg.upstream_port}"),
            text_color=C_GREEN)

    def stop(self):
        if self.server:
            self.server.stop()
            self.server = None
        self.btn_start.configure(state="normal")
        self.btn_stop.configure(state="disabled")
        self.lbl_status.configure(text="Lá chắn đang tắt.", text_color=C_MUTED)

    def _on_event(self, ev: ShieldEvent):
        self.after(0, lambda: self._add_row(ev))

    def _add_row(self, ev: ShieldEvent):
        if not self.server:
            return
        blocked = not ev.verdict.allowed
        tag = "block" if blocked else "pass"
        verdict = ev.verdict.category if blocked else "Sạch"
        action = f"⛔ CHẶN {ev.status}" if blocked else f"✅ {ev.status}"
        self.tree.insert("", "end", tags=(tag,), values=(
            time.strftime("%H:%M:%S"), ev.ip, ev.method, ev.path[:60], verdict, action))
        kids = self.tree.get_children()
        if len(kids) > 300:
            self.tree.delete(kids[0])
        self.tree.see(self.tree.get_children()[-1])
        st = self.server.stats
        self.card_total.configure(text=str(st["total"]))
        self.card_block.configure(text=str(st["blocked"]))
        self.card_pass.configure(text=str(st["total"] - st["blocked"]))
        self.card_ips.configure(text=str(len(self.server.detector.blocked_ips())))


def main():
    if ctk is None:
        print("Cần customtkinter: pip install customtkinter")
        return 1
    ctk.set_appearance_mode("Dark")
    ctk.set_default_color_theme("blue")
    ShieldApp().mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
