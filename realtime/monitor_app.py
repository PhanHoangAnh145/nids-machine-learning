"""
Cửa sổ GIÁM SÁT THỜI GIAN THỰC độc lập (CustomTkinter).

Chạy riêng, KHÔNG sửa main.py của luồng cũ:
    python -m realtime.monitor_app

Hai chế độ:
  * Bắt gói trực tiếp trên card mạng (cần Scapy + Npcap, quyền Administrator).
  * Phát lại một file .pcap (không cần Scapy) — tiện demo và kiểm thử.

Giao diện bám đúng mẫu của main.py cũ: việc bắt/đọc gói chạy ở LUỒNG NỀN,
cập nhật bảng và bộ đếm qua self.after() để không treo giao diện.
"""
from __future__ import annotations

import os
import sys
import threading
import time
from tkinter import filedialog

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from realtime.config import RealtimeConfig
from realtime.engine import Prediction, RealtimeEngine

try:
    import customtkinter as ctk
except ImportError:
    ctk = None


class RealtimeMonitorApp(ctk.CTk if ctk else object):
    def __init__(self):
        super().__init__()
        self.title("NIDS SHIELD - Giám sát thời gian thực")
        self.geometry("1040x680")
        self.engine = RealtimeEngine(config=RealtimeConfig())
        self._stop = threading.Event()
        self._worker = None
        self._counts = {"conn": 0, "attack": 0, "pkt": 0}
        self._build()

    # ---- giao diện ----------------------------------------------------
    def _build(self):
        import customtkinter as ctk
        top = ctk.CTkFrame(self)
        top.pack(fill="x", padx=12, pady=10)
        ctk.CTkLabel(top, text="🛡️ Giám sát thời gian thực", font=ctk.CTkFont(size=18, weight="bold")).pack(side="left", padx=10)
        self.iface_entry = ctk.CTkEntry(top, placeholder_text="Tên card mạng (vd Wi-Fi)", width=200)
        self.iface_entry.pack(side="left", padx=6)
        self.btn_live = ctk.CTkButton(top, text="▶ Bắt gói trực tiếp", command=self.start_live)
        self.btn_live.pack(side="left", padx=6)
        self.btn_replay = ctk.CTkButton(top, text="📂 Phát lại .pcap", command=self.start_replay)
        self.btn_replay.pack(side="left", padx=6)
        self.btn_stop = ctk.CTkButton(top, text="⏹ Dừng", fg_color="#a33", command=self.stop)
        self.btn_stop.pack(side="left", padx=6)

        cards = ctk.CTkFrame(self)
        cards.pack(fill="x", padx=12, pady=(0, 8))
        self.lbl_pkt = self._card(cards, "Gói tin", "0")
        self.lbl_conn = self._card(cards, "Kết nối", "0")
        self.lbl_atk = self._card(cards, "Cảnh báo tấn công", "0", "#e55")

        self.box = ctk.CTkTextbox(self, font=ctk.CTkFont(family="Consolas", size=12))
        self.box.pack(fill="both", expand=True, padx=12, pady=(0, 12))

    def _card(self, parent, title, value, color=None):
        import customtkinter as ctk
        f = ctk.CTkFrame(parent)
        f.pack(side="left", expand=True, fill="x", padx=6, pady=6)
        ctk.CTkLabel(f, text=title).pack(pady=(8, 0))
        lbl = ctk.CTkLabel(f, text=value, font=ctk.CTkFont(size=22, weight="bold"),
                           text_color=color)
        lbl.pack(pady=(0, 8))
        return lbl

    # ---- điều khiển ---------------------------------------------------
    def start_live(self):
        iface = self.iface_entry.get().strip() or None
        self._start(lambda: self.engine.live_capture(
            iface=iface, on_prediction=self._on_pred, stop_event=self._stop))

    def start_replay(self):
        path = filedialog.askopenfilename(filetypes=[("PCAP", "*.pcap *.pcapng"), ("All", "*.*")])
        if not path:
            return
        self._append(f"[*] Phát lại {os.path.basename(path)} ...\n")
        self._start(lambda: self.engine.replay_pcap(path, on_prediction=self._on_pred))

    def _start(self, target):
        if self._worker and self._worker.is_alive():
            return
        self._stop.clear()
        self._worker = threading.Thread(target=self._guard(target), daemon=True)
        self._worker.start()

    def _guard(self, target):
        def run():
            try:
                target()
            except Exception as exc:              # noqa: BLE001
                self.after(0, lambda: self._append(f"[!] Lỗi: {exc}\n"))
        return run

    def stop(self):
        self._stop.set()

    # ---- cập nhật từ luồng nền ---------------------------------------
    def _on_pred(self, pred: Prediction):
        self.after(0, lambda: self._render(pred))

    def _render(self, pred: Prediction):
        self._counts["conn"] += 1
        self._counts["attack"] += int(pred.is_attack)
        self._counts["pkt"] = self.engine.stats["packets"]
        self.lbl_pkt.configure(text=str(self._counts["pkt"]))
        self.lbl_conn.configure(text=str(self._counts["conn"]))
        self.lbl_atk.configure(text=str(self._counts["attack"]))
        if pred.is_attack:
            c = pred.conn
            self._append(f"🚨 {c.src}:{c.sport} -> {c.dst}:{c.dport} "
                         f"[{c.proto}/{c.service}/{c.flag}] {pred.category.upper()} "
                         f"({pred.confidence*100:.0f}%)\n")

    def _append(self, text):
        self.box.insert("end", text)
        self.box.see("end")


def main():
    if ctk is None:
        print("Cần customtkinter: pip install customtkinter")
        return 1
    RealtimeMonitorApp().mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
