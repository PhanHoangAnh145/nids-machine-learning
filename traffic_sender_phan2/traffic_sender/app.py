"""
GIAO DIỆN Phần 2 — Traffic Generator & Sender (CustomTkinter).

Chỉ chứa logic GIAO DIỆN; mọi xử lý pcap nằm ở pcap_tools.py. Việc gửi gói chạy
trên LUỒNG PHỤ (threading) nên không làm đơ UI; tiến độ/log cập nhật qua self.after.

Chạy:  python -m traffic_sender

CẢNH BÁO: Công cụ kiểm thử NIDS trong phòng lab. Chỉ phát gói tới máy/mạng do
chính bạn sở hữu và được phép thử nghiệm.
"""
from __future__ import annotations

import os
import sys
import threading
from tkinter import filedialog

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from traffic_sender import pcap_tools as pt

try:
    import customtkinter as ctk
except ImportError:
    ctk = None

# Màu dùng chung (đồng bộ với app Phần 1)
C_GREEN, C_GREEN_H = "#2ca02c", "#227d22"
C_RED, C_RED_H = "#c0392b", "#a5281b"
C_BLUE, C_BLUE_H = "#1f6aa5", "#17537f"
C_MUTED = "gray"

# Mô tả ngắn cho từng kiểu tấn công (theo nhãn trong pcap_tools.TEMPLATES)
ATTACK_DESC = {
    "A - DoS / SYN Flood": "Gửi ồ ạt gói SYN tới một cổng, không hoàn tất bắt tay → nghẽn dịch vụ.",
    "B - Port Scanning": "Lần lượt dò nhiều cổng để tìm dịch vụ đang mở.",
    "C - Web Request (HTTP)": "Một phiên HTTP bình thường — dùng để kiểm tra báo động giả.",
}


class SenderApp(ctk.CTk if ctk else object):
    def __init__(self):
        super().__init__()
        self.title("NIDS Lab · Traffic Sender (Phần 2)")
        self.geometry("840x880")
        self.minsize(760, 760)
        self.last_generated = None
        self._send_thread = None
        self._stop = threading.Event()
        self._build()

    # ===================================================================== UI
    def _card(self, title, subtitle=None):
        """Tạo một 'thẻ' có tiêu đề, trả về khung nội dung bên trong."""
        wrap = ctk.CTkFrame(self)
        wrap.pack(fill="x", padx=16, pady=(0, 12))
        head = ctk.CTkFrame(wrap, fg_color="transparent")
        head.pack(fill="x", padx=16, pady=(12, 0))
        ctk.CTkLabel(head, text=title, font=ctk.CTkFont(size=15, weight="bold")).pack(side="left")
        if subtitle:
            ctk.CTkLabel(head, text="  " + subtitle, text_color=C_MUTED).pack(side="left")
        body = ctk.CTkFrame(wrap, fg_color="transparent")
        body.pack(fill="x", padx=16, pady=(6, 14))
        return body

    def _build(self):
        # ---- Header ----------------------------------------------------
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", padx=16, pady=(14, 10))
        ctk.CTkLabel(header, text="🛰️  Traffic Sender",
                     font=ctk.CTkFont(size=22, weight="bold")).pack(side="left")
        ctk.CTkLabel(header, text="  Phần 2 · Mô phỏng lưu lượng tấn công",
                     text_color=C_MUTED, font=ctk.CTkFont(size=13)).pack(side="left")
        ctk.CTkLabel(header, text="⚠ CHỈ DÙNG TRONG LAB", text_color="#e0a030",
                     font=ctk.CTkFont(size=11, weight="bold")).pack(side="right")

        # ---- ① TẠO GÓI TIN --------------------------------------------
        g = self._card("① Tạo gói tin", "từ kho mẫu trong templates/")
        g.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(g, text="Kiểu tấn công").grid(row=0, column=0, sticky="w", pady=6, padx=(0, 10))
        self.templates = pt.list_templates()
        labels = list(self.templates.keys()) or ["(thiếu file mẫu)"]
        self.cbo_type = ctk.CTkOptionMenu(g, values=labels, width=280, command=self._on_type_change)
        self.cbo_type.grid(row=0, column=1, sticky="w", pady=6)
        self.lbl_type_desc = ctk.CTkLabel(g, text=ATTACK_DESC.get(labels[0], ""),
                                          text_color=C_MUTED, font=ctk.CTkFont(size=12))
        self.lbl_type_desc.grid(row=1, column=1, sticky="w", pady=(0, 6))

        ctk.CTkLabel(g, text="IP nguồn").grid(row=2, column=0, sticky="w", pady=6, padx=(0, 10))
        srow = ctk.CTkFrame(g, fg_color="transparent")
        srow.grid(row=2, column=1, sticky="w")
        self.chk_rand = ctk.CTkCheckBox(srow, text="Ngẫu nhiên", command=self._toggle_src)
        self.chk_rand.select()
        self.chk_rand.pack(side="left", padx=(0, 10))
        self.ent_src = ctk.CTkEntry(srow, placeholder_text="vd 10.0.0.9", width=160, state="disabled")
        self.ent_src.pack(side="left")

        ctk.CTkLabel(g, text="IP đích").grid(row=3, column=0, sticky="w", pady=6, padx=(0, 10))
        drow = ctk.CTkFrame(g, fg_color="transparent")
        drow.grid(row=3, column=1, sticky="w")
        self.ent_dst = ctk.CTkEntry(drow, placeholder_text="để trống cũng được", width=160)
        self.ent_dst.pack(side="left", padx=(0, 12))
        self.chk_time = ctk.CTkCheckBox(drow, text="Mới hoá thời gian")
        self.chk_time.select()
        self.chk_time.pack(side="left", padx=(0, 10))
        self.chk_cks = ctk.CTkCheckBox(drow, text="Tính lại checksum")
        self.chk_cks.select()
        self.chk_cks.pack(side="left")

        grow = ctk.CTkFrame(g, fg_color="transparent")
        grow.grid(row=4, column=1, sticky="w", pady=(8, 0))
        self.btn_gen = ctk.CTkButton(grow, text="⚙  Tạo gói tin", width=150, height=36,
                                     font=ctk.CTkFont(weight="bold"), command=self.on_generate)
        self.btn_gen.pack(side="left", padx=(0, 12))
        self.lbl_gen = ctk.CTkLabel(grow, text="chưa tạo file nào", text_color=C_MUTED)
        self.lbl_gen.pack(side="left")

        # ---- ② GỬI TỚI PHẦN 1 (socket) --------------------------------
        s = self._card("② Gửi tới Phần 1", "khuyên dùng · không cần Npcap/quyền Admin")
        s.grid_columnconfigure(3, weight=1)

        ctk.CTkLabel(s, text="Địa chỉ Phần 1").grid(row=0, column=0, sticky="w", pady=6, padx=(0, 10))
        self.ent_part1_ip = ctk.CTkEntry(s, width=200)
        self.ent_part1_ip.insert(0, "127.0.0.1")
        self.ent_part1_ip.grid(row=0, column=1, sticky="w", pady=6)
        ctk.CTkLabel(s, text=f"cổng {pt.PART1_PORT}", text_color=C_MUTED).grid(
            row=0, column=2, sticky="w", padx=10)

        self.btn_part1 = ctk.CTkButton(s, text="🛰  Gửi tới Phần 1", width=180, height=38,
                                       fg_color=C_GREEN, hover_color=C_GREEN_H,
                                       font=ctk.CTkFont(weight="bold"), command=self.on_send_to_part1)
        self.btn_part1.grid(row=1, column=0, columnspan=2, sticky="w", pady=(8, 2))
        ctk.CTkLabel(s, text="cùng máy: 127.0.0.1   •   khác máy: IP máy chạy Phần 1",
                     text_color=C_MUTED, font=ctk.CTkFont(size=12)).grid(
            row=2, column=0, columnspan=4, sticky="w", pady=(0, 2))

        # ---- ③ NÂNG CAO: phát ra card mạng ----------------------------
        a = self._card("③ Nâng cao · phát gói thô ra card mạng", "cần Npcap + quyền Admin")
        a.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(a, text="Card mạng").grid(row=0, column=0, sticky="w", pady=6, padx=(0, 10))
        irow = ctk.CTkFrame(a, fg_color="transparent")
        irow.grid(row=0, column=1, sticky="ew")
        self.cbo_iface = ctk.CTkOptionMenu(irow, values=["(bấm nạp)"], width=360)
        self.cbo_iface.pack(side="left")
        ctk.CTkButton(irow, text="🔄", width=40, command=self._refresh_ifaces).pack(side="left", padx=6)

        ctk.CTkLabel(a, text="File pcap").grid(row=1, column=0, sticky="w", pady=6, padx=(0, 10))
        frow = ctk.CTkFrame(a, fg_color="transparent")
        frow.grid(row=1, column=1, sticky="ew")
        frow.grid_columnconfigure(0, weight=1)
        self.ent_file = ctk.CTkEntry(frow, placeholder_text="mặc định dùng file vừa tạo")
        self.ent_file.grid(row=0, column=0, sticky="ew")
        ctk.CTkButton(frow, text="📂 Chọn", width=80, command=self._browse).grid(row=0, column=1, padx=(6, 0))

        orow = ctk.CTkFrame(a, fg_color="transparent")
        orow.grid(row=2, column=1, sticky="w", pady=6)
        ctk.CTkLabel(orow, text="Giãn cách (s)").pack(side="left", padx=(0, 6))
        self.ent_inter = ctk.CTkEntry(orow, width=70)
        self.ent_inter.insert(0, "0.0")
        self.ent_inter.pack(side="left", padx=(0, 16))
        ctk.CTkLabel(orow, text="Lặp lại").pack(side="left", padx=(0, 6))
        self.ent_repeat = ctk.CTkEntry(orow, width=60)
        self.ent_repeat.insert(0, "1")
        self.ent_repeat.pack(side="left")

        brow = ctk.CTkFrame(a, fg_color="transparent")
        brow.grid(row=3, column=1, sticky="w", pady=(8, 0))
        self.btn_send = ctk.CTkButton(brow, text="🚀  Phát ra card mạng", width=180, height=36,
                                      fg_color=C_BLUE, hover_color=C_BLUE_H, command=self.on_send)
        self.btn_send.pack(side="left", padx=(0, 10))
        self.btn_stop = ctk.CTkButton(brow, text="⏹ Dừng", width=90, height=36,
                                      fg_color=C_RED, hover_color=C_RED_H, command=self._stop_send)
        self.btn_stop.pack(side="left")

        # ---- Tiến trình + Log -----------------------------------------
        self.progress = ctk.CTkProgressBar(self, height=10)
        self.progress.set(0)
        self.progress.pack(fill="x", padx=16, pady=(2, 8))

        logwrap = ctk.CTkFrame(self)
        logwrap.pack(fill="both", expand=True, padx=16, pady=(0, 14))
        lhead = ctk.CTkFrame(logwrap, fg_color="transparent")
        lhead.pack(fill="x", padx=12, pady=(8, 0))
        ctk.CTkLabel(lhead, text="Nhật ký", font=ctk.CTkFont(size=13, weight="bold")).pack(side="left")
        ctk.CTkButton(lhead, text="Xoá", width=56, height=26, fg_color="transparent",
                      border_width=1, command=self._clear_log).pack(side="right")
        self.log_box = ctk.CTkTextbox(logwrap, font=ctk.CTkFont(family="Consolas", size=12))
        self.log_box.pack(fill="both", expand=True, padx=12, pady=(4, 12))
        self._log("Sẵn sàng.  ① Tạo gói tin  →  ② Gửi tới Phần 1.")

    # ===================================================================== helpers
    def _on_type_change(self, choice):
        self.lbl_type_desc.configure(text=ATTACK_DESC.get(choice, ""))

    def _toggle_src(self):
        self.ent_src.configure(state="disabled" if self.chk_rand.get() else "normal")

    def _refresh_ifaces(self):
        ifaces = pt.list_interfaces() or ["(cần cài scapy)"]
        self.cbo_iface.configure(values=ifaces)
        self.cbo_iface.set(ifaces[0])

    def _browse(self):
        path = filedialog.askopenfilename(filetypes=[("PCAP", "*.pcap *.pcapng"), ("All", "*.*")])
        if path:
            self.ent_file.delete(0, "end")
            self.ent_file.insert(0, path)

    def _clear_log(self):
        self.log_box.delete("1.0", "end")

    def _log(self, msg):
        self.log_box.insert("end", msg + "\n")
        self.log_box.see("end")

    def _log_safe(self, msg):
        self.after(0, lambda: self._log(msg))

    # ===================================================================== actions
    def on_generate(self):
        label = self.cbo_type.get()
        if label not in self.templates:
            self._log("[!] Không có file mẫu. Kiểm tra thư mục templates/.")
            return
        opt = pt.MutateOptions(
            randomize_src=bool(self.chk_rand.get()),
            src_ip=None if self.chk_rand.get() else (self.ent_src.get().strip() or None),
            dst_ip=self.ent_dst.get().strip() or None,
            reset_time=bool(self.chk_time.get()),
            recompute_checksum=bool(self.chk_cks.get()),
        )
        try:
            out = pt.mutate_template(label, opt, log=self._log)
            self.last_generated = out
            self.ent_file.delete(0, "end")
            self.ent_file.insert(0, out)
            self.lbl_gen.configure(text=f"✓ {os.path.basename(out)}", text_color=C_GREEN)
        except Exception as exc:                 # noqa: BLE001
            self._log(f"[!] Lỗi tạo gói: {exc}")

    def on_send(self):
        if self._send_thread and self._send_thread.is_alive():
            self._log("[!] Đang gửi, vui lòng đợi hoặc bấm Dừng.")
            return
        path = self.ent_file.get().strip() or self.last_generated
        if not path or not os.path.exists(path):
            self._log("[!] Chưa có file pcap hợp lệ để gửi.")
            return
        iface_label = self.cbo_iface.get()
        iface = None if iface_label.startswith("(") else pt.resolve_iface(iface_label)
        try:
            inter = float(self.ent_inter.get() or 0)
            repeat = int(self.ent_repeat.get() or 1)
        except ValueError:
            self._log("[!] Giãn cách/Lặp lại phải là số.")
            return

        self._stop.clear()
        self.progress.set(0)

        def worker():
            try:
                pt.send_pcap(
                    path, iface=iface, inter=inter, repeat=repeat,
                    progress=lambda d, t: self.after(0, lambda: self.progress.set(d / t)),
                    log=self._log_safe,
                    stop_flag=self._stop.is_set,
                )
            except Exception as exc:             # noqa: BLE001
                self._log_safe(f"[!] Lỗi gửi: {exc}")
                self._log_safe("    Gợi ý: cần Scapy + quyền Admin (Npcap), chọn đúng card mạng.")
            finally:
                self.after(0, lambda: self.btn_send.configure(state="normal"))

        self.btn_send.configure(state="disabled")
        self._send_thread = threading.Thread(target=worker, daemon=True)
        self._send_thread.start()

    def on_send_to_part1(self):
        """Gửi thẳng file pcap sang Phần 1 qua TCP (localhost hoặc LAN)."""
        if self._send_thread and self._send_thread.is_alive():
            self._log("[!] Đang gửi, vui lòng đợi hoặc bấm Dừng.")
            return
        path = self.ent_file.get().strip() or self.last_generated
        if not path or not os.path.exists(path):
            self._log("[!] Chưa có file pcap. Hãy bấm '⚙ Tạo gói tin' trước.")
            return
        host = self.ent_part1_ip.get().strip() or "127.0.0.1"

        def worker():
            try:
                pt.stream_pcap_to_part1(
                    path, host=host,
                    progress=lambda d, t: self.after(0, lambda: self.progress.set(d / t)),
                    log=self._log_safe)
            except (ConnectionRefusedError, OSError):
                self._log_safe(f"[!] Không kết nối được Phần 1 tại {host}:{pt.PART1_PORT}. "
                               "Phần 1 đã bấm '🛰 Nhận từ Phần 2' chưa? Nếu 2 máy: đúng IP, "
                               "cùng mạng, và firewall máy P1 đã cho phép?")
            except Exception as exc:              # noqa: BLE001
                self._log_safe(f"[!] Lỗi gửi tới Phần 1: {exc}")
            finally:
                self.after(0, lambda: self.btn_part1.configure(state="normal"))

        self.progress.set(0)
        self.btn_part1.configure(state="disabled")
        self._send_thread = threading.Thread(target=worker, daemon=True)
        self._send_thread.start()

    def _stop_send(self):
        self._stop.set()


def main():
    if ctk is None:
        print("Cần customtkinter: pip install customtkinter")
        return 1
    ctk.set_appearance_mode("Dark")
    ctk.set_default_color_theme("blue")
    SenderApp().mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
