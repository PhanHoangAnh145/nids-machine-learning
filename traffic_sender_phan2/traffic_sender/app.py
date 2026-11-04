"""
GIAO DIỆN Phần 2 — Traffic Generator & Sender (CustomTkinter).

Chỉ chứa logic GIAO DIỆN; mọi xử lý pcap nằm ở pcap_tools.py. Việc gửi gói chạy
trên LUỒNG PHỤ (threading) để không làm đơ UI, tiến độ/log cập nhật qua self.after.

Chạy:
    python -m traffic_sender          (hoặc: python -m traffic_sender.app)

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


class SenderApp(ctk.CTk if ctk else object):
    def __init__(self):
        super().__init__()
        self.title("NIDS Lab - Traffic Generator & Sender (Phần 2)")
        self.geometry("820x760")
        self.last_generated: str | None = None
        self._send_thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._build()

    # ------------------------------------------------------------- UI build
    def _build(self):
        pad = {"padx": 12, "pady": 6}

        warn = ctk.CTkLabel(
            self, text="⚠️  Công cụ KIỂM THỬ trong phòng lab — chỉ phát gói tới máy/mạng của chính bạn.",
            text_color="#e0a030", font=ctk.CTkFont(size=12, weight="bold"))
        warn.pack(fill="x", padx=12, pady=(10, 0))

        # ---- Mục 1: Kho mẫu + Mục 2: Sinh gói --------------------------
        gen = ctk.CTkFrame(self)
        gen.pack(fill="x", **pad)
        ctk.CTkLabel(gen, text="① Kho mẫu & Sinh gói tin",
                     font=ctk.CTkFont(size=15, weight="bold")).grid(row=0, column=0, columnspan=4, sticky="w", padx=10, pady=(8, 4))

        ctk.CTkLabel(gen, text="Loại tấn công:").grid(row=1, column=0, sticky="w", padx=10, pady=6)
        self.templates = pt.list_templates()
        labels = list(self.templates.keys()) or ["(không thấy file mẫu trong templates/)"]
        self.cbo_type = ctk.CTkOptionMenu(gen, values=labels, width=260)
        self.cbo_type.grid(row=1, column=1, sticky="w", padx=10, pady=6)

        ctk.CTkLabel(gen, text="IP nguồn:").grid(row=2, column=0, sticky="w", padx=10, pady=6)
        self.chk_rand = ctk.CTkCheckBox(gen, text="Ngẫu nhiên", command=self._toggle_src)
        self.chk_rand.select()
        self.chk_rand.grid(row=2, column=1, sticky="w", padx=10, pady=6)
        self.ent_src = ctk.CTkEntry(gen, placeholder_text="vd 10.0.0.9", width=180, state="disabled")
        self.ent_src.grid(row=2, column=2, sticky="w", padx=10, pady=6)

        ctk.CTkLabel(gen, text="IP đích (máy chạy Phần 1):").grid(row=3, column=0, sticky="w", padx=10, pady=6)
        self.ent_dst = ctk.CTkEntry(gen, placeholder_text="vd 192.168.1.50", width=180)
        self.ent_dst.grid(row=3, column=1, sticky="w", padx=10, pady=6)
        self.chk_time = ctk.CTkCheckBox(gen, text="Làm mới timestamp")
        self.chk_time.select()
        self.chk_time.grid(row=3, column=2, sticky="w", padx=10, pady=6)
        self.chk_cks = ctk.CTkCheckBox(gen, text="Tính lại checksum")
        self.chk_cks.select()
        self.chk_cks.grid(row=3, column=3, sticky="w", padx=10, pady=6)

        self.btn_gen = ctk.CTkButton(gen, text="⚙️  Sinh gói tin", command=self.on_generate)
        self.btn_gen.grid(row=4, column=0, columnspan=2, sticky="w", padx=10, pady=(6, 12))
        self.lbl_gen = ctk.CTkLabel(gen, text="Chưa sinh file nào.", text_color="#8ab4f8")
        self.lbl_gen.grid(row=4, column=2, columnspan=2, sticky="w", padx=10)

        # ---- Mục 3: Gửi gói --------------------------------------------
        snd = ctk.CTkFrame(self)
        snd.pack(fill="x", **pad)
        ctk.CTkLabel(snd, text="② Gửi gói tin ra card mạng",
                     font=ctk.CTkFont(size=15, weight="bold")).grid(row=0, column=0, columnspan=4, sticky="w", padx=10, pady=(8, 4))

        ctk.CTkLabel(snd, text="Card mạng:").grid(row=1, column=0, sticky="w", padx=10, pady=6)
        ifaces = pt.list_interfaces() or ["(cần Scapy để liệt kê)"]
        self.cbo_iface = ctk.CTkOptionMenu(snd, values=ifaces, width=220)
        self.cbo_iface.grid(row=1, column=1, sticky="w", padx=10, pady=6)
        ctk.CTkButton(snd, text="🔄", width=36, command=self._refresh_ifaces).grid(row=1, column=2, sticky="w")

        ctk.CTkLabel(snd, text="File pcap:").grid(row=2, column=0, sticky="w", padx=10, pady=6)
        self.ent_file = ctk.CTkEntry(snd, placeholder_text="dùng file vừa sinh, hoặc Chọn...", width=380)
        self.ent_file.grid(row=2, column=1, columnspan=2, sticky="w", padx=10, pady=6)
        ctk.CTkButton(snd, text="📂 Chọn...", width=90, command=self._browse).grid(row=2, column=3, sticky="w", padx=6)

        ctk.CTkLabel(snd, text="Giãn cách (giây):").grid(row=3, column=0, sticky="w", padx=10, pady=6)
        self.ent_inter = ctk.CTkEntry(snd, width=80)
        self.ent_inter.insert(0, "0.0")
        self.ent_inter.grid(row=3, column=1, sticky="w", padx=10, pady=6)
        ctk.CTkLabel(snd, text="Lặp lại:").grid(row=3, column=2, sticky="e", padx=4)
        self.ent_repeat = ctk.CTkEntry(snd, width=60)
        self.ent_repeat.insert(0, "1")
        self.ent_repeat.grid(row=3, column=3, sticky="w", padx=6)

        # IP của máy chạy Phần 1 (cho nút "Gửi sang Phần 1")
        ctk.CTkLabel(snd, text="IP Phần 1:").grid(row=4, column=0, sticky="w", padx=10, pady=6)
        self.ent_part1_ip = ctk.CTkEntry(snd, width=200)
        self.ent_part1_ip.insert(0, "127.0.0.1")
        self.ent_part1_ip.grid(row=4, column=1, sticky="w", padx=10, pady=6)
        ctk.CTkLabel(snd, text="(127.0.0.1 nếu cùng máy; IP máy kia nếu 2 máy)",
                     text_color="gray").grid(row=4, column=2, columnspan=2, sticky="w", padx=6)

        self.btn_send = ctk.CTkButton(snd, text="🚀  Gửi ra card mạng", command=self.on_send)
        self.btn_send.grid(row=5, column=0, sticky="w", padx=10, pady=(6, 10))
        self.btn_part1 = ctk.CTkButton(
            snd, text="🛰  Gửi sang Phần 1", fg_color="#6a3", hover_color="#582",
            command=self.on_send_to_part1)
        self.btn_part1.grid(row=5, column=1, sticky="w", padx=10, pady=(6, 10))
        self.btn_stop = ctk.CTkButton(snd, text="⏹ Dừng", fg_color="#a33", command=self._stop_send)
        self.btn_stop.grid(row=5, column=2, sticky="w", pady=(6, 10))

        self.progress = ctk.CTkProgressBar(snd)
        self.progress.set(0)
        self.progress.grid(row=6, column=0, columnspan=4, sticky="ew", padx=10, pady=(0, 10))

        # ---- Log --------------------------------------------------------
        self.log_box = ctk.CTkTextbox(self, font=ctk.CTkFont(family="Consolas", size=12))
        self.log_box.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        self._log("Sẵn sàng. Chọn loại tấn công -> Sinh gói tin -> Gửi gói tin.")

    # ------------------------------------------------------------- helpers
    def _toggle_src(self):
        self.ent_src.configure(state="disabled" if self.chk_rand.get() else "normal")

    def _refresh_ifaces(self):
        ifaces = pt.list_interfaces() or ["(cần Scapy)"]
        self.cbo_iface.configure(values=ifaces)
        if ifaces:
            self.cbo_iface.set(ifaces[0])

    def _browse(self):
        path = filedialog.askopenfilename(filetypes=[("PCAP", "*.pcap *.pcapng"), ("All", "*.*")])
        if path:
            self.ent_file.delete(0, "end")
            self.ent_file.insert(0, path)

    def _log(self, msg):
        self.log_box.insert("end", msg + "\n")
        self.log_box.see("end")

    def _log_safe(self, msg):
        self.after(0, lambda: self._log(msg))

    # ------------------------------------------------------------- actions
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
            self.lbl_gen.configure(text=f"✓ {os.path.basename(out)}")
        except Exception as exc:                 # noqa: BLE001
            self._log(f"[!] Lỗi sinh gói: {exc}")

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
                self._log_safe("    Gợi ý: cần Scapy + quyền quản trị (Npcap/root), chọn đúng card mạng.")
            finally:
                self.after(0, lambda: self.btn_send.configure(state="normal"))

        self.btn_send.configure(state="disabled")
        self._send_thread = threading.Thread(target=worker, daemon=True)
        self._send_thread.start()

    def on_send_to_part1(self):
        """Gửi thẳng file pcap sang Phần 1 qua localhost (Phần 1 phải đang lắng nghe)."""
        if self._send_thread and self._send_thread.is_alive():
            self._log("[!] Đang gửi, vui lòng đợi hoặc bấm Dừng.")
            return
        path = self.ent_file.get().strip() or self.last_generated
        if not path or not os.path.exists(path):
            self._log("[!] Chưa có file pcap. Hãy bấm 'Sinh gói tin' trước.")
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
                               "Kiểm tra: Phần 1 đã bấm '🛰 Nghe từ Phần 2' chưa? "
                               "Nếu 2 máy: đúng IP máy P1 và cùng mạng chưa? Tường lửa có chặn không?")
            except Exception as exc:              # noqa: BLE001
                self._log_safe(f"[!] Lỗi gửi sang Phần 1: {exc}")
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
    SenderApp().mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
