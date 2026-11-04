"""
Ung dung Giao dien Do hoa (GUI) He thong Phat hien Xam nhap Mang (NIDS)
Su dung Machine Learning (Random Forest) tren tap du lieu NSL-KDD.
Sinh vien thuc hien: Phan Hoang Anh
"""
import os
import sys
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import customtkinter as ctk
from PIL import Image, ImageTk
import pandas as pd
import numpy as np

# Cau hinh encoding UTF-8 tren Windows
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except Exception:
        pass

# Them thu muc src vao sys.path de import
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
SRC_DIR = os.path.join(CURRENT_DIR, "src")
MODELS_DIR = os.path.join(CURRENT_DIR, "models")
DATA_DIR = os.path.join(CURRENT_DIR, "data")
sys.path.append(SRC_DIR)

from predictor import NIDSPredictor
from crypto_logger import SecureAlertLogger
from preprocess import FEATURE_NAMES, CLASS_DISPLAY_NAMES, CLASS_LABELS

# Module giám sát thời gian thực (độc lập, đặt ở thư mục realtime/). Nhập có bảo
# vệ: nếu thiếu, ứng dụng vẫn chạy bình thường, chỉ tab Realtime báo hướng dẫn.
try:
    from realtime.engine import RealtimeEngine
    from realtime.config import RealtimeConfig
    REALTIME_OK = True
    REALTIME_ERR = ""
except Exception as _e:  # noqa: BLE001
    REALTIME_OK = False
    REALTIME_ERR = str(_e)

# Cau hinh giao dien CustomTkinter
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")


class NIDSApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("NIDS SHIELD - Hệ Thống Phát Hiện Xâm Nhập Mạng (AI / Machine Learning)")
        self.geometry("1180x760")
        self.minsize(1050, 680)

        # Khoi tao bo du doan NIDS
        self.predictor = None
        self.init_predictor()

        # Khoi tao module ma hoa nhat ky AES-256-GCM
        self.crypto_logger = SecureAlertLogger()

        # Dữ liệu lưu trữ tạm cho quét file CSV
        self.batch_df = None
        self.batch_result_df = None

        # Thiết lập giao diện tổng thể (Sidebar + Content Area)
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)

        self.create_sidebar()
        self.create_content_frames()

        # Mặc định mở tab đầu tiên
        self.select_tab("single")

    def init_predictor(self):
        try:
            self.predictor = NIDSPredictor()
        except Exception as e:
            messagebox.showerror(
                "Lỗi Khởi Tạo Mô Hình",
                f"Không thể tải mô hình Machine Learning:\n{e}\n\nVui lòng chạy lại file 'src/train.py' trước!"
            )

    # =========================================================================
    # SIDEBAR NAVIGATION
    # =========================================================================
    def create_sidebar(self):
        self.sidebar_frame = ctk.CTkFrame(self, width=230, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(7, weight=1)

        # Logo / Tiêu đề ứng dụng
        self.logo_label = ctk.CTkLabel(
            self.sidebar_frame,
            text="🛡️ NIDS SHIELD",
            font=ctk.CTkFont(size=20, weight="bold")
        )
        self.logo_label.grid(row=0, column=0, padx=20, pady=(25, 5))

        self.sub_logo = ctk.CTkLabel(
            self.sidebar_frame,
            text="Phát Hiện Xâm Nhập AI",
            font=ctk.CTkFont(size=12),
            text_color="gray"
        )
        self.sub_logo.grid(row=1, column=0, padx=20, pady=(0, 25))

        # Các nút chuyển trang
        self.btn_single = ctk.CTkButton(
            self.sidebar_frame,
            text="🔍  Quét Gói Tin Đơn",
            height=40,
            anchor="w",
            font=ctk.CTkFont(size=14, weight="bold"),
            command=lambda: self.select_tab("single")
        )
        self.btn_single.grid(row=2, column=0, padx=15, pady=8, sticky="ew")

        self.btn_batch = ctk.CTkButton(
            self.sidebar_frame,
            text="📁  Quét File CSV",
            height=40,
            anchor="w",
            font=ctk.CTkFont(size=14, weight="bold"),
            command=lambda: self.select_tab("batch")
        )
        self.btn_batch.grid(row=3, column=0, padx=15, pady=8, sticky="ew")

        self.btn_charts = ctk.CTkButton(
            self.sidebar_frame,
            text="📊  Biểu Đồ & Thống Kê",
            height=40,
            anchor="w",
            font=ctk.CTkFont(size=14, weight="bold"),
            command=lambda: self.select_tab("charts")
        )
        self.btn_charts.grid(row=4, column=0, padx=15, pady=8, sticky="ew")

        self.btn_about = ctk.CTkButton(
            self.sidebar_frame,
            text="ℹ️  Giới Thiệu Đồ Án",
            height=40,
            anchor="w",
            font=ctk.CTkFont(size=14, weight="bold"),
            command=lambda: self.select_tab("about")
        )
        self.btn_about.grid(row=5, column=0, padx=15, pady=8, sticky="ew")

        # Nút tab GIÁM SÁT THỜI GIAN THỰC (bổ sung)
        self.btn_realtime = ctk.CTkButton(
            self.sidebar_frame,
            text="📡  Giám Sát Realtime",
            height=40,
            anchor="w",
            font=ctk.CTkFont(size=14, weight="bold"),
            command=lambda: self.select_tab("realtime")
        )
        self.btn_realtime.grid(row=6, column=0, padx=15, pady=8, sticky="ew")

        # Cài đặt giao diện Dark/Light ở chân sidebar
        self.theme_label = ctk.CTkLabel(self.sidebar_frame, text="Chế độ hiển thị:", anchor="w")
        self.theme_label.grid(row=8, column=0, padx=20, pady=(10, 0), sticky="w")
        self.theme_menu = ctk.CTkOptionMenu(
            self.sidebar_frame,
            values=["Dark", "Light", "System"],
            command=ctk.set_appearance_mode
        )
        self.theme_menu.grid(row=9, column=0, padx=20, pady=(5, 20), sticky="ew")

    # =========================================================================
    # QUẢN LÝ CHUYỂN TAB
    # =========================================================================
    def create_content_frames(self):
        # 1. Frame Quét gói tin đơn
        self.frame_single = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")
        self.setup_single_frame()

        # 2. Frame Quét file CSV hàng loạt
        self.frame_batch = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")
        self.setup_batch_frame()

        # 3. Frame Biểu đồ & Đánh giá
        self.frame_charts = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")
        self.setup_charts_frame()

        # 4. Frame Giới thiệu
        self.frame_about = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")
        self.setup_about_frame()

        # 5. Frame Giám sát thời gian thực (bổ sung)
        self.frame_realtime = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")
        self.setup_realtime_frame()

    def select_tab(self, tab_name):
        # Reset màu nút sidebar
        default_fg = ["#3B8ED0", "#1F6AA5"]
        inactive_fg = "transparent"

        self.btn_single.configure(fg_color=default_fg if tab_name == "single" else inactive_fg)
        self.btn_batch.configure(fg_color=default_fg if tab_name == "batch" else inactive_fg)
        self.btn_charts.configure(fg_color=default_fg if tab_name == "charts" else inactive_fg)
        self.btn_about.configure(fg_color=default_fg if tab_name == "about" else inactive_fg)
        self.btn_realtime.configure(fg_color=default_fg if tab_name == "realtime" else inactive_fg)

        # Ẩn tất cả frame
        self.frame_single.grid_forget()
        self.frame_batch.grid_forget()
        self.frame_charts.grid_forget()
        self.frame_about.grid_forget()
        self.frame_realtime.grid_forget()

        # Hiển thị frame được chọn
        if tab_name == "single":
            self.frame_single.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)
        elif tab_name == "batch":
            self.frame_batch.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)
        elif tab_name == "charts":
            self.frame_charts.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)
        elif tab_name == "about":
            self.frame_about.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)
        elif tab_name == "realtime":
            self.frame_realtime.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)

    # =========================================================================
    # TAB 1: QUÉT GÓI TIN ĐƠN LẺ (SINGLE SCANNER)
    # =========================================================================
    def setup_single_frame(self):
        self.frame_single.grid_columnconfigure(0, weight=3)
        self.frame_single.grid_columnconfigure(1, weight=2)
        self.frame_single.grid_rowconfigure(1, weight=1)

        # Header tab
        header = ctk.CTkLabel(
            self.frame_single,
            text="🔍 Phân Tích & Giám Sát Gói Tin Lưu Lượng Mạng",
            font=ctk.CTkFont(size=20, weight="bold")
        )
        header.grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 15))

        # Cột trái: Form nhập liệu & Lấy mẫu test
        left_box = ctk.CTkFrame(self.frame_single)
        left_box.grid(row=1, column=0, sticky="nsew", padx=(0, 10))
        left_box.grid_columnconfigure((0, 1), weight=1)

        # Thanh điều khiển lấy mẫu test ngẫu nhiên
        test_bar = ctk.CTkFrame(left_box, fg_color=("gray85", "gray20"))
        test_bar.grid(row=0, column=0, columnspan=2, sticky="ew", padx=15, pady=15)
        test_bar.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(test_bar, text="Kiểm thử nhanh:", font=ctk.CTkFont(weight="bold")).grid(
            row=0, column=0, padx=10, pady=10, sticky="w"
        )
        self.sample_filter_menu = ctk.CTkOptionMenu(
            test_bar,
            values=["Tất cả loại", "dos", "probe", "r2l", "u2r", "normal"],
            width=130
        )
        self.sample_filter_menu.grid(row=0, column=1, padx=5, pady=10, sticky="w")

        btn_random = ctk.CTkButton(
            test_bar,
            text="🎲 Lấy Mẫu Ngẫu Nhiên",
            command=self.load_random_sample,
            width=160
        )
        btn_random.grid(row=0, column=2, padx=10, pady=10, sticky="e")

        # Các trường thông số mạng tiêu biểu
        fields_container = ctk.CTkScrollableFrame(left_box, label_text="Thông số gói tin kết nối")
        fields_container.grid(row=1, column=0, columnspan=2, sticky="nsew", padx=15, pady=(0, 15))
        left_box.grid_rowconfigure(1, weight=1)
        fields_container.grid_columnconfigure((0, 1), weight=1)

        self.form_entries = {}
        self.current_sample_dict = {}

        fields_meta = [
            ("protocol_type", "Giao thức mạng (protocol_type):", ["tcp", "udp", "icmp"], "tcp"),
            ("service", "Dịch vụ mạng (service):", ["http", "private", "smtp", "ftp_data", "eco_i", "other", "telnet", "finger"], "http"),
            ("flag", "Cờ trạng thái kết nối (flag):", ["SF", "S0", "REJ", "RSTR", "SH", "RSTO"], "SF"),
            ("duration", "Thời lượng kết nối (giây):", None, "0"),
            ("src_bytes", "Số Byte gửi đi (src_bytes):", None, "215"),
            ("dst_bytes", "Số Byte nhận về (dst_bytes):", None, "45076"),
            ("count", "Số kết nối đến cùng Host (count):", None, "1"),
            ("srv_count", "Số kết nối cùng dịch vụ (srv_count):", None, "1"),
            ("serror_rate", "Tỷ lệ lỗi SYN (serror_rate 0.0 - 1.0):", None, "0.0"),
            ("dst_host_count", "Số kết nối đích (dst_host_count):", None, "255"),
            ("dst_host_srv_count", "Số kết nối dịch vụ đích:", None, "255"),
            ("dst_host_same_srv_rate", "Tỷ lệ cùng dịch vụ đích:", None, "1.0"),
            ("dst_host_diff_srv_rate", "Tỷ lệ khác dịch vụ đích:", None, "0.0")
        ]

        for i, (key, label_text, options, default_val) in enumerate(fields_meta):
            ctk.CTkLabel(fields_container, text=label_text, anchor="w").grid(
                row=i, column=0, padx=10, pady=6, sticky="w"
            )
            if options:
                menu = ctk.CTkOptionMenu(fields_container, values=options)
                menu.set(default_val)
                menu.grid(row=i, column=1, padx=10, pady=6, sticky="ew")
                self.form_entries[key] = menu
            else:
                entry = ctk.CTkEntry(fields_container)
                entry.insert(0, default_val)
                entry.grid(row=i, column=1, padx=10, pady=6, sticky="ew")
                self.form_entries[key] = entry

        # Nút Quét Lớn
        btn_scan = ctk.CTkButton(
            left_box,
            text="⚡ PHÂN TÍCH & QUÉT GÓI TIN",
            font=ctk.CTkFont(size=15, weight="bold"),
            height=46,
            fg_color="#1f77b4",
            hover_color="#155d8f",
            command=self.run_single_prediction
        )
        btn_scan.grid(row=2, column=0, columnspan=2, padx=15, pady=15, sticky="ew")

        # Cột phải: Hộp kết quả phân tích
        right_box = ctk.CTkFrame(self.frame_single)
        right_box.grid(row=1, column=1, sticky="nsew", padx=(10, 0))
        right_box.grid_rowconfigure(4, weight=1)

        ctk.CTkLabel(
            right_box,
            text="KẾT QUẢ ĐÁNH GIÁ AN NINH",
            font=ctk.CTkFont(size=16, weight="bold")
        ).pack(padx=15, pady=(20, 10))

        # Thẻ trạng thái lớn
        self.status_card = ctk.CTkFrame(right_box, height=110, fg_color="gray25", corner_radius=12)
        self.status_card.pack(fill="x", padx=15, pady=10)
        self.status_card.pack_propagate(False)

        self.lbl_status_icon = ctk.CTkLabel(
            self.status_card, text="🛡️", font=ctk.CTkFont(size=36)
        )
        self.lbl_status_icon.pack(side="left", padx=20)

        self.lbl_status_text = ctk.CTkLabel(
            self.status_card,
            text="SẴN SÀNG\nChưa quét gói tin nào",
            font=ctk.CTkFont(size=16, weight="bold"),
            justify="left"
        )
        self.lbl_status_text.pack(side="left", padx=10)

        # Thanh tiến trình độ tin cậy
        ctk.CTkLabel(right_box, text="Độ tin cậy của mô hình (Confidence):", anchor="w").pack(
            fill="x", padx=15, pady=(15, 2)
        )
        self.confidence_bar = ctk.CTkProgressBar(right_box, height=14)
        self.confidence_bar.pack(fill="x", padx=15, pady=(0, 5))
        self.confidence_bar.set(0)

        self.lbl_confidence_val = ctk.CTkLabel(
            right_box, text="0.0%", font=ctk.CTkFont(size=14, weight="bold")
        )
        self.lbl_confidence_val.pack(anchor="e", padx=15)

        # Chi tiết phân bố xác suất của 5 lớp
        ctk.CTkLabel(right_box, text="Xác suất theo từng phân loại:", font=ctk.CTkFont(weight="bold"), anchor="w").pack(
            fill="x", padx=15, pady=(15, 5)
        )
        self.prob_frame = ctk.CTkFrame(right_box, fg_color="transparent")
        self.prob_frame.pack(fill="x", padx=15, pady=5)

        self.prob_labels = {}
        for cat in CLASS_LABELS:
            row = ctk.CTkFrame(self.prob_frame, fg_color="transparent")
            row.pack(fill="x", pady=2)
            lbl_name = ctk.CTkLabel(row, text=f"• {CLASS_DISPLAY_NAMES.get(cat, cat)}:", width=180, anchor="w")
            lbl_name.pack(side="left")
            lbl_val = ctk.CTkLabel(row, text="0.0%", font=ctk.CTkFont(weight="bold"))
            lbl_val.pack(side="right")
            self.prob_labels[cat] = lbl_val

        # Khung kiểm tra đối chiếu nhãn thực tế
        self.actual_frame = ctk.CTkFrame(right_box, fg_color=("gray80", "gray18"), corner_radius=8)
        self.actual_frame.pack(fill="x", padx=15, pady=20)

        self.lbl_actual_info = ctk.CTkLabel(
            self.actual_frame,
            text="Đối chiếu dữ liệu gốc:\nChưa có mẫu đối chiếu",
            justify="center",
            font=ctk.CTkFont(size=12)
        )
        self.lbl_actual_info.pack(padx=10, pady=10)

    def load_random_sample(self):
        if not self.predictor:
            return
        cat_filter = self.sample_filter_menu.get()
        if cat_filter == "Tất cả loại":
            cat_filter = None

        try:
            sample = self.predictor.get_random_sample(category_filter=cat_filter)
            self.current_sample_dict = sample

            # Điền giá trị vào form
            for key, widget in self.form_entries.items():
                if key in sample:
                    val = str(sample[key])
                    if isinstance(widget, ctk.CTkOptionMenu):
                        widget.set(val)
                    elif isinstance(widget, ctk.CTkEntry):
                        widget.delete(0, tk.END)
                        widget.insert(0, val)

            # Cập nhật thông tin thực tế và đặt trạng thái chờ quét
            act_cat = sample.get('_actual_category', 'N/A')
            act_lbl = sample.get('_actual_label', 'N/A')
            
            # Reset lại kết quả bên phải về trạng thái chờ
            self.status_card.configure(fg_color="gray25")
            self.lbl_status_icon.configure(text="⏳")
            self.lbl_status_text.configure(
                text="ĐÃ NẠP MẪU KIỂM THỬ\nNhấn nút bên dưới để quét",
                text_color="white"
            )
            self.confidence_bar.set(0)
            self.lbl_confidence_val.configure(text="0.0%")
            for cat, lbl in self.prob_labels.items():
                lbl.configure(text="0.0%")
                
            self.lbl_actual_info.configure(
                text=f"📌 Dữ liệu gốc trong tập Test:\n• Tên tấn công: {act_lbl}\n• Nhóm thực tế: {CLASS_DISPLAY_NAMES.get(act_cat, act_cat)}\n\n👉 Hãy nhấn nút [⚡ PHÂN TÍCH & QUÉT GÓI TIN] bên dưới!"
            )
        except Exception as e:
            messagebox.showerror("Lỗi", f"Không thể lấy mẫu test: {e}")

    def run_single_prediction(self):
        if not self.predictor:
            messagebox.showwarning("Cảnh báo", "Mô hình NIDS chưa sẵn sàng.")
            return

        # Gom dữ liệu từ các ô nhập
        input_data = self.current_sample_dict.copy()
        for key, widget in self.form_entries.items():
            val = widget.get()
            try:
                if '.' in val:
                    val = float(val)
                elif val.isdigit():
                    val = int(val)
            except ValueError:
                pass
            input_data[key] = val

        try:
            result = self.predictor.predict_single(input_data)
            
            # Ma hoa nhat ky khi AI phat hien tan cong
            if result["is_attack"]:
                try:
                    self.crypto_logger.append_alert({
                        "event": "single_scan",
                        "category": result["category"],
                        "confidence": float(result["confidence"]),
                        "protocol": str(input_data.get("protocol_type", "")),
                        "service": str(input_data.get("service", "")),
                        "flag": str(input_data.get("flag", ""))
                    })

                    print("[CRYPTO] Da ma hoa va luu canh bao!")

                except Exception as crypto_error:
                    messagebox.showwarning(
                        "Loi ma hoa",
                        f"Khong the luu nhat ky: {crypto_error}"
                    )


            # Cập nhật Card Trạng thái
            if result['is_attack']:
                # Màu đỏ cảnh báo
                self.status_card.configure(fg_color="#8b1e1e")
                self.lbl_status_icon.configure(text="🚨")
                self.lbl_status_text.configure(
                    text=f"PHÁT HIỆN TẤN CÔNG!\nLoại: {result['display_name']}\nMức độ: Nguy Hiểm",
                    text_color="white"
                )
            else:
                # Màu xanh lá an toàn
                self.status_card.configure(fg_color="#1e7336")
                self.lbl_status_icon.configure(text="✅")
                self.lbl_status_text.configure(
                    text="GÓI TIN AN TOÀN\nLưu lượng mạng bình thường",
                    text_color="white"
                )

            # Độ tin cậy
            conf = result['confidence']
            self.confidence_bar.set(conf)
            self.lbl_confidence_val.configure(text=f"{conf * 100:.1f}%")

            # Xác suất 5 lớp
            probs = result['probabilities']
            for cat, lbl in self.prob_labels.items():
                p = probs.get(cat, 0.0)
                lbl.configure(text=f"{p * 100:.1f}%")

            # Đánh giá đúng/sai nếu có nhãn gốc (format sạch sẽ, không cộng dồn text cũ)
            if '_actual_category' in self.current_sample_dict:
                act = self.current_sample_dict['_actual_category']
                act_lbl = self.current_sample_dict.get('_actual_label', 'N/A')
                is_correct = (act == result['category'])
                status_icon = "🎯 CHÍNH XÁC (Đoán trúng)" if is_correct else "⚠️ CẢNH BÁO LỆCH (Đoán sai)"
                self.lbl_actual_info.configure(
                    text=f"📌 Dữ liệu gốc trong tập Test:\n• Tên tấn công cụ thể: {act_lbl}\n• Nhóm thực tế: {CLASS_DISPLAY_NAMES.get(act, act)}\n\n{status_icon}\n(AI dự đoán: {result['display_name']})"
                )

        except Exception as e:
            messagebox.showerror("Lỗi Phân Tích", f"Đã xảy ra lỗi khi quét: {e}")

    # =========================================================================
    # TAB 2: QUÉT HÀNG LOẠT TỪ FILE CSV (BATCH SCANNER)
    # =========================================================================
    def setup_batch_frame(self):
        self.frame_batch.grid_columnconfigure(0, weight=1)
        self.frame_batch.grid_rowconfigure(3, weight=1)

        # Tiêu đề
        ctk.CTkLabel(
            self.frame_batch,
            text="📁 Quét & Phân Tích Lưu Lượng Mạng Hàng Loạt (Batch Scan)",
            font=ctk.CTkFont(size=20, weight="bold")
        ).grid(row=0, column=0, sticky="w", pady=(0, 15))

        # Thanh chọn File
        file_bar = ctk.CTkFrame(self.frame_batch)
        file_bar.grid(row=1, column=0, sticky="ew", pady=(0, 15))
        file_bar.grid_columnconfigure(0, weight=1)

        self.txt_file_path = ctk.CTkEntry(
            file_bar,
            placeholder_text="Chọn file CSV chứa lưu lượng mạng để quét...",
            height=38
        )
        self.txt_file_path.grid(row=0, column=0, padx=(15, 10), pady=12, sticky="ew")

        btn_browse = ctk.CTkButton(
            file_bar, text="📂 Chọn File...", width=120, height=38, command=self.browse_csv_file
        )
        btn_browse.grid(row=0, column=1, padx=(0, 10), pady=12)

        btn_sample = ctk.CTkButton(
            file_bar,
            text="📄 File Mẫu (200 Mẫu)",
            width=150,
            height=38,
            fg_color="#2b5b84",
            hover_color="#1e4160",
            command=self.load_sample_csv
        )
        btn_sample.grid(row=0, column=2, padx=(0, 10), pady=12)

        self.btn_run_batch = ctk.CTkButton(
            file_bar,
            text="🚀 BẮT ĐẦU QUÉT",
            font=ctk.CTkFont(weight="bold"),
            width=140,
            height=38,
            fg_color="#2ca02c",
            hover_color="#227d22",
            command=self.start_batch_scan_thread
        )
        self.btn_run_batch.grid(row=0, column=3, padx=(0, 15), pady=12)

        # Thẻ Thống kê nhanh sau khi quét
        self.batch_stats_frame = ctk.CTkFrame(self.frame_batch)
        self.batch_stats_frame.grid(row=2, column=0, sticky="ew", pady=(0, 15))
        self.batch_stats_frame.grid_columnconfigure((0, 1, 2, 3), weight=1)

        self.card_total = self.create_mini_stat_card(self.batch_stats_frame, 0, "Tổng Gói Tin", "0", "gray")
        self.card_normal = self.create_mini_stat_card(self.batch_stats_frame, 1, "An Toàn (Normal)", "0", "#2ca02c")
        self.card_attack = self.create_mini_stat_card(self.batch_stats_frame, 2, "Bị Tấn Công", "0", "#d62728")
        self.card_rate = self.create_mini_stat_card(self.batch_stats_frame, 3, "Tỷ Lệ Tấn Công", "0.0%", "#ff7f0e")

        # Bảng hiển thị kết quả (Treeview)
        table_container = ctk.CTkFrame(self.frame_batch)
        table_container.grid(row=3, column=0, sticky="nsew")
        table_container.grid_rowconfigure(0, weight=1)
        table_container.grid_columnconfigure(0, weight=1)

        columns = ("id", "protocol", "service", "flag", "prediction", "confidence", "status")
        self.tree = ttk.Treeview(table_container, columns=columns, show="headings", selectmode="browse")

        self.tree.heading("id", text="# STT")
        self.tree.heading("protocol", text="Giao thức")
        self.tree.heading("service", text="Dịch vụ")
        self.tree.heading("flag", text="Cờ (Flag)")
        self.tree.heading("prediction", text="Dự đoán nhóm")
        self.tree.heading("confidence", text="Độ tin cậy")
        self.tree.heading("status", text="Cảnh báo an ninh")

        self.tree.column("id", width=60, anchor="center")
        self.tree.column("protocol", width=90, anchor="center")
        self.tree.column("service", width=110, anchor="center")
        self.tree.column("flag", width=90, anchor="center")
        self.tree.column("prediction", width=180, anchor="w")
        self.tree.column("confidence", width=100, anchor="center")
        self.tree.column("status", width=150, anchor="center")

        # Style cho Treeview phù hợp Dark Mode
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview", rowheight=26, font=("Segoe UI", 10))
        style.configure("Treeview.Heading", font=("Segoe UI", 10, "bold"))

        # Scrollbar
        scroll_y = ttk.Scrollbar(table_container, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll_y.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        scroll_y.grid(row=0, column=1, sticky="ns")

        # Tag màu dòng
        self.tree.tag_configure("attack", background="#ffcccc", foreground="#990000")
        self.tree.tag_configure("normal", background="#e6ffe6", foreground="#006600")

        # Thanh tiến trình & Nút xuất báo cáo
        bottom_bar = ctk.CTkFrame(self.frame_batch, fg_color="transparent")
        bottom_bar.grid(row=4, column=0, sticky="ew", pady=(10, 0))
        bottom_bar.grid_columnconfigure(0, weight=1)

        self.batch_progress = ctk.CTkProgressBar(bottom_bar, height=12)
        self.batch_progress.grid(row=0, column=0, sticky="ew", padx=(0, 15))
        self.batch_progress.set(0)

        self.btn_export = ctk.CTkButton(
            bottom_bar,
            text="💾 Xuất Kết Quả CSV",
            width=160,
            command=self.export_batch_results,
            state="disabled"
        )
        self.btn_export.grid(row=0, column=1, sticky="e")

    def create_mini_stat_card(self, parent, col, title, initial_val, color):
        card = ctk.CTkFrame(parent, fg_color=("gray85", "gray20"))
        card.grid(row=0, column=col, padx=8, pady=10, sticky="nsew")
        ctk.CTkLabel(card, text=title, font=ctk.CTkFont(size=12)).pack(pady=(8, 2))
        lbl_val = ctk.CTkLabel(card, text=initial_val, font=ctk.CTkFont(size=18, weight="bold"), text_color=color)
        lbl_val.pack(pady=(0, 8))
        return lbl_val

    # =========================================================================
    # TAB 5: GIÁM SÁT THỜI GIAN THỰC (REALTIME) — bổ sung, dùng module realtime/
    # =========================================================================
    def setup_realtime_frame(self):
        self.rt_engine = None
        self.rt_thread = None
        self.rt_stop = threading.Event()
        self.rt_iface_map = {}
        self.rt_counts = {"pkt": 0, "conn": 0, "attack": 0}

        self.frame_realtime.grid_columnconfigure(0, weight=1)
        self.frame_realtime.grid_rowconfigure(3, weight=1)

        ctk.CTkLabel(
            self.frame_realtime,
            text="📡 Giám Sát & Bắt Gói Tin Thời Gian Thực",
            font=ctk.CTkFont(size=20, weight="bold")
        ).grid(row=0, column=0, sticky="w", pady=(0, 15))

        # Nếu thiếu module realtime -> hiện hướng dẫn, dừng tại đây
        if not REALTIME_OK:
            ctk.CTkLabel(
                self.frame_realtime,
                text=("Chưa dùng được module realtime.\n\n"
                      f"Chi tiết: {REALTIME_ERR}\n\n"
                      "Hãy chắc chắn thư mục 'realtime/' nằm cùng cấp với main.py "
                      "và đã cài: pip install scapy scikit-learn pandas joblib"),
                justify="left", text_color="#e0a030"
            ).grid(row=1, column=0, sticky="w", padx=10)
            return

        # Thanh điều khiển
        bar = ctk.CTkFrame(self.frame_realtime)
        bar.grid(row=1, column=0, sticky="ew", pady=(0, 15))
        bar.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(bar, text="Card mạng:").grid(row=0, column=0, padx=(15, 6), pady=12)
        self.rt_iface_menu = ctk.CTkOptionMenu(bar, values=["(bấm 🔄 để nạp)"], width=360)
        self.rt_iface_menu.grid(row=0, column=1, padx=6, pady=12, sticky="w")
        ctk.CTkButton(bar, text="🔄", width=36, command=self._rt_refresh_ifaces).grid(row=0, column=2, padx=6)

        self.btn_rt_start = ctk.CTkButton(
            bar, text="▶ Bắt gói trực tiếp", fg_color="#2ca02c", hover_color="#227d22",
            command=self.start_realtime_capture)
        self.btn_rt_start.grid(row=0, column=3, padx=6, pady=12)
        self.btn_rt_stop = ctk.CTkButton(
            bar, text="⏹ Dừng", fg_color="#a33", hover_color="#822", command=self.stop_realtime_capture)
        self.btn_rt_stop.grid(row=0, column=4, padx=6, pady=12)
        ctk.CTkButton(
            bar, text="📂 Phát lại pcap", fg_color="#2b5b84", hover_color="#1e4160",
            command=self.replay_pcap_file).grid(row=0, column=5, padx=(6, 15), pady=12)

        # Hàng 2: nhận gói GỬI THẲNG từ Phần 2 qua localhost (không cần Npcap/quyền)
        ctk.CTkLabel(bar, text="Nhận từ Phần 2:").grid(row=1, column=0, padx=(15, 6), pady=(0, 12))
        self.btn_rt_listen = ctk.CTkButton(
            bar, text="🛰 Nghe từ Phần 2", fg_color="#6a3", hover_color="#582",
            command=self.toggle_listen)
        self.btn_rt_listen.grid(row=1, column=1, padx=6, pady=(0, 12), sticky="w")
        self.rt_listen_lbl = ctk.CTkLabel(bar, text="(đang tắt)", text_color="gray")
        self.rt_listen_lbl.grid(row=1, column=2, columnspan=3, padx=6, pady=(0, 12), sticky="w")

        # Thẻ thống kê
        stat = ctk.CTkFrame(self.frame_realtime)
        stat.grid(row=2, column=0, sticky="ew", pady=(0, 15))
        stat.grid_columnconfigure((0, 1, 2, 3), weight=1)
        self.rt_card_pkt = self.create_mini_stat_card(stat, 0, "Gói Tin Bắt Được", "0", "gray")
        self.rt_card_conn = self.create_mini_stat_card(stat, 1, "Kết Nối", "0", "#1f77b4")
        self.rt_card_atk = self.create_mini_stat_card(stat, 2, "Bị Tấn Công", "0", "#d62728")
        self.rt_card_rate = self.create_mini_stat_card(stat, 3, "Tỷ Lệ Tấn Công", "0.0%", "#ff7f0e")

        # Bảng kết nối phát hiện được
        tbl = ctk.CTkFrame(self.frame_realtime)
        tbl.grid(row=3, column=0, sticky="nsew")
        tbl.grid_rowconfigure(0, weight=1)
        tbl.grid_columnconfigure(0, weight=1)

        cols = ("time", "src", "dst", "service", "flag", "prediction", "confidence", "status")
        self.rt_tree = ttk.Treeview(tbl, columns=cols, show="headings", selectmode="browse")
        for c, t, w, a in [
            ("time", "Thời gian", 90, "center"), ("src", "Nguồn", 150, "w"),
            ("dst", "Đích", 150, "w"), ("service", "Dịch vụ", 90, "center"),
            ("flag", "Cờ", 70, "center"), ("prediction", "Dự đoán", 150, "w"),
            ("confidence", "Tin cậy", 80, "center"), ("status", "Cảnh báo", 150, "center"),
        ]:
            self.rt_tree.heading(c, text=t)
            self.rt_tree.column(c, width=w, anchor=a)
        scroll = ttk.Scrollbar(tbl, orient="vertical", command=self.rt_tree.yview)
        self.rt_tree.configure(yscrollcommand=scroll.set)
        self.rt_tree.grid(row=0, column=0, sticky="nsew")
        scroll.grid(row=0, column=1, sticky="ns")
        self.rt_tree.tag_configure("attack", background="#ffcccc", foreground="#990000")
        self.rt_tree.tag_configure("normal", background="#e6ffe6", foreground="#006600")

        self.rt_status = ctk.CTkLabel(self.frame_realtime, text="Sẵn sàng.", anchor="w", text_color="gray")
        self.rt_status.grid(row=4, column=0, sticky="ew", pady=(8, 0))

        self._rt_refresh_ifaces()

    # ---- liệt kê card mạng (tên dễ đọc + IP) -------------------------------
    def _rt_refresh_ifaces(self):
        labels, mapping = [], {}
        try:
            from scapy.arch.windows import get_windows_if_list
            rows = []
            for d in get_windows_if_list():
                desc = d.get("description") or d.get("name") or "?"
                ips = [ip for ip in (d.get("ips") or []) if ":" not in ip]
                lbl = f"{desc}  [{ips[0] if ips else 'không IP'}]"
                mapping[lbl] = d.get("name") or d.get("guid")
                rows.append((lbl, bool(ips)))
            rows.sort(key=lambda x: (not x[1]))
            labels = [r[0] for r in rows]
        except Exception:  # noqa: BLE001
            try:
                from scapy.arch import get_if_list
                labels = list(get_if_list())
                mapping = {x: x for x in labels}
            except Exception:  # noqa: BLE001
                labels = ["(cần cài scapy)"]
        self.rt_iface_map = mapping
        self.rt_iface_menu.configure(values=labels or ["(không thấy card)"])
        if labels:
            self.rt_iface_menu.set(labels[0])

    def _rt_new_engine(self):
        """Tạo engine mới (reset bộ đếm) nhưng DÙNG LẠI model đã nạp sẵn."""
        self.rt_engine = RealtimeEngine(
            config=RealtimeConfig(flow_timeout=2.0),
            predictor=self.predictor,
            load_model=self.predictor is None,
        )
        self.rt_counts = {"pkt": 0, "conn": 0, "attack": 0}
        self.rt_tree.delete(*self.rt_tree.get_children())
        self._rt_update_cards()

    def _rt_update_cards(self):
        c = self.rt_counts
        self.rt_card_pkt.configure(text=str(c["pkt"]))
        self.rt_card_conn.configure(text=str(c["conn"]))
        self.rt_card_atk.configure(text=str(c["attack"]))
        rate = (c["attack"] / c["conn"] * 100) if c["conn"] else 0.0
        self.rt_card_rate.configure(text=f"{rate:.1f}%")

    def _rt_on_pred(self, pred):
        self.after(0, lambda: self._rt_add_row(pred))

    def _rt_add_row(self, pred):
        conn = pred.conn
        self.rt_counts["conn"] += 1
        self.rt_counts["attack"] += int(pred.is_attack)
        if self.rt_engine:
            self.rt_counts["pkt"] = self.rt_engine.stats.get("packets", self.rt_counts["pkt"])
        tag = "attack" if pred.is_attack else "normal"
        status = f"🚨 {pred.category.upper()}" if pred.is_attack else "✅ AN TOÀN"
        self.rt_tree.insert(
            "", "end", tags=(tag,),
            values=(time.strftime("%H:%M:%S"), f"{conn.src}:{conn.sport}",
                    f"{conn.dst}:{conn.dport}", conn.service, conn.flag,
                    CLASS_DISPLAY_NAMES.get(pred.category, pred.category),
                    f"{pred.confidence*100:.0f}%", status))
        self.rt_tree.see(self.rt_tree.get_children()[-1])
        self._rt_update_cards()

    def start_realtime_capture(self):
        if self.rt_thread and self.rt_thread.is_alive():
            self.rt_status.configure(text="Đang chạy; bấm Dừng trước.")
            return
        label = self.rt_iface_menu.get()
        iface = self.rt_iface_map.get(label, label)
        if not iface or iface.startswith("("):
            self.rt_status.configure(text="Chưa chọn được card mạng (bấm 🔄).")
            return
        self._rt_new_engine()
        self.rt_stop.clear()
        self.rt_status.configure(text=f"Đang bắt gói trên: {label} ...")

        def worker():
            try:
                self.rt_engine.live_capture(
                    iface=iface, on_prediction=self._rt_on_pred, stop_event=self.rt_stop)
            except Exception as exc:  # noqa: BLE001
                self.after(0, lambda: self.rt_status.configure(
                    text=f"Lỗi bắt gói: {exc} (cần Npcap + quyền Administrator)"))
            finally:
                self.after(0, lambda: self.btn_rt_start.configure(state="normal"))

        self.btn_rt_start.configure(state="disabled")
        self.rt_thread = threading.Thread(target=worker, daemon=True)
        self.rt_thread.start()

    def stop_realtime_capture(self):
        self.rt_stop.set()
        self.rt_status.configure(text="Đã dừng bắt gói.")

    # ---- NHẬN GÓI GỬI THẲNG TỪ PHẦN 2 (localhost HOẶC qua LAN 2 máy) ---------
    LISTEN_HOST = "0.0.0.0"   # nghe trên MỌI card -> nhận được cả localhost lẫn máy khác trong LAN
    LISTEN_PORT = 59999

    @staticmethod
    def _lan_ip():
        """IP LAN của máy này (để máy Phần 2 khác biết trỏ tới đâu)."""
        import socket
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:  # noqa: BLE001
            return "127.0.0.1"

    def toggle_listen(self):
        """Bật/tắt chế độ lắng nghe gói tin do Phần 2 gửi qua localhost."""
        if getattr(self, "rt_listening", False):
            self.rt_listen_stop.set()
            self.rt_listening = False
            self.btn_rt_listen.configure(text="🛰 Nghe từ Phần 2")
            self.rt_listen_lbl.configure(text="(đang tắt)", text_color="gray")
            return
        # bật
        self._rt_new_engine()
        self.rt_listen_stop = threading.Event()
        self.rt_listening = True
        self.btn_rt_listen.configure(text="⏹ Dừng nghe")
        self.rt_listen_lbl.configure(
            text=(f"Đang nghe cổng {self.LISTEN_PORT} — cùng máy: 127.0.0.1 | "
                  f"máy khác trỏ tới: {self._lan_ip()}:{self.LISTEN_PORT}"),
            text_color="#2ca02c")
        threading.Thread(target=self._listen_server, daemon=True).start()

    def _listen_server(self):
        import socket
        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind((self.LISTEN_HOST, self.LISTEN_PORT))
            srv.listen(1)
            srv.settimeout(1.0)
        except Exception as exc:  # noqa: BLE001
            self.after(0, lambda: self.rt_listen_lbl.configure(
                text=f"Lỗi mở cổng: {exc}", text_color="#d62728"))
            self.rt_listening = False
            return
        while not self.rt_listen_stop.is_set():
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            self._handle_part2_client(conn)
        srv.close()

    def _handle_part2_client(self, conn):
        import json
        from realtime.packet import PacketMeta
        self.after(0, lambda: self.rt_listen_lbl.configure(
            text="Phần 2 đang gửi...", text_color="#2ca02c"))
        try:
            f = conn.makefile("r", encoding="utf-8")
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    d = json.loads(line)
                except ValueError:
                    continue
                meta = PacketMeta(
                    ts=d.get("ts") or time.time(), proto=d.get("proto", "other"),
                    src_ip=d.get("src", "0.0.0.0"), dst_ip=d.get("dst", "0.0.0.0"),
                    sport=int(d.get("sport", 0)), dport=int(d.get("dport", 0)),
                    length=int(d.get("length", 0)),
                    tcp_flags=frozenset(d.get("flags", [])),
                    icmp_type=int(d.get("icmp_type", 8)))
                for pred in self.rt_engine.ingest_packet(meta):
                    self._rt_on_pred(pred)
            for pred in self.rt_engine.flush():
                self._rt_on_pred(pred)
        finally:
            conn.close()
        self.after(0, lambda: self.rt_listen_lbl.configure(
            text=f"Đã nhận xong 1 đợt. Vẫn đang nghe cổng {self.LISTEN_PORT}...",
            text_color="#2ca02c"))

    def replay_pcap_file(self):
        path = filedialog.askopenfilename(
            title="Chọn file pcap để phát lại",
            filetypes=[("PCAP", "*.pcap *.pcapng"), ("All", "*.*")])
        if not path:
            return
        if self.rt_thread and self.rt_thread.is_alive():
            self.rt_status.configure(text="Đang chạy; bấm Dừng trước.")
            return
        self._rt_new_engine()
        self.rt_status.configure(text=f"Đang phát lại: {os.path.basename(path)} ...")

        def worker():
            try:
                self.rt_engine.replay_pcap(path, on_prediction=self._rt_on_pred)
                self.after(0, lambda: self.rt_status.configure(
                    text=f"Xong: {os.path.basename(path)}"))
            except Exception as exc:  # noqa: BLE001
                self.after(0, lambda: self.rt_status.configure(text=f"Lỗi phát lại: {exc}"))

        self.rt_thread = threading.Thread(target=worker, daemon=True)
        self.rt_thread.start()

    def browse_csv_file(self):
        file_path = filedialog.askopenfilename(
            title="Chọn file CSV mạng",
            filetypes=[("CSV Files", "*.csv"), ("Text Files", "*.txt"), ("All Files", "*.*")]
        )
        if file_path:
            self.txt_file_path.delete(0, tk.END)
            self.txt_file_path.insert(0, file_path)

    def load_sample_csv(self):
        sample_path = os.path.join(DATA_DIR, "sample_test.csv")
        if os.path.exists(sample_path):
            self.txt_file_path.delete(0, tk.END)
            self.txt_file_path.insert(0, sample_path)
            messagebox.showinfo("Thành công", f"Đã nạp file mẫu: {os.path.basename(sample_path)}")
        else:
            messagebox.showwarning("Không tìm thấy", "Chưa tìm thấy file sample_test.csv. Hãy chạy lại train.py!")

    def start_batch_scan_thread(self):
        file_path = self.txt_file_path.get().strip()
        if not file_path or not os.path.exists(file_path):
            messagebox.showwarning("Cảnh báo", "Vui lòng chọn một file dữ liệu hợp lệ trước!")
            return

        self.btn_run_batch.configure(state="disabled", text="ĐANG QUÉT...")
        self.batch_progress.set(0.1)

        thread = threading.Thread(target=self.run_batch_scan_process, args=(file_path,), daemon=True)
        thread.start()

    def run_batch_scan_process(self, file_path):
        try:
            # Đọc file CSV
            df = pd.read_csv(file_path)
            self.batch_progress.set(0.3)

            
            # Du doan bang AI
            result_df = self.predictor.predict_batch(df)
            self.batch_result_df = result_df

            # Tong hop ket qua de ma hoa
            attack_rows = result_df[
                result_df["is_attack"].astype(bool)
            ]

            try:
                self.crypto_logger.append_alert({
                    "event": "batch_scan",
                    "file_name": os.path.basename(file_path),
                    "total_records": int(len(result_df)),
                    "attack_records": int(len(attack_rows)),
                    "categories": {
                        str(k): int(v)
                        for k, v in attack_rows[
                            "predicted_category"
                        ].value_counts().items()
                    }
                })

                print("[CRYPTO] Da ma hoa bao cao quet CSV!")

            except Exception as crypto_error:
                error_message = str(crypto_error)

                self.after(
                    0,
                    lambda msg=error_message: messagebox.showwarning(
                        "Loi ma hoa",
                        f"Quet thanh cong nhung khong luu duoc log: {msg}"
                    )
                )

            self.batch_progress.set(0.8)


            # Đưa dữ liệu lên Treeview trên main thread
            self.after(0, lambda: self.update_batch_ui(result_df))

        except Exception as e:
            self.after(0, lambda: messagebox.showerror("Lỗi Quét File", f"Đã có lỗi xảy ra:\n{e}"))
            self.after(0, lambda: self.btn_run_batch.configure(state="normal", text="🚀 BẮT ĐẦU QUÉT"))

    def update_batch_ui(self, result_df):
        # Xóa dữ liệu cũ trong Treeview
        for item in self.tree.get_children():
            self.tree.delete(item)

        total_rows = len(result_df)
        attack_count = int(result_df['is_attack'].sum())
        normal_count = total_rows - attack_count
        rate = (attack_count / total_rows * 100) if total_rows > 0 else 0

        self.card_total.configure(text=f"{total_rows:,}")
        self.card_normal.configure(text=f"{normal_count:,}")
        self.card_attack.configure(text=f"{attack_count:,}")
        self.card_rate.configure(text=f"{rate:.1f}%")

        # Nạp dữ liệu vào bảng (tối đa 300 dòng đầu để mượt UI)
        for i, row in result_df.head(300).iterrows():
            is_atk = bool(row['is_attack'])
            tag = "attack" if is_atk else "normal"
            status_text = "🚨 NGUY HIỂM" if is_atk else "🟢 AN TOÀN"
            pred_name = row.get('predicted_name', row['predicted_category'])
            conf_str = f"{row.get('confidence', 1.0) * 100:.1f}%"

            self.tree.insert(
                "", "end",
                values=(
                    i + 1,
                    row.get('protocol_type', '-'),
                    row.get('service', '-'),
                    row.get('flag', '-'),
                    pred_name,
                    conf_str,
                    status_text
                ),
                tags=(tag,)
            )

        self.batch_progress.set(1.0)
        self.btn_run_batch.configure(state="normal", text="🚀 BẮT ĐẦU QUÉT")
        self.btn_export.configure(state="normal")
        messagebox.showinfo(
            "Hoàn tất quét",
            f"Đã quét xong {total_rows:,} gói tin!\nPhát hiện: {attack_count} gói tin tấn công ({rate:.1f}%)."
        )

    def export_batch_results(self):
        if self.batch_result_df is None:
            return
        save_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV Files", "*.csv")],
            initialfile="ket_qua_quet_nids.csv"
        )
        if save_path:
            try:
                self.batch_result_df.to_csv(save_path, index=False)
                messagebox.showinfo("Thành công", f"Đã lưu kết quả tại:\n{save_path}")
            except Exception as e:
                messagebox.showerror("Lỗi", f"Không thể lưu file: {e}")

    # =========================================================================
    # TAB 3: BIỂU ĐỒ & BÁO CÁO MÔ HÌNH (ANALYTICS & CHARTS)
    # =========================================================================
    def setup_charts_frame(self):
        self.frame_charts.grid_columnconfigure(0, weight=1)
        self.frame_charts.grid_rowconfigure(2, weight=1)

        # Header
        ctk.CTkLabel(
            self.frame_charts,
            text="📊 Báo Cáo Hiệu Năng & Trực Quan Hóa Mô Hình Machine Learning",
            font=ctk.CTkFont(size=20, weight="bold")
        ).grid(row=0, column=0, sticky="w", pady=(0, 15))

        # Thanh chọn xem biểu đồ
        chart_selector_bar = ctk.CTkFrame(self.frame_charts)
        chart_selector_bar.grid(row=1, column=0, sticky="ew", pady=(0, 15))

        self.btn_view_cm = ctk.CTkButton(
            chart_selector_bar,
            text="Ma Trận Nhầm Lẫn (Confusion Matrix)",
            command=lambda: self.display_chart("confusion_matrix.png")
        )
        self.btn_view_cm.pack(side="left", padx=10, pady=10)

        self.btn_view_fi = ctk.CTkButton(
            chart_selector_bar,
            text="Đặc Trưng Quan Trọng (Top 15 Features)",
            command=lambda: self.display_chart("feature_importance.png")
        )
        self.btn_view_fi.pack(side="left", padx=10, pady=10)

        self.btn_view_cmp = ctk.CTkButton(
            chart_selector_bar,
            text="So Sánh 3 Thuật Toán (DT - RF - KNN)",
            command=lambda: self.display_chart("model_comparison.png")
        )
        self.btn_view_cmp.pack(side="left", padx=10, pady=10)

        # Khung hiển thị ảnh biểu đồ
        self.chart_display_box = ctk.CTkScrollableFrame(self.frame_charts, label_text="Hình ảnh biểu đồ")
        self.chart_display_box.grid(row=2, column=0, sticky="nsew")

        self.lbl_chart_image = ctk.CTkLabel(self.chart_display_box, text="")
        self.lbl_chart_image.pack(pady=20, padx=20)

        # Tải mặc định biểu đồ ma trận nhầm lẫn
        self.display_chart("confusion_matrix.png")

    def display_chart(self, chart_filename):
        img_path = os.path.join(MODELS_DIR, chart_filename)
        if not os.path.exists(img_path):
            self.lbl_chart_image.configure(
                text=f"Chưa tìm thấy biểu đồ {chart_filename}.\nVui lòng chạy lại src/train.py!",
                image=None
            )
            return

        try:
            pil_img = Image.open(img_path)
            # Resize để vừa khung màn hình
            width, height = pil_img.size
            max_width = 860
            if width > max_width:
                ratio = max_width / width
                new_w = max_width
                new_h = int(height * ratio)
                pil_img = pil_img.resize((new_w, new_h), Image.Resampling.LANCZOS)

            ctk_img = ctk.CTkImage(light_image=pil_img, dark_image=pil_img, size=pil_img.size)
            self.lbl_chart_image.configure(image=ctk_img, text="")
        except Exception as e:
            self.lbl_chart_image.configure(text=f"Lỗi tải ảnh: {e}", image=None)

    # =========================================================================
    # TAB 4: GIỚI THIỆU & THÔNG TIN ĐỒ ÁN (ABOUT)
    # =========================================================================
    def setup_about_frame(self):
        self.frame_about.grid_columnconfigure(0, weight=1)
        self.frame_about.grid_rowconfigure(1, weight=1)

        ctk.CTkLabel(
            self.frame_about,
            text="ℹ️ Thông Tin Đề Tài & Hướng Dẫn Sử Dụng",
            font=ctk.CTkFont(size=20, weight="bold")
        ).grid(row=0, column=0, sticky="w", pady=(0, 15))

        info_box = ctk.CTkScrollableFrame(self.frame_about)
        info_box.grid(row=1, column=0, sticky="nsew")

        content = """
==========================================================================
        HỆ THỐNG PHÁT HIỆN XÂM NHẬP MẠNG (NIDS) BẰNG MACHINE LEARNING
==========================================================================

1. THÔNG TIN CHUNG:
   • Môn học / Đề tài: An toàn & Bảo mật Thông tin (ATTT)
   • Người thực hiện: Phan Hoàng Anh
   • Bộ dữ liệu sử dụng: NSL-KDD (Chuẩn quốc tế đánh giá hệ thống NIDS)
   • Ngôn ngữ & Thư viện: Python 3, Scikit-learn, Pandas, CustomTkinter, Joblib

--------------------------------------------------------------------------
2. CÁC TÍNH NĂNG CHÍNH CỦA ỨNG DỤNG:
   • Quét Gói Tin Đơn Lẻ:
     - Nhập hoặc lấy ngẫu nhiên 1 mẫu gói tin từ tập kiểm thử.
     - Phân tích cảnh báo thời gian thực: Bình thường hoặc Tấn công (DoS, Probe, R2L, U2R).
     - Đo lường độ tin cậy và phân bố xác suất của từng phân loại.

   • Quét Hàng Loạt Từ File CSV:
     - Đọc các tệp tin chứa hàng ngàn bản ghi lưu lượng mạng.
     - Phân loại song song trong luồng nền (Multithreading), không làm đơ giao diện.
     - Báo cáo tổng số gói tin bị tấn công, tỷ lệ rủi ro và xuất kết quả ra file CSV.

   • Biểu Đồ & Thống Kê Mô Hình:
     - Xem ma trận nhầm lẫn (Confusion Matrix).
     - Phân tích các đặc trưng mạng quan trọng nhất (Feature Importance).
     - So sánh độ chính xác giữa 3 thuật toán: Decision Tree, Random Forest và KNN.

--------------------------------------------------------------------------
3. 5 NHÓM LƯU LƯỢNG ĐƯỢC PHÂN LOẠI:
   • Normal : Lưu lượng mạng an toàn của người dùng bình thường.
   • DoS    : Tấn công từ chối dịch vụ (làm cạn kiệt băng thông / tài nguyên máy chủ).
   • Probe  : Dò quét mạng, quét cổng dịch vụ để thu thập thông tin lỗ hổng.
   • R2L    : Kẻ tấn công từ xa truy cập trái phép vào máy chủ cục bộ (đoán pass, ftp...).
   • U2R    : Tài khoản thường leo thang đặc quyền để chiếm quyền root / quản trị.
==========================================================================
        """
        ctk.CTkLabel(
            info_box,
            text=content,
            font=ctk.CTkFont(family="Consolas", size=13),
            justify="left"
        ).pack(padx=20, pady=20, anchor="w")


if __name__ == "__main__":
    app = NIDSApp()
    app.mainloop()