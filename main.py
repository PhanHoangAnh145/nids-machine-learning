"""
Ung dung Giao dien Do hoa (GUI) He thong Phat hien Xam nhap Mang (NIDS)
Su dung Machine Learning (Random Forest) tren tap du lieu NSL-KDD.
Sinh vien thuc hien: Phan Hoang Anh
"""
import os
import sys
import threading
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
from preprocess import FEATURE_NAMES, CLASS_DISPLAY_NAMES, CLASS_LABELS

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
        self.sidebar_frame.grid_rowconfigure(6, weight=1)

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

        # Cài đặt giao diện Dark/Light ở chân sidebar
        self.theme_label = ctk.CTkLabel(self.sidebar_frame, text="Chế độ hiển thị:", anchor="w")
        self.theme_label.grid(row=7, column=0, padx=20, pady=(10, 0), sticky="w")
        self.theme_menu = ctk.CTkOptionMenu(
            self.sidebar_frame,
            values=["Dark", "Light", "System"],
            command=ctk.set_appearance_mode
        )
        self.theme_menu.grid(row=8, column=0, padx=20, pady=(5, 20), sticky="ew")

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

    def select_tab(self, tab_name):
        # Reset màu nút sidebar
        default_fg = ["#3B8ED0", "#1F6AA5"]
        inactive_fg = "transparent"

        self.btn_single.configure(fg_color=default_fg if tab_name == "single" else inactive_fg)
        self.btn_batch.configure(fg_color=default_fg if tab_name == "batch" else inactive_fg)
        self.btn_charts.configure(fg_color=default_fg if tab_name == "charts" else inactive_fg)
        self.btn_about.configure(fg_color=default_fg if tab_name == "about" else inactive_fg)

        # Ẩn tất cả frame
        self.frame_single.grid_forget()
        self.frame_batch.grid_forget()
        self.frame_charts.grid_forget()
        self.frame_about.grid_forget()

        # Hiển thị frame được chọn
        if tab_name == "single":
            self.frame_single.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)
        elif tab_name == "batch":
            self.frame_batch.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)
        elif tab_name == "charts":
            self.frame_charts.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)
        elif tab_name == "about":
            self.frame_about.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)

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

            # Dự đoán
            result_df = self.predictor.predict_batch(df)
            self.batch_result_df = result_df
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