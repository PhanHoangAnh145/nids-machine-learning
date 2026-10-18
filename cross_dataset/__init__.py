"""
cross_dataset - Module đánh giá chéo (cross-dataset evaluation) cho NIDS.

Nguyên tắc thiết kế (BẮT BUỘC):
  * KHÔNG sửa, KHÔNG ghi đè bất kỳ file nào của luồng cũ (src/, main.py, models/).
  * Chỉ ĐỌC 2 artifact đã train: models/best_model.joblib và models/preprocessor.joblib.
  * Mọi kết quả ghi ra thư mục riêng: reports/cross_dataset/.

Luồng xử lý:
  Dataset mới --(Adapter)--> 41 cột thô NSL-KDD + attack_category
             --(preprocessor.joblib, giữ nguyên)--> 122 chiều
             --(best_model.joblib, giữ nguyên)--> dự đoán --> metrics
"""

__version__ = "1.0.0"
