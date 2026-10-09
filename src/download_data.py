"""
Script tải bộ dữ liệu NSL-KDD từ CDN về thư mục data/raw/
"""
import os
import sys
import requests

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except Exception:
        pass

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "raw")

DATASET_FILES = {
    # KDDTrain+_20Percent.txt (khoảng 25,192 mẫu - huấn luyện cực nhanh và chuẩn)
    # KDDTest+.txt (khoảng 22,544 mẫu - tập kiểm thử độc lập)
    "KDDTrain+.txt": "https://cdn.jsdelivr.net/gh/defcom17/NSL_KDD@master/KDDTrain%2B.txt",
    "KDDTrain+_20Percent.txt": "https://cdn.jsdelivr.net/gh/defcom17/NSL_KDD@master/KDDTrain%2B_20Percent.txt",
    "KDDTest+.txt": "https://cdn.jsdelivr.net/gh/defcom17/NSL_KDD@master/KDDTest%2B.txt",
}

def download_file(url: str, dest_path: str):
    print(f"[*] Dang tai {os.path.basename(dest_path)} tu {url}...")
    try:
        response = requests.get(url, stream=True, timeout=30)
        response.raise_for_status()
        
        total_size = int(response.headers.get("content-length", 0))
        downloaded = 0
        chunk_size = 1024 * 64
        
        with open(dest_path, "wb") as f:
            for chunk in response.iter_content(chunk_size=chunk_size):
                if chunk:
                    f.write(chunk)
                    downloaded += len(chunk)
                    if total_size > 0:
                        percent = (downloaded / total_size) * 100
                        print(f"\r    Tien do: {downloaded / 1024 / 1024:.2f}MB / {total_size / 1024 / 1024:.2f}MB ({percent:.1f}%)", end="")
        print(f"\n[+] Da tai xong: {dest_path}")
        return True
    except Exception as e:
        print(f"\n[-] Loi khi tai {url}: {e}")
        return False

def ensure_datasets(use_full_train: bool = False):
    os.makedirs(DATA_DIR, exist_ok=True)
    
    train_filename = "KDDTrain+.txt" if use_full_train else "KDDTrain+_20Percent.txt"
    files_to_download = [train_filename, "KDDTest+.txt"]
    
    for filename in files_to_download:
        dest_path = os.path.join(DATA_DIR, filename)
        if os.path.exists(dest_path) and os.path.getsize(dest_path) > 1000:
            print(f"[i] File da ton tai: {dest_path} ({os.path.getsize(dest_path) / 1024 / 1024:.2f} MB)")
        else:
            url = DATASET_FILES[filename]
            success = download_file(url, dest_path)
            if not success:
                raise RuntimeError(f"Khong the tai tap du lieu {filename}")
                
    return (
        os.path.join(DATA_DIR, train_filename),
        os.path.join(DATA_DIR, "KDDTest+.txt")
    )

if __name__ == "__main__":
    ensure_datasets(use_full_train=False)
