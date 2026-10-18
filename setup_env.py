"""
setup_env.py - Cài đặt thư viện & kiểm tra môi trường cho dự án NIDS.

Cách dùng: mở file này trong PyCharm và bấm Run (hoặc: python setup_env.py).
Script dùng CHÍNH trình thông dịch Python đang chạy nó (sys.executable), nên
thư viện được cài đúng vào môi trường mà PyCharm dùng để chạy main.py.

Các bước:
  1. Đảm bảo có pip
  2. pip install -r requirements.txt
  3. Kiểm tra import từng thư viện
  4. Nạp thử model + preprocessor
  5. Chạy unit test + đối chứng KDDTest+ của module cross_dataset
Toàn bộ kết quả được ghi thêm vào file setup_env.log cạnh script.
"""
import importlib
import os
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.abspath(__file__))
LOG_PATH = os.path.join(ROOT, "setup_env.log")
os.chdir(ROOT)

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

_log = open(LOG_PATH, "w", encoding="utf-8")


def log(msg=""):
    print(msg, flush=True)
    _log.write(msg + "\n")
    _log.flush()


def run(cmd, title):
    log(f"\n$ {' '.join(cmd)}")
    env = dict(os.environ, PYTHONIOENCODING="utf-8", MPLBACKEND="Agg")
    p = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True,
                       encoding="utf-8", errors="replace", env=env)
    out = (p.stdout or "") + (p.stderr or "")
    lines = out.strip().splitlines()
    for line in lines[-40:]:           # chỉ giữ 40 dòng cuối cho gọn
        log("    " + line)
    ok = p.returncode == 0
    log(f"[{'OK' if ok else 'LOI'}] {title} (exit code {p.returncode})")
    return ok


results = {}
t0 = time.time()
log("=" * 70)
log("  CAI DAT & KIEM TRA MOI TRUONG - NIDS")
log("=" * 70)
log(f"Python     : {sys.version.split()[0]}")
log(f"Executable : {sys.executable}")
log(f"Thu muc    : {ROOT}")

# 1. pip
try:
    import pip  # noqa: F401
    results["pip"] = True
except ImportError:
    log("\n[!] Chua co pip -> cai bang ensurepip")
    results["pip"] = run([sys.executable, "-m", "ensurepip", "--upgrade"], "ensurepip")

# 2. Cài thư viện
results["pip install"] = run(
    [sys.executable, "-m", "pip", "install", "--disable-pip-version-check",
     "-r", "requirements.txt"],
    "Cai thu vien tu requirements.txt",
)

# 3. Kiểm tra import
log("\n[*] Kiem tra import thu vien:")
importlib.invalidate_caches()
modules = ["customtkinter", "PIL", "numpy", "pandas", "sklearn", "joblib",
           "matplotlib", "Crypto", "cryptography", "sympy", "requests", "tkinter"]
import_ok = True
for m in modules:
    try:
        mod = importlib.import_module(m)
        log(f"    [OK]  {m:<14} {getattr(mod, '__version__', '')}")
    except Exception as e:
        import_ok = False
        log(f"    [LOI] {m:<14} {type(e).__name__}: {e}")
results["import"] = import_ok

# 4. Nạp model
if import_ok:
    results["load model"] = run(
        [sys.executable, "-c",
         "import joblib; m=joblib.load('models/best_model.joblib'); "
         "p=joblib.load('models/preprocessor.joblib'); "
         "print(type(m).__name__, 'n_features =', m.n_features_in_)"],
        "Nap models/best_model.joblib + preprocessor.joblib",
    )

    # 5. Module cross_dataset
    if os.path.isdir(os.path.join(ROOT, "cross_dataset")):
        results["unit test"] = run(
            [sys.executable, "-m", "unittest", "discover", "-s", "cross_dataset/tests", "-t", "."],
            "Unit test cross_dataset",
        )
        results["doi chung KDDTest+"] = run(
            [sys.executable, "-m", "cross_dataset.run_inference", "--dataset", "nsl-kdd",
             "--input", "data/raw/KDDTest+.txt", "--compare-baseline"],
            "Doi chung KDDTest+ qua pipeline moi",
        )

log("\n" + "=" * 70)
log("  TONG KET")
log("=" * 70)
for k, v in results.items():
    log(f"  {'[OK] ' if v else '[LOI]'} {k}")
all_ok = all(results.values())
log(f"\n=> {'MOI TRUONG SAN SANG - co the chay main.py' if all_ok else 'CON LOI - xem chi tiet o tren'}"
    f"  ({time.time() - t0:.0f}s)")
log(f"   Log day du: {LOG_PATH}")
_log.close()
sys.exit(0 if all_ok else 1)
