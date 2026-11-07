"""Chạy Net Shield: python -m net_shield [--lan] [--pass=XXX] [--port=8081]"""
import sys

from .config import IPSConfig
from .server import run


def main() -> int:
    cfg = IPSConfig()
    for arg in sys.argv[1:]:
        if arg == "--lan":
            cfg.allow_lan = True
        elif arg.startswith("--pass="):
            cfg.dashboard_password = arg.split("=", 1)[1]
        elif arg.startswith("--port="):
            cfg.dashboard_port = int(arg.split("=", 1)[1])
        elif arg in ("-h", "--help"):
            print("Tùy chọn: --lan (mở cho máy khác cùng mạng), "
                  "--pass=MATKHAU, --port=8081")
            return 0
    return run(cfg) or 0


if __name__ == "__main__":
    sys.exit(main())
