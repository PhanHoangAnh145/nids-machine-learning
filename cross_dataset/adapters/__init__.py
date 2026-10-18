"""Import để các adapter tự đăng ký vào registry."""
from .base import BaseAdapter, get_adapter, list_adapters, register_adapter  # noqa: F401
from . import nsl_kdd, unsw_nb15  # noqa: F401
