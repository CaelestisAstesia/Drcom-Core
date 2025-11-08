# src/drcom_core/__init__.py
"""
drcom-core: 现代化 Dr.Com 认证协议核心库
"""

# 公共 API
from .config import DrcomConfig, load_config_from_dict
from .core import DrcomCore
from .state import DrcomState

__all__ = [
    "DrcomCore",
    "DrcomConfig",
    "DrcomState",
    "load_config_from_dict",
]
