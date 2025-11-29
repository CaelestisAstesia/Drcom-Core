# src/drcom_core/__init__.py
"""
Drcom-Core v1.1.0
现代化、高扩展的 Dr.COM 认证协议核心库。
"""

# 暴露核心配置
from .config import (
    DrcomConfig,
    create_config_from_dict,
    load_config_from_env,
    load_config_from_toml,
)

# 暴露引擎与状态
from .core import DrcomCore

# 暴露异常体系 (方便上层 try-except)
from .exceptions import (
    AuthError,
    AuthErrorCode,
    ConfigError,
    DrcomError,
    NetworkError,
    ProtocolError,
)
from .state import CoreStatus, DrcomState

__version__ = "1.1.0"

__all__ = [
    "DrcomCore",
    "DrcomConfig",
    "DrcomState",
    "CoreStatus",
    "create_config_from_dict",
    "load_config_from_env",
    "load_config_from_toml",
    "DrcomError",
    "ConfigError",
    "NetworkError",
    "AuthError",
    "AuthErrorCode",
    "ProtocolError",
]
