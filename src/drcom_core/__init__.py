# src/drcom_core/__init__.py
"""
drcom-core: 现代化 Dr.Com 认证协议核心库
"""

from .config import DrcomConfig, load_config_from_toml, validate_and_create_config
from .core import DrcomCore
from .exceptions import AuthError, ConfigError, DrcomError, NetworkError, ProtocolError
from .state import CoreStatus, DrcomState

__all__ = [
    "DrcomCore",
    "DrcomConfig",
    "DrcomState",
    "CoreStatus",
    "load_config_from_toml",
    "validate_and_create_config",
    "DrcomError",
    "ConfigError",
    "NetworkError",
    "ProtocolError",
    "AuthError",
]
__version__ = "1.0.0b1"
