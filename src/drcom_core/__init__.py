# src/drcom_core/__init__.py
"""
Drcom-Core: 现代化 Dr.Com 认证协议核心库 (v1.0.0)

本模块导出所有公共 API，外部应用应当仅从此处导入所需组件，
而不应直接访问子模块。

Usage:
    from drcom_core import DrcomCore, load_config_from_toml

    config = load_config_from_toml("config.toml")
    core = DrcomCore(config)
    core.login()
"""

from .config import DrcomConfig, load_config_from_toml, validate_and_create_config
from .core import DrcomCore
from .exceptions import (
    AuthError,
    AuthErrorCode,
    ConfigError,
    DrcomError,
    NetworkError,
    ProtocolError,
)
from .state import CoreStatus, DrcomState

__all__ = [
    # 核心引擎
    "DrcomCore",
    # 配置与模型
    "DrcomConfig",
    "load_config_from_toml",
    "validate_and_create_config",
    # 状态管理
    "DrcomState",
    "CoreStatus",
    # 异常体系
    "DrcomError",
    "ConfigError",
    "NetworkError",
    "ProtocolError",
    "AuthError",
    "AuthErrorCode",
]

__version__ = "1.0.0"
