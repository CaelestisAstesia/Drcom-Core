# src/drcom_core/protocols/__init__.py
"""
Dr.COM 协议层 (Protocol Layer)

本包负责协议数据包的haole纯粹构建 (Build) 与解析 (Parse)。

- 不包含任何 socket 操作或网络 I/O。
- 不包含任何状态管理 (State)。
- 不依赖于 core 或 network 层。
"""

from . import constants
from .challenge import build_challenge_request, parse_challenge_response
from .keep_alive import (
    build_keep_alive1_packet,
    build_keep_alive2_packet,
    parse_keep_alive1_response,
    parse_keep_alive2_response,
)
from .login import build_login_packet, parse_login_response
from .logout import build_logout_packet, parse_logout_response

# 公共 API
__all__ = [
    "constants",
    "build_challenge_request",
    "parse_challenge_response",
    "build_login_packet",
    "parse_login_response",
    "build_keep_alive1_packet",
    "parse_keep_alive1_response",
    "build_keep_alive2_packet",
    "parse_keep_alive2_response",
    "build_logout_packet",
    "parse_logout_response",
]
