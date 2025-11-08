# src/drcom_core/state.py
"""
Dr.COM 核心库 - 状态模块

负责定义和存储所有易变的会话状态。
"""

from dataclasses import dataclass


@dataclass
class DrcomState:
    """
    存储 Dr.COM 核心认证会话的动态状态。
    """

    # 登录凭证
    salt: bytes = b""
    auth_info: bytes = b""
    login_success: bool = False

    # Keep Alive 2 状态
    keep_alive_serial_num: int = 0
    keep_alive_tail: bytes = b"\x00\x00\x00\x00"
    _ka2_initialized: bool = False  # 内部标志，标记KA2是否已完成三步握手
