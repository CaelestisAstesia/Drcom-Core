# src/drcom_core/state.py
"""
Dr.COM 核心库 - 状态模块

负责定义和存储所有易变的会话状态。
"""

from dataclasses import dataclass
from enum import Enum, auto


class CoreStatus(Enum):
    """核心引擎的生命周期状态枚举"""

    IDLE = auto()  # 初始化完成，未操作
    CONNECTING = auto()  # 正在执行 Challenge 或 Login 流程
    LOGGED_IN = auto()  # 登录成功，等待心跳启动 (或心跳暂停)
    HEARTBEAT = auto()  # 心跳线程正在运行 (在线保活中)
    OFFLINE = auto()  # 已离线 (可能是主动登出，也可能是掉线)
    ERROR = auto()  # 发生致命错误停止


@dataclass
class DrcomState:
    """
    存储 Dr.COM 核心认证会话的动态状态。
    """

    # --- 基础会话数据 ---
    # 登录凭证
    salt: bytes = b""
    auth_info: bytes = b""

    # --- 高级状态监控 ---
    status: CoreStatus = CoreStatus.IDLE
    """当前引擎的精确状态"""

    last_error: str = ""
    """最近一次发生的错误简报 (用于 IPC/CLI 显示)"""

    # --- Keep Alive 2 协议状态 ---
    keep_alive_serial_num: int = 0
    keep_alive_tail: bytes = b"\x00\x00\x00\x00"
    _ka2_initialized: bool = False  # 内部标志，标记KA2是否已完成三步握手

    @property
    def is_online(self) -> bool:
        """
        辅助属性：判断当前是否处于在线状态。
        替代旧的 login_success 字段。
        """
        return self.status in (CoreStatus.LOGGED_IN, CoreStatus.HEARTBEAT)
