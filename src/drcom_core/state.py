# src/drcom_core/state.py
"""
Dr.COM 核心库 - 状态模块 (State)

负责定义和存储所有易变的会话状态。
"""

from dataclasses import dataclass
from enum import Enum, auto


class CoreStatus(Enum):
    """核心引擎的生命周期状态枚举"""

    IDLE = auto()  # 初始化完成，未操作
    CONNECTING = auto()  # 正在执行 Challenge 或 Login 流程
    LOGGED_IN = auto()  # 登录成功，等待心跳启动
    HEARTBEAT = auto()  # 心跳线程正在运行 (在线保活中)
    OFFLINE = auto()  # 已离线 (主动登出或掉线)
    ERROR = auto()  # 发生异常停止


@dataclass
class DrcomState:
    """
    存储 Dr.COM 认证会话的动态状态。
    这里的数据随每一次登录会话重置。
    """

    # --- 基础会话凭据 ---
    salt: bytes = b""  # 挑战获取的盐值
    auth_info: bytes = b""  # 登录成功后返回的 Token (用于注销和心跳)

    # --- 引擎状态 ---
    status: CoreStatus = CoreStatus.IDLE
    last_error: str = ""  # 最近一次报错信息

    # --- Keep Alive 2 (D版) 状态机 ---
    keep_alive_serial_num: int = 0  # 序列号 (0-255 循环)
    keep_alive_tail: bytes = b"\x00" * 4  # 尾部签名 (Tail)
    _ka2_initialized: bool = False  # 内部标志：是否已完成 KA2 初始握手

    @property
    def is_online(self) -> bool:
        """
        判断是否处于在线状态 (LOGGED_IN 或 HEARTBEAT)。
        这是外部主循环判断是否需要重连的依据。
        """
        return self.status in (CoreStatus.LOGGED_IN, CoreStatus.HEARTBEAT)
