# File: src/drcom_core/state.py
"""
Dr.COM 核心库 - 状态模块

负责定义和存储所有易变的会话状态。
本模块不包含业务逻辑，仅作为数据容器供 Core 和 Strategy 共享读写。
"""

from dataclasses import dataclass
from enum import Enum, auto


class CoreStatus(Enum):
    """核心引擎的生命周期状态枚举。

    状态流转示意:
    IDLE -> CONNECTING -> LOGGED_IN -> HEARTBEAT -> OFFLINE
               |              |            |
               v              v            v
             ERROR          ERROR        ERROR
    """

    IDLE = auto()
    """初始状态，引擎已实例化但未执行任何操作。"""

    CONNECTING = auto()
    """正在连接中 (正在执行 Challenge 握手或 Login 登录)。"""

    LOGGED_IN = auto()
    """登录成功。已获取 Auth Info，但心跳线程尚未启动。"""

    HEARTBEAT = auto()
    """在线保活中。心跳守护线程正在后台稳定运行。"""

    OFFLINE = auto()
    """已离线。可能是用户主动注销，或因网络波动导致的心跳丢失。"""

    ERROR = auto()
    """错误状态。发生了不可恢复的技术性错误 (如端口绑定失败)。"""


@dataclass
class DrcomState:
    """存储 Dr.COM 认证会话的易变状态数据。

    该对象是非持久化的。每次重新登录 (Re-Login) 时，
    建议重置或重新实例化此对象，以避免旧的序列号污染新会话。

    Attributes:
        salt: Challenge 阶段从服务器获取的随机盐值 (4 Bytes)。
        auth_info: 登录成功后服务器返回的鉴权令牌 (16 Bytes)。
        status: 当前核心引擎的运行状态。
        last_error: 最近一次发生的错误信息描述，用于 UI 显示。
        keep_alive_serial_num: KA2 包的序列号 (0-255)，每次发送后自增。
        keep_alive_tail: KA2 包的尾部签名，由上一次响应提取。
        _ka2_initialized: [Internal] KA2 初始化握手是否完成的标志位。
    """

    # --- 基础会话凭据 ---
    salt: bytes = b""
    auth_info: bytes = b""

    # --- 引擎状态 ---
    status: CoreStatus = CoreStatus.IDLE
    last_error: str = ""

    # --- D 版协议专用状态 ---
    keep_alive_serial_num: int = 0
    keep_alive_tail: bytes = b"\x00" * 4
    _ka2_initialized: bool = False

    @property
    def is_online(self) -> bool:
        """判断当前是否处于“在线”状态。

        在线状态包括 LOGGED_IN (刚登录) 和 HEARTBEAT (保活中)。
        该属性通常用于外部守护进程判断是否需要执行自动重连。

        Returns:
            bool: 如果在线返回 True。
        """
        return self.status in (CoreStatus.LOGGED_IN, CoreStatus.HEARTBEAT)
