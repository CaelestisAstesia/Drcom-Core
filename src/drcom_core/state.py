# src/drcom_core/state.py
"""
Dr.COM 核心库 - 状态模块 (State)

负责定义和存储所有易变的会话状态。
本模块不包含业务逻辑，仅作为数据容器 (Data Class) 供 Core 和 Strategy 共享读写。
"""

from dataclasses import dataclass
from enum import Enum, auto


class CoreStatus(Enum):
    """
    核心引擎的生命周期状态枚举。

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
    """
    存储 Dr.COM 认证会话的易变状态数据。

    该对象是非持久化的，每次重新登录 (Re-Login) 时，
    建议重置或重新实例化此对象，以避免旧的序列号污染新会话。
    """

    # =========================================================================
    # 1. 基础会话凭据 (Session Credentials)
    # =========================================================================
    salt: bytes = b""
    """
    挑战 (Challenge) 阶段从服务器获取的随机盐值 (4 Bytes)。
    用于后续登录包和心跳包的 MD5 加密。
    """

    auth_info: bytes = b""
    """
    登录成功 (0x04) 后服务器返回的鉴权令牌 (16 Bytes)。
    用于注销包和心跳包的身份验证。
    """

    # =========================================================================
    # 2. 引擎状态 (Engine Status)
    # =========================================================================
    status: CoreStatus = CoreStatus.IDLE
    """当前核心引擎的运行状态。"""

    last_error: str = ""
    """
    最近一次发生的错误信息描述。
    用于在上层 UI 显示“离线原因”。
    """

    # =========================================================================
    # 3. D 版协议专用状态机 (D-Series State Machine)
    # =========================================================================
    keep_alive_serial_num: int = 0
    """
    KeepAlive2 (0x07) 包的序列号 (0-255)。
    每次发送心跳包后自增并取模。
    """

    keep_alive_tail: bytes = b"\x00" * 4
    """
    KeepAlive2 (0x07) 包的尾部签名 (Tail)。
    由上一次心跳响应包的 [16:20] 字节提取，用于下一次请求。
    """

    _ka2_initialized: bool = False
    """
    [Internal] 内部标志位：KA2 初始化握手是否完成。
    D 版心跳分为 Init (3步) 和 Loop (2步) 两个阶段，此标志用于切换阶段。
    """

    @property
    def is_online(self) -> bool:
        """
        判断当前是否处于“在线”状态。

        在线状态包括:
        - LOGGED_IN: 刚登录成功，虽然还没发心跳，但在逻辑上已在线。
        - HEARTBEAT: 心跳正常维持中。

        该属性通常用于外部守护进程 (Daemon) 判断是否需要执行自动重连。

        Returns:
            bool: 如果在线返回 True。
        """
        return self.status in (CoreStatus.LOGGED_IN, CoreStatus.HEARTBEAT)
