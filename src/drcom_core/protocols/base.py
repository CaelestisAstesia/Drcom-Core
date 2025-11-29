"""
Dr.COM 协议基类 (Base Protocol)

定义所有 Dr.COM 协议策略必须实现的抽象接口。
"""

import abc
import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..config import DrcomConfig
    from ..network import NetworkClient
    from ..state import DrcomState


class BaseProtocol(abc.ABC):
    """协议策略抽象基类。

    所有具体的协议版本实现（如 D版、P版）都必须继承此类，
    并实现登录、心跳保活和注销的异步逻辑。
    """

    def __init__(
        self,
        config: "DrcomConfig",
        state: "DrcomState",
        net_client: "NetworkClient",
    ) -> None:
        """初始化协议基类。

        Args:
            config: 全局配置对象。
            state: 共享状态对象。
            net_client: 异步网络客户端实例。
        """
        self.config = config
        self.state = state
        self.net_client = net_client
        self.logger = logging.getLogger(self.__class__.__name__)

    @abc.abstractmethod
    async def login(self) -> bool:
        """[Abstract] 执行登录流程。

        Returns:
            bool: 登录成功返回 True，失败返回 False。

        Raises:
            AuthError: 认证被拒绝（密码错误、欠费等）。
            NetworkError: 网络通信异常。
            ProtocolError: 协议交互异常。
        """
        raise NotImplementedError

    @abc.abstractmethod
    async def keep_alive(self) -> bool:
        """[Abstract] 执行一次心跳循环。

        Returns:
            bool: 心跳成功返回 True，失败返回 False。
        """
        raise NotImplementedError

    @abc.abstractmethod
    async def logout(self) -> None:
        """[Abstract] 执行登出流程。

        清理服务器端会话和本地状态。
        """
        raise NotImplementedError
