# src/drcom_core/protocols/base.py
"""
Dr.COM 协议基类 (Base Protocol)

所有协议策略 (Strategy) 都必须继承此类，并实现 login/keep_alive/logout 接口。
"""

import abc
import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..config import DrcomConfig
    from ..network import NetworkClient
    from ..state import DrcomState


class BaseProtocol(abc.ABC):
    """
    协议策略抽象基类。
    """

    def __init__(
        self,
        config: "DrcomConfig",
        state: "DrcomState",
        net_client: "NetworkClient",
    ):
        self.config = config
        self.state = state
        self.net_client = net_client
        self.logger = logging.getLogger(self.__class__.__name__)

    @abc.abstractmethod
    def login(self) -> bool:
        """执行登录流程，成功返回 True"""
        raise NotImplementedError

    @abc.abstractmethod
    def keep_alive(self) -> bool:
        """执行一次心跳循环，成功返回 True"""
        raise NotImplementedError

    @abc.abstractmethod
    def logout(self) -> None:
        """执行登出流程"""
        raise NotImplementedError
