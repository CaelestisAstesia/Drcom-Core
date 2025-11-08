# src/drcom_core/protocols/base.py
"""
Dr.COM 核心库 - 协议策略接口 (Strategy Interface)

定义所有协议版本（D, P, X...）必须遵守的抽象基类 (ABC)。
DrcomCore (引擎) 将调用这些标准接口，而不关心具体实现。
"""

import abc
import logging
from typing import TYPE_CHECKING

# 使用 TYPE_CHECKING 块来避免循环导入
# 这些类型仅用于类型提示，不会在运行时导入
if TYPE_CHECKING:
    from ..config import DrcomConfig
    from ..network import NetworkClient
    from ..state import DrcomState

logger = logging.getLogger(__name__)


class BaseProtocol(abc.ABC):
    """
    协议策略的抽象基类。
    """

    def __init__(
        self,
        config: "DrcomConfig",
        state: "DrcomState",
        net_client: "NetworkClient",
    ):
        """
        初始化策略。

        Args:
            config: 只读的配置对象。
            state: 可读/写的状态对象。
            net_client: 用于收发数据的网络客户端。
        """
        self.config = config
        self.state = state
        self.net_client = net_client
        self.logger = logging.getLogger(
            f"{__name__}.{self.__class__.__name__}"
        )  # e.g., ...protocols.base.D_Protocol
        self.logger.info("协议策略已初始化。")

    @abc.abstractmethod
    def login(self) -> bool:
        """
        执行完整的登录流程。
        必须在成功时设置 self.state.login_success = True。

        Returns:
            bool: 登录是否成功。
        """
        raise NotImplementedError

    @abc.abstractmethod
    def keep_alive(self) -> bool:
        """
        执行*一次*心跳循环。
        引擎 (DrcomCore) 将负责循环调用此方法和处理休眠。

        Returns:
            bool: 心跳是否成功。如果返回 False，引擎将停止心跳循环。
        """
        raise NotImplementedError

    @abc.abstractmethod
    def logout(self) -> None:
        """
        执行登出流程。
        必须在完成后重置 self.state。
        """
        raise NotImplementedError
