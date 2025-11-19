# src/drcom_core/network.py
"""
Dr.COM 核心库 - 网络模块

封装 UDP Socket 的创建、绑定、发送和接收逻辑。
这是核心库中唯一执行网络 I/O 的地方。
"""

import logging
import socket
from typing import Optional, Tuple

from .config import DrcomConfig
from .exceptions import NetworkError

logger = logging.getLogger(__name__)


class NetworkClient:
    """
    封装 UDP 套接字操作。
    """

    def __init__(self, config: DrcomConfig):
        """
        初始化并绑定套接字。

        Args:
            config: 已验证的 DrcomConfig 对象。

        Raises:
            NetworkError: 如果套接字创建或绑定失败。
        """
        self.config = config
        self.sock: Optional[socket.socket] = None
        bind_addr = (self.config.bind_ip, self.config.drcom_port)

        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            # 绑定到配置的 BIND_IP 和 认证端口
            # 这是 Dr.COM D 版的特殊要求，客户端和服务端在同一端口 (通常是 61440)
            self.sock.bind(bind_addr)
            # 只有在非常详细的调试模式下才设置非阻塞，一般保持阻塞+超时即可
            self.sock.setblocking(True)

            logger.info(f"网络客户端初始化成功，已绑定到 {bind_addr[0]}:{bind_addr[1]}")
        except socket.error as e:
            logger.critical(
                f"网络套接字初始化失败: {e} (端口 {self.config.drcom_port} 可能已被占用)"
            )
            raise NetworkError(f"端口绑定失败 {bind_addr}: {e}") from e

    def send(self, packet: bytes):
        """
        发送 UDP 数据包到配置的服务器。

        Args:
            packet: 要发送的原始字节包。

        Raises:
            NetworkError: 如果发送失败 (如网络不可达)。
        """
        if not self.sock:
            raise NetworkError("套接字未初始化或已关闭。")

        target = (self.config.server_address, self.config.drcom_port)
        try:
            self.sock.sendto(packet, target)
        except socket.error as e:
            logger.error(f"发送数据包到 {target} 失败: {e}")
            raise NetworkError(f"发送失败: {e}") from e

    def receive(self, timeout: float) -> Tuple[bytes, Tuple[str, int]]:
        """
        设置超时并等待接收 UDP 数据包。

        Args:
            timeout: 本次接收的超时时间（秒）。

        Returns:
            Tuple[bytes, Tuple[str, int]]: (接收到的数据, (来源IP, 来源端口))

        Raises:
            NetworkError: 如果超时或发生其他网络错误。
        """
        if not self.sock:
            raise NetworkError("套接字未初始化或已关闭。")

        try:
            self.sock.settimeout(timeout)
            data, address = self.sock.recvfrom(1024)  # 缓冲区大小 1024 字节
            return data, address
        except socket.timeout:
            logger.debug(f"接收数据超时 ({timeout}s)。")
            raise NetworkError(f"接收超时 ({timeout}s)") from None
        except socket.error as e:
            logger.error(f"接收数据时发生 Socket 错误: {e}")
            raise NetworkError(f"接收错误: {e}") from e

    def close(self):
        """
        关闭套接字。
        """
        if self.sock:
            try:
                self.sock.close()
            except socket.error as e:
                logger.warning(f"关闭套接字时发生错误 (可忽略): {e}")
            finally:
                self.sock = None
                logger.info("网络套接字已关闭。")
