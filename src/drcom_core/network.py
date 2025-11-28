# src/drcom_core/network.py
"""
Dr.COM 核心库 - 网络模块 (Network)

封装 UDP Socket 的创建、绑定、发送和接收逻辑。
"""

import logging
import socket
from typing import Tuple

from .config import DrcomConfig
from .exceptions import NetworkError

logger = logging.getLogger(__name__)


class NetworkClient:
    """
    封装 UDP 套接字操作。
    """

    def __init__(self, config: DrcomConfig):
        self.config = config
        self.sock: socket.socket | None = None
        self._bind_socket()

    def _bind_socket(self) -> None:
        """创建并绑定 Socket"""
        bind_addr = (self.config.bind_ip, self.config.server_port)

        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

            # 设置端口复用，避免 "Address already in use" 错误
            # 这在快速重启或调试时非常有用
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            self.sock.bind(bind_addr)
            # 默认设为阻塞模式，超时由 receive 方法控制
            self.sock.setblocking(True)

            logger.debug(f"Socket 绑定成功: {bind_addr}")

        except socket.error as e:
            self.close()
            raise NetworkError(f"端口绑定失败 {bind_addr}: {e}") from e

    def send(self, packet: bytes) -> None:
        """
        发送 UDP 数据包到目标服务器。
        """
        if not self.sock:
            raise NetworkError("Socket 未初始化")

        target = (self.config.server_address, self.config.server_port)
        try:
            self.sock.sendto(packet, target)
        except socket.error as e:
            raise NetworkError(f"发送失败: {e}") from e

    def receive(self, timeout: float) -> Tuple[bytes, Tuple[str, int]]:
        """
        接收 UDP 数据包。

        Args:
            timeout: 超时时间 (秒)。

        Returns:
            (data, (ip, port)): 接收到的数据和来源地址。

        Raises:
            NetworkError: 超时或 Socket 错误。
        """
        if not self.sock:
            raise NetworkError("Socket 未初始化")

        try:
            self.sock.settimeout(timeout)
            data, address = self.sock.recvfrom(1024)  # 1KB 足够 Dr.COM 使用
            return data, address

        except socket.timeout:
            # 超时是预期内的行为（例如发包后没收到回复），不需要 log error
            # 抛出异常由上层重试逻辑处理
            raise NetworkError(f"接收超时 ({timeout}s)") from None

        except socket.error as e:
            raise NetworkError(f"接收错误: {e}") from e

    def close(self) -> None:
        """关闭 Socket"""
        if self.sock:
            try:
                self.sock.close()
            except socket.error:
                pass
            finally:
                self.sock = None
                logger.debug("Socket 已关闭")

    def __del__(self) -> None:
        self.close()
