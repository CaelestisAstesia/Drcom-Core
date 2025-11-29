# src/drcom_core/network.py
"""
Dr.COM 核心库 - 网络模块 (Network)

封装 UDP Socket 的创建、绑定、发送和接收逻辑。
该模块屏蔽了底层 Socket 的复杂性，向策略层提供纯粹的 bytes 收发接口。
"""

import logging
import socket
from typing import Tuple

from .config import DrcomConfig
from .exceptions import NetworkError

logger = logging.getLogger(__name__)


class NetworkClient:
    """
    封装 UDP 套接字操作的客户端。

    负责维护一个长生命周期的 UDP Socket，处理 bind、sendto、recvfrom 等底层操作。
    同时负责将 socket 异常转化为库内部的 NetworkError。
    """

    def __init__(self, config: DrcomConfig):
        """
        初始化网络客户端并绑定端口。

        Args:
            config (DrcomConfig): 配置对象，提供 bind_ip 和 server_port。

        Raises:
            NetworkError: 如果端口绑定失败。
        """
        self.config = config
        self.sock: socket.socket | None = None
        self._bind_socket()

    def _bind_socket(self) -> None:
        """
        [Internal] 创建并绑定 UDP Socket。

        执行步骤:
        1. 创建 AF_INET, SOCK_DGRAM 套接字。
        2. 设置 SO_REUSEADDR 允许端口复用 (对快速重启至关重要)。
        3. 绑定到指定的本地 IP 和端口 (通常是 61440)。
        4. 设置为阻塞模式 (超时由后续操作控制)。

        Raises:
            NetworkError: 绑定失败时抛出。
        """
        # Dr.COM 客户端通常需要绑定固定的源端口 (如 61440)
        # 否则服务器可能拒绝响应
        bind_addr = (self.config.bind_ip, self.config.server_port)

        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

            # 设置端口复用，避免程序崩溃重启后出现 "Address already in use" 错误
            # 这在开发调试和系统服务自动重启时非常有用
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            self.sock.bind(bind_addr)

            # 默认设为阻塞模式，具体的读写超时由 receive 方法中的 settimeout 控制
            self.sock.setblocking(True)

            logger.debug(f"Socket 绑定成功: {bind_addr}")

        except Exception as e:
            # [Enhanced] 捕获所有绑定阶段的错误 (包括 PermissionError, OSError)
            # 如果绑定失败，确保释放资源
            self.close()
            raise NetworkError(f"端口绑定失败 {bind_addr}: {e}") from e

    def send(self, packet: bytes) -> None:
        """
        发送 UDP 数据包到配置的目标服务器。

        Args:
            packet (bytes): 要发送的二进制数据。

        Raises:
            NetworkError: Socket 未初始化或发送失败 (如网络不可达)。
        """
        if not self.sock:
            raise NetworkError("Socket 未初始化")

        target = (self.config.server_address, self.config.server_port)
        try:
            self.sock.sendto(packet, target)
        except OSError as e:
            # [Enhanced] 捕获 Network is unreachable 等系统级 IO 错误
            raise NetworkError(f"发送失败 (IO): {e}") from e
        except Exception as e:
            raise NetworkError(f"发送失败 (Unknown): {e}") from e

    def receive(self, timeout: float) -> Tuple[bytes, Tuple[str, int]]:
        """
        接收 UDP 数据包。

        该方法是阻塞的，直到收到数据或超时。

        Args:
            timeout (float): 等待超时时间 (秒)。

        Returns:
            Tuple[bytes, Tuple[str, int]]:
                - bytes: 接收到的数据内容。
                - Tuple[str, int]: 发送方的地址信息 (IP, Port)。

        Raises:
            NetworkError: 接收超时或 Socket 错误。
        """
        if not self.sock:
            raise NetworkError("Socket 未初始化")

        try:
            # 动态设置当次接收的超时时间
            self.sock.settimeout(timeout)

            # 1024 字节 (1KB) 足够容纳最大的 Dr.COM 协议包 (通常 < 500B)
            data, address = self.sock.recvfrom(1024)
            return data, address

        except socket.timeout:
            # 超时是预期内的行为（例如发包后没收到回复），不需要 log error
            # 抛出异常由上层策略层的重试逻辑处理
            raise NetworkError(f"接收超时 ({timeout}s)") from None

        except OSError as e:
            # 捕获 WinError 10054 (远程主机强迫关闭连接) 等
            raise NetworkError(f"接收错误 (IO): {e}") from e

        except Exception as e:
            raise NetworkError(f"接收错误 (Unknown): {e}") from e

    def close(self) -> None:
        """
        显式关闭 Socket 资源。

        可以被多次安全调用。
        """
        if self.sock:
            try:
                self.sock.close()
            except socket.error:
                pass
            finally:
                self.sock = None
                logger.debug("Socket 已关闭")

    def __enter__(self):
        """
        支持上下文管理协议。
        """
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """
        支持上下文管理协议。
        """
        self.close()

    def __del__(self) -> None:
        """
        确保对象销毁时释放 Socket 资源。
        """
        self.close()
