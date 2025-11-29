# src/drcom_core/network.py
"""
Dr.COM 核心库 - 网络模块 (Network) [Asyncio Edition]

封装 UDP Socket 的创建、绑定、发送和接收逻辑。
该模块屏蔽了底层 Socket 的复杂性，向策略层提供纯粹的 bytes 收发接口。
"""

import asyncio
import logging
from typing import Optional, Tuple, cast

from .config import DrcomConfig
from .exceptions import NetworkError

logger = logging.getLogger(__name__)


class DrcomUdpProtocol(asyncio.DatagramProtocol):
    """
    asyncio UDP 协议适配器。
    将回调风格的 data_received 转换为 Queue 模式，供上层 await 使用。
    """

    def __init__(self):
        self.transport: Optional[asyncio.DatagramTransport] = None
        # 队列存储 (data, addr) 元组
        self.queue: asyncio.Queue[Tuple[bytes, Tuple[str, int]]] = asyncio.Queue()
        self.error: Optional[Exception] = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = cast(asyncio.DatagramTransport, transport)
        logger.debug("UDP Transport 已建立")

    def datagram_received(self, data: bytes, addr: Tuple[str, int]) -> None:
        # 将收到的数据放入队列，非阻塞
        self.queue.put_nowait((data, addr))

    def error_received(self, exc: Exception) -> None:
        logger.error(f"UDP 错误: {exc}")
        self.error = exc
        # 可以选择是否要在 queue 中放入错误信号，或者在 receive 时检查

    def connection_lost(self, exc: Optional[Exception]) -> None:
        if exc:
            logger.warning(f"UDP 连接断开: {exc}")
        self.transport = None


class NetworkClient:
    """
    封装 asyncio UDP 操作的客户端。
    """

    def __init__(self, config: DrcomConfig):
        self.config = config
        self.protocol: Optional[DrcomUdpProtocol] = None
        self.transport: Optional[asyncio.DatagramTransport] = None

    async def connect(self) -> None:
        """
        初始化 UDP Endpoint。
        替代原有的 _bind_socket。
        """
        loop = asyncio.get_running_loop()
        bind_addr = (self.config.bind_ip, self.config.server_port)

        try:
            # reuse_port=True 在某些系统上能避免端口占用错误，但 Windows 支持有限
            # 这里主要依靠 asyncio 自身的管理
            transport, protocol = await loop.create_datagram_endpoint(
                lambda: DrcomUdpProtocol(),
                local_addr=bind_addr,
                reuse_address=True,  # 对应 SO_REUSEADDR
            )
            self.transport = cast(asyncio.DatagramTransport, transport)
            self.protocol = cast(DrcomUdpProtocol, protocol)
            logger.debug(f"Async Socket 绑定成功: {bind_addr}")

        except Exception as e:
            await self.close()
            raise NetworkError(f"端口绑定失败 {bind_addr}: {e}") from e

    async def send(self, packet: bytes) -> None:
        """
        发送 UDP 数据包。
        虽然 UDP 发送通常是非阻塞的，但为了接口统一和未来的扩展性，这里保持 async。
        """
        if not self.transport or self.transport.is_closing():
            # 尝试自动重连或报错
            if not self.transport:
                # 如果从未连接过，尝试连接
                await self.connect()
            else:
                raise NetworkError("Transport 已关闭")

        target = (self.config.server_address, self.config.server_port)
        try:
            # sendto 是同步非阻塞的
            self.transport.sendto(packet, target)
        except Exception as e:
            raise NetworkError(f"发送失败: {e}") from e

    async def receive(self, timeout: float) -> Tuple[bytes, Tuple[str, int]]:
        """
        接收 UDP 数据包 (Async)。

        使用 asyncio.wait_for 实现超时控制。
        """
        if not self.protocol:
            raise NetworkError("Protocol 未初始化")

        try:
            # 从队列中等待获取数据
            return await asyncio.wait_for(self.protocol.queue.get(), timeout=timeout)

        except asyncio.TimeoutError:
            # 超时不需要 log error，交由上层处理
            raise NetworkError(f"接收超时 ({timeout}s)") from None
        except Exception as e:
            raise NetworkError(f"接收错误: {e}") from e

    async def close(self) -> None:
        """关闭 Transport"""
        if self.transport:
            self.transport.close()
            self.transport = None
            logger.debug("UDP Transport 已关闭")

    async def __aenter__(self):
        await self.connect()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()

    def __del__(self):
        # 异步资源很难在 __del__ 中清理，主要依赖显式 close
        pass
