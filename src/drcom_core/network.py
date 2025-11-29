"""
Dr.COM 核心库 - 网络模块 (Network)

封装 UDP Socket 的创建、绑定、发送和接收逻辑。
使用 asyncio.Queue 将底层回调转换为流式接口。
"""

import asyncio
import logging
from typing import cast

from .config import DrcomConfig
from .exceptions import NetworkError

logger = logging.getLogger(__name__)


class DrcomUdpProtocol(asyncio.DatagramProtocol):
    """asyncio UDP 协议适配器。"""

    def __init__(self) -> None:
        self.transport: asyncio.DatagramTransport | None = None
        # 使用限制大小的队列防止内存溢出
        self.queue: asyncio.Queue[tuple[bytes, tuple[str, int]] | Exception] = (
            asyncio.Queue(maxsize=128)
        )
        self.dropped_packets: int = 0

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = cast(asyncio.DatagramTransport, transport)
        logger.debug("UDP Transport 已建立")

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        """接收数据并放入队列。"""
        try:
            self.queue.put_nowait((data, addr))
        except asyncio.QueueFull:
            self.dropped_packets += 1
            if self.dropped_packets % 10 == 1:
                logger.warning(
                    f"UDP 接收队列已满，已丢弃 {self.dropped_packets} 个数据包。"
                )

    def error_received(self, exc: Exception) -> None:
        """处理 UDP 错误。"""
        logger.error(f"UDP 错误: {exc}")
        self._propagate_error(exc)

    def connection_lost(self, exc: Exception | None) -> None:
        """处理连接断开。"""
        if exc:
            logger.warning(f"UDP 连接断开: {exc}")
            self._propagate_error(exc)
        else:
            logger.debug("UDP 连接已正常关闭")
            self._propagate_error(NetworkError("连接已关闭"))
        self.transport = None

    def _propagate_error(self, exc: Exception) -> None:
        """将底层错误立即传播给上层消费者。"""
        try:
            self.queue.put_nowait(exc)
        except asyncio.QueueFull:
            try:
                self.queue.get_nowait()
                self.queue.put_nowait(exc)
            except Exception:
                pass


class NetworkClient:
    """封装 asyncio UDP 操作的客户端。"""

    def __init__(self, config: DrcomConfig) -> None:
        self.config = config
        self.protocol: DrcomUdpProtocol | None = None
        self.transport: asyncio.DatagramTransport | None = None

    async def connect(self) -> None:
        """初始化 UDP Endpoint。"""
        loop = asyncio.get_running_loop()
        bind_addr = (self.config.bind_ip, self.config.server_port)

        try:
            transport, protocol = await loop.create_datagram_endpoint(
                lambda: DrcomUdpProtocol(),
                local_addr=bind_addr,
            )
            self.transport = cast(asyncio.DatagramTransport, transport)
            self.protocol = cast(DrcomUdpProtocol, protocol)
            logger.debug(f"Async Socket 绑定成功: {bind_addr}")

        except Exception as e:
            await self.close()
            # 这里的异常会被上层捕获，Prober 可能会将其误报为超时，
            # 但在 Login 阶段会正确显示为 "端口绑定失败"。
            raise NetworkError(f"端口绑定失败 {bind_addr}: {e}") from e

    async def send(self, packet: bytes) -> None:
        """发送 UDP 数据包。"""
        if not self.transport or self.transport.is_closing():
            if not self.transport:
                await self.connect()
            else:
                raise NetworkError("Transport 已关闭")

        assert self.transport is not None

        target = (self.config.server_address, self.config.server_port)
        try:
            self.transport.sendto(packet, target)
        except Exception as e:
            raise NetworkError(f"发送失败: {e}") from e

    async def receive(self, timeout: float) -> tuple[bytes, tuple[str, int]]:
        """接收 UDP 数据包 (Async)。"""
        if not self.protocol:
            raise NetworkError("Protocol 未初始化")

        try:
            item = await asyncio.wait_for(self.protocol.queue.get(), timeout=timeout)

            if isinstance(item, Exception):
                raise item

            return item

        except asyncio.TimeoutError:
            raise NetworkError(f"接收超时 ({timeout}s)") from None
        except NetworkError:
            raise
        except Exception as e:
            raise NetworkError(f"接收错误: {e}") from e

    async def close(self) -> None:
        """关闭 Transport。"""
        if self.transport:
            self.transport.close()
            self.transport = None
            logger.debug("UDP Transport 已关闭")

    async def __aenter__(self) -> "NetworkClient":
        await self.connect()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self.close()
