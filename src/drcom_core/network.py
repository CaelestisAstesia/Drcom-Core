# src/drcom_core/network.py
"""
Dr.COM 核心库 - 网络模块 (Network) [Asyncio Edition]

封装 UDP Socket 的创建、绑定、发送和接收逻辑。
该模块屏蔽了底层 Socket 的复杂性，向策略层提供纯粹的 bytes 收发接口。
"""

import asyncio
import logging
from typing import Optional, Tuple, Union, cast

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
        # [Fix A] 设置 maxsize=128，防止队列无限制增长导致 OOM
        # 队列内容可以是数据元组，也可以是异常对象（用于快速失败）
        self.queue: asyncio.Queue[Union[Tuple[bytes, Tuple[str, int]], Exception]] = (
            asyncio.Queue(maxsize=128)
        )

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = cast(asyncio.DatagramTransport, transport)
        logger.debug("UDP Transport 已建立")

    def datagram_received(self, data: bytes, addr: Tuple[str, int]) -> None:
        """接收数据并放入队列"""
        try:
            self.queue.put_nowait((data, addr))
        except asyncio.QueueFull:
            # 如果队列满了，丢弃最旧的包以腾出空间（Ring Buffer 策略），或者直接丢弃新包
            # 这里选择丢弃新包并记录警告，避免阻塞协议线程
            logger.warning("UDP 接收队列已满，丢弃数据包")

    def error_received(self, exc: Exception) -> None:
        """处理 UDP 错误"""
        logger.error(f"UDP 错误: {exc}")
        self._propagate_error(exc)

    def connection_lost(self, exc: Optional[Exception]) -> None:
        """处理连接断开"""
        if exc:
            logger.warning(f"UDP 连接断开: {exc}")
            self._propagate_error(exc)
        else:
            logger.debug("UDP 连接已正常关闭")
            # 正常关闭时也可以发一个信号，视业务逻辑而定，这里发送一个特定异常以中断 receive
            self._propagate_error(NetworkError("连接已关闭"))
        self.transport = None

    def _propagate_error(self, exc: Exception) -> None:
        """[Fix B] 辅助方法：将底层错误立即传播给上层消费者"""
        try:
            # 尝试放入队列，让 receive() 立即读到并抛出
            self.queue.put_nowait(exc)
        except asyncio.QueueFull:
            # 如果队列满了，为了保证错误能被传达，我们可以强行移除一个元素
            try:
                self.queue.get_nowait()
                self.queue.put_nowait(exc)
            except Exception:
                pass  # 极端情况忽略


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
        """
        loop = asyncio.get_running_loop()
        bind_addr = (self.config.bind_ip, self.config.server_port)

        try:
            # reuse_address=True 对应 SO_REUSEADDR
            transport, protocol = await loop.create_datagram_endpoint(
                lambda: DrcomUdpProtocol(),
                local_addr=bind_addr,
                reuse_address=True,
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
        """
        # 1. 确保连接可用
        if not self.transport or self.transport.is_closing():
            if not self.transport:
                await self.connect()
            else:
                raise NetworkError("Transport 已关闭")

        # [Change] 显式断言：此时 transport 绝不可能是 None
        # 这会让静态类型检查器闭嘴，且不需要后续多余的 if 判断
        assert self.transport is not None

        target = (self.config.server_address, self.config.server_port)
        try:
            # sendto 是同步非阻塞的，直接调用
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
            item = await asyncio.wait_for(self.protocol.queue.get(), timeout=timeout)

            # [Fix B] 检查取出来的是数据还是错误
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
        pass
