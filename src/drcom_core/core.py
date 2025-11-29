"""
Dr.COM 核心引擎 (Core Engine)

职责：
1. 资源组装：State + Network + Config。
2. 策略分发。
3. 生命周期：Login -> Heartbeat -> Stop。
"""

import asyncio
import inspect
import logging
from collections.abc import Awaitable, Callable
from typing import Any

from .config import DrcomConfig
from .exceptions import AuthError, ConfigError, DrcomError, NetworkError
from .network import NetworkClient
from .protocols.base import BaseProtocol
from .protocols.d_series import Protocol520D
from .state import CoreStatus, DrcomState

logger = logging.getLogger(__name__)

# 定义回调函数类型别名：支持同步或异步函数
StatusCallback = Callable[[CoreStatus, str], Any | Awaitable[Any]]


class DrcomCore:
    """Dr.COM 认证核心引擎 (Async)。"""

    def __init__(
        self,
        config: DrcomConfig,
        status_callback: StatusCallback | None = None,
    ) -> None:
        """初始化核心引擎。

        Args:
            config: 全局配置对象。
            status_callback: 状态变更回调函数 (支持 async def)。
        """
        self.config = config
        self._callback = status_callback

        try:
            self.state = DrcomState()
            self.net_client = NetworkClient(config)
        except Exception as e:
            raise ConfigError(f"组件初始化失败: {e}") from e

        self.protocol: BaseProtocol
        self._load_strategy()

        self._stop_event = asyncio.Event()
        self._heartbeat_task: asyncio.Task | None = None

        self._update_status(CoreStatus.IDLE, "引擎已就绪")

    def _load_strategy(self) -> None:
        """加载并实例化对应的协议策略。"""
        ver = self.config.protocol_version
        if ver == "D":
            self.protocol = Protocol520D(self.config, self.state, self.net_client)
        else:
            raise ConfigError(f"不支持的协议版本: {ver}")

    async def login(self) -> bool:
        """执行登录流程。

        外部调用必须使用 await core.login()。

        Returns:
            bool: 登录成功返回 True，失败返回 False (仅限未知逻辑错误)。

        Raises:
            AuthError: 认证被拒绝 (业务层面的失败)。
            NetworkError: 网络通信异常 (IO层面的失败)。
            DrcomError: 其他不可恢复的错误。
        """
        self._update_status(CoreStatus.CONNECTING, "正在登录...")

        if self.state.is_online:
            logger.warning("当前已在线，跳过登录")
            return True

        if not self.net_client.transport:
            await self.net_client.connect()

        try:
            success = await self.protocol.login()
            if success:
                self._update_status(CoreStatus.LOGGED_IN, "登录成功")
                return True
            else:
                # 协议层返回 False 通常意味着逻辑失败但未抛异常 (如 Challenge 无响应)
                self._update_status(CoreStatus.OFFLINE, "登录失败 (未知原因)")
                return False

        except AuthError as ae:
            self.state.last_error = str(ae)
            self._update_status(CoreStatus.OFFLINE, f"认证被拒绝: {ae}")
            raise

        except (NetworkError, DrcomError) as e:
            # [Fix C-01] 不再吞没异常返回 False，而是记录状态后向上冒泡。
            # 这允许上层调用者决定是重试 (NetworkError) 还是报错退出。
            self.state.last_error = str(e)
            self._update_status(CoreStatus.ERROR, f"登录异常: {e}")
            raise

    async def step(self) -> bool:
        """[Dual Mode API] 执行单次心跳步进。

        供外部 Event Loop (如 Daemon) 精细控制心跳时机。
        如果处于非在线状态，调用此方法无效（返回 False）。

        Returns:
            bool: 心跳执行成功返回 True，失败或状态不正确返回 False。
        """
        if not self.state.is_online:
            return False

        try:
            if await self.protocol.keep_alive():
                return True
            else:
                logger.error("心跳检测失败 (Protocol return False)")
                return False
        except Exception as e:
            logger.error(f"心跳步进异常: {e}")
            return False

    async def start_heartbeat(self) -> None:
        """[Dual Mode API] 启动内置的后台心跳任务。

        适用于简单脚本或不需要外部接管 Loop 的场景。
        会阻塞直到心跳 Loop 真正开始运行。
        """
        if self._heartbeat_task and not self._heartbeat_task.done():
            return

        if self.state.status != CoreStatus.LOGGED_IN:
            logger.error("无法启动心跳：未处于登录成功状态")
            return

        self._stop_event.clear()
        started_event = asyncio.Event()

        self._heartbeat_task = asyncio.create_task(
            self._heartbeat_loop(started_event), name="DrcomHeartbeatTask"
        )
        await started_event.wait()

    async def stop(self) -> None:
        """停止引擎。"""
        self._stop_event.set()

        if self._heartbeat_task and not self._heartbeat_task.done():
            self._heartbeat_task.cancel()
            try:
                await self._heartbeat_task
            except asyncio.CancelledError:
                pass
            finally:
                self._heartbeat_task = None

        if self.state.is_online:
            try:
                await self.protocol.logout()
            except Exception as e:
                logger.warning(f"注销过程异常: {e}")

        await self.net_client.close()
        self._update_status(CoreStatus.OFFLINE, "已停止")

    async def _heartbeat_loop(self, started_event: asyncio.Event | None = None) -> None:
        """[Internal] 内置心跳循环。"""
        self._update_status(CoreStatus.HEARTBEAT, "心跳维持中")

        if started_event:
            started_event.set()

        try:
            while not self._stop_event.is_set():
                # 复用 step() 逻辑
                if not await self.step():
                    break

                # 等待下一次心跳或停止信号
                try:
                    await asyncio.wait_for(self._stop_event.wait(), timeout=20.0)
                except asyncio.TimeoutError:
                    continue

        except asyncio.CancelledError:
            logger.debug("心跳任务被取消")
            raise

        if not self._stop_event.is_set():
            self._update_status(CoreStatus.OFFLINE, "心跳丢失，已掉线")

    def _update_status(self, status: CoreStatus, msg: str) -> None:
        """更新内部状态并异步触发回调。"""
        self.state.status = status
        logger.info(f"[{status.name}] {msg}")

        if self._callback:
            try:
                # [Fix Callback] 智能识别回调类型
                if inspect.iscoroutinefunction(self._callback):
                    # 如果是 async def 定义的协程，创建 Task 执行
                    asyncio.create_task(self._callback(status, msg))  # type: ignore
                else:
                    # 如果是同步函数，使用 call_soon 调度
                    loop = asyncio.get_running_loop()
                    loop.call_soon(self._callback, status, msg)
            except RuntimeError:
                # 应对 loop 尚未运行或已关闭的边缘情况
                pass
