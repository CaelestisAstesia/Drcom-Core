"""
Dr.COM 核心引擎 (Core Engine)

职责：
1. 资源组装：State + Network + Config。
2. 策略分发。
3. 生命周期：Login -> Heartbeat -> Stop。
"""

import asyncio
import logging
from collections.abc import Callable

from .config import DrcomConfig
from .exceptions import AuthError, ConfigError, DrcomError, NetworkError
from .network import NetworkClient
from .protocols.base import BaseProtocol
from .protocols.d_series import Protocol520D
from .state import CoreStatus, DrcomState

logger = logging.getLogger(__name__)


class DrcomCore:
    """Dr.COM 认证核心引擎 (Async)。"""

    def __init__(
        self,
        config: DrcomConfig,
        status_callback: Callable[[CoreStatus, str], None] | None = None,
    ) -> None:
        """初始化核心引擎。

        Args:
            config: 全局配置对象。
            status_callback: 状态变更回调函数 (必须是非阻塞的)。

        Raises:
            ConfigError: 组件初始化失败（如网络客户端创建失败）。
        """
        self.config = config
        self._callback = status_callback

        try:
            self.state = DrcomState()
            # NetworkClient 只是初始化，真正的连接在 connect 或 login 时建立
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
            bool: 登录成功返回 True，失败返回 False。

        Raises:
            AuthError: 认证被服务器明确拒绝。
        """
        self._update_status(CoreStatus.CONNECTING, "正在登录...")

        if self.state.is_online:
            logger.warning("当前已在线，跳过登录")
            return True

        # 确保网络连接已建立
        if not self.net_client.transport:
            await self.net_client.connect()

        try:
            success = await self.protocol.login()
            if success:
                self._update_status(CoreStatus.LOGGED_IN, "登录成功")
                return True
            else:
                self._update_status(CoreStatus.OFFLINE, "登录失败 (未知原因)")
                return False

        except AuthError as ae:
            self.state.last_error = str(ae)
            self._update_status(CoreStatus.OFFLINE, f"认证被拒绝: {ae}")
            raise

        except (NetworkError, DrcomError) as e:
            self.state.last_error = str(e)
            self._update_status(CoreStatus.ERROR, f"登录异常: {e}")
            return False

    async def start_heartbeat(self) -> None:
        """启动后台心跳任务。

        该方法会阻塞直到心跳 Loop 真正开始运行（进入 HEARTBEAT 状态），
        确保调用返回时，后台任务已就绪。
        """
        if self._heartbeat_task and not self._heartbeat_task.done():
            return

        if self.state.status != CoreStatus.LOGGED_IN:
            logger.error("无法启动心跳：未处于登录成功状态")
            return

        self._stop_event.clear()

        # 创建一个 Event 用于同步启动状态
        started_event = asyncio.Event()

        # 将 Event 传递给 loop
        self._heartbeat_task = asyncio.create_task(
            self._heartbeat_loop(started_event), name="DrcomHeartbeatTask"
        )

        # 等待 Loop 发出“我已启动”的信号
        await started_event.wait()

    async def stop(self) -> None:
        """停止引擎。

        1. 停止心跳任务。
        2. 发送注销包。
        3. 关闭网络连接。
        必须 await 以确保资源清理完成。
        """
        # 1. 触发停止信号
        self._stop_event.set()

        # 2. 取消并等待心跳任务
        if self._heartbeat_task and not self._heartbeat_task.done():
            self._heartbeat_task.cancel()
            try:
                await self._heartbeat_task
            except asyncio.CancelledError:
                pass
            finally:
                self._heartbeat_task = None

        # 3. 尝试注销 (Await)
        if self.state.is_online:
            try:
                await self.protocol.logout()
            except Exception as e:
                logger.warning(f"注销过程异常: {e}")

        # 4. 关闭网络资源 (Await)
        await self.net_client.close()

        self._update_status(CoreStatus.OFFLINE, "已停止")

    async def _heartbeat_loop(self, started_event: asyncio.Event | None = None) -> None:
        """[Internal] 心跳协程循环。"""
        self._update_status(CoreStatus.HEARTBEAT, "心跳维持中")

        if started_event:
            started_event.set()

        try:
            while not self._stop_event.is_set():
                try:
                    # 执行一次异步心跳
                    if not await self.protocol.keep_alive():
                        logger.error("心跳检测失败 (Protocol return False)")
                        break
                except Exception as e:
                    logger.error(f"心跳任务发生异常: {e}")
                    break

                # 使用 asyncio.sleep 等待，支持被 cancel 唤醒
                try:
                    await asyncio.wait_for(self._stop_event.wait(), timeout=20.0)
                except asyncio.TimeoutError:
                    # 超时意味着没有收到停止信号，继续下一次心跳
                    continue

        except asyncio.CancelledError:
            logger.debug("心跳任务被取消")
            raise  # 重新抛出以便 task 状态正确

        if not self._stop_event.is_set():
            self._update_status(CoreStatus.OFFLINE, "心跳丢失，已掉线")

    def _update_status(self, status: CoreStatus, msg: str) -> None:
        """更新内部状态并触发回调。"""
        self.state.status = status
        logger.info(f"[{status.name}] {msg}")
        if self._callback:
            # 回调应尽量轻量，避免阻塞 Loop
            try:
                self._callback(status, msg)
            except Exception:
                pass
