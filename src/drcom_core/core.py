# src/drcom_core/core.py
"""
Dr.COM 核心引擎 (Core Engine) - v1.0.0

这是外部调用者 (CLI/GUI) 唯一需要交互的类。
它负责：
1. 资源组装：State + Network + Config。
2. 策略分发：根据 config.protocol_version 选择 D版/P版 策略。
3. 生命周期：Login -> Daemon Thread -> Logout。
"""

import logging
import threading
from collections.abc import Callable
from typing import Optional

from .config import DrcomConfig
from .exceptions import AuthError, ConfigError, DrcomError, NetworkError
from .network import NetworkClient
from .protocols.base import BaseProtocol
from .protocols.d_series import Protocol520D
from .state import CoreStatus, DrcomState

logger = logging.getLogger(__name__)


class DrcomCore:
    """
    Dr.COM 认证核心引擎 (Facade)。

    该类封装了底层的协议策略、网络通信和状态维护，为上层应用提供简单的
    login/start_heartbeat/stop 接口。它不处理具体的 UI 交互，但通过回调函数
    上报状态变更。
    """

    def __init__(
        self,
        config: DrcomConfig,
        status_callback: Optional[Callable[[CoreStatus, str], None]] = None,
    ) -> None:
        """
        初始化核心引擎。

        Args:
            config (DrcomConfig): 强类型配置对象，包含了账户、网络和协议参数。
            status_callback (Callable[[CoreStatus, str], None], optional):
                状态变更时的回调函数。
                参数为 (当前状态, 描述文本)。默认为 None。

        Raises:
            ConfigError: 如果网络组件初始化失败 (如 Bind IP 非法)。
        """
        self.config = config
        self._callback = status_callback

        # 1. 初始化基础组件
        try:
            self.state = DrcomState()
            self.net_client = NetworkClient(config)
        except Exception as e:
            raise ConfigError(f"网络组件初始化失败: {e}") from e

        # 2. 加载协议策略 (Strategy Pattern)
        self.protocol: BaseProtocol
        self._load_strategy()

        # 3. 线程控制 (Thread Control)
        # 使用 Event 来优雅地停止心跳线程
        self._stop_event = threading.Event()
        self._heartbeat_thread: Optional[threading.Thread] = None

        self._update_status(CoreStatus.IDLE, "引擎已就绪")

    def _load_strategy(self) -> None:
        """
        [Internal] 根据配置加载对应的协议策略实现。

        Raises:
            ConfigError: 如果配置了不支持的协议版本。
        """
        ver = self.config.protocol_version

        if ver == "D":
            self.protocol = Protocol520D(self.config, self.state, self.net_client)
        # Future: P 版 (PPPoE) 支持
        # elif ver == "P":
        #     self.protocol = ProtocolPPPoE(...)
        else:
            raise ConfigError(f"不支持的协议版本: {ver}")

    def login(self) -> bool:
        """
        [Sync API] 执行同步登录流程。

        该方法会阻塞直到登录成功、失败或超时。

        Returns:
            bool: 登录成功返回 True。
                  如果由于网络问题或未知错误导致登录失败，返回 False。

        Raises:
            AuthError: 如果发生明确的认证拒绝 (如密码错误、欠费、IP 限制)。
                       这通常意味着用户配置错误或账号问题，需要上层 UI 显式提示用户。
        """
        self._update_status(CoreStatus.CONNECTING, "正在登录...")

        # 防止重复登录
        if self.state.is_online:
            logger.warning("当前已在线，跳过登录")
            return True

        try:
            success = self.protocol.login()
            if success:
                self._update_status(CoreStatus.LOGGED_IN, "登录成功")
                return True
            else:
                # 协议层返回 False 通常意味着逻辑失败但未抛异常 (如 Challenge 无响应)
                self._update_status(CoreStatus.OFFLINE, "登录失败 (未知原因)")
                return False

        except AuthError as ae:
            # Case 1: 业务拒绝 (密码错误等)
            # 必须抛出给上层，因为这通常不需要重试，而需要用户干预
            self.state.last_error = str(ae)
            self._update_status(CoreStatus.OFFLINE, f"认证被拒绝: {ae}")
            raise

        except (NetworkError, DrcomError) as e:
            # Case 2: 技术错误 (网络不通、超时等)
            # 记录错误但不 Crash，返回 False 供上层决定是否重试
            self.state.last_error = str(e)
            self._update_status(CoreStatus.ERROR, f"登录异常: {e}")
            return False

    def start_heartbeat(self) -> None:
        """
        [Async API] 启动后台心跳守护线程。

        前提：必须先调用 login() 并返回成功 (CoreStatus.LOGGED_IN)。
        如果线程已在运行，此调用将被忽略。
        """
        if self._heartbeat_thread and self._heartbeat_thread.is_alive():
            return

        if self.state.status != CoreStatus.LOGGED_IN:
            logger.error("无法启动心跳：未处于登录成功状态")
            return

        self._stop_event.clear()
        self._heartbeat_thread = threading.Thread(
            target=self._heartbeat_loop, name="DrcomHeartbeat", daemon=True
        )
        self._heartbeat_thread.start()

    def stop(self) -> None:
        """
        [Sync API] 停止引擎。

        流程：
        1. 发送停止信号给心跳线程。
        2. 等待心跳线程结束。
        3. 发送协议注销包 (Logout)。
        4. 清理网络资源。
        """
        # 1. 停止线程
        self._stop_event.set()
        if self._heartbeat_thread:
            # 给线程一点时间优雅退出
            self._heartbeat_thread.join(timeout=2.0)

        # 2. 尝试注销 (Best Effort)
        if self.state.is_online:
            try:
                self.protocol.logout()
            except Exception as e:
                logger.warning(f"注销过程异常: {e}")

        # 3. 清理状态
        # 注意：NetworkClient 通常不需要显式 close，这里主要重置状态
        self._update_status(CoreStatus.OFFLINE, "已停止")

    def _heartbeat_loop(self) -> None:
        """
        [Internal] 心跳线程主循环。

        每隔 20 秒执行一次心跳。如果心跳失败或发生异常，将退出循环并将状态置为 OFFLINE。
        """
        self._update_status(CoreStatus.HEARTBEAT, "心跳维持中")

        while not self._stop_event.is_set():
            try:
                # 执行一次完整的心跳交互 (KA1 + KA2 Sequence)
                if not self.protocol.keep_alive():
                    logger.error("心跳检测失败 (Protocol return False)")
                    break
            except Exception as e:
                logger.error(f"心跳线程发生未捕获异常: {e}")
                break

            # 等待 20 秒 (使用 wait 可被 _stop_event.set() 立即唤醒，无需死等)
            if self._stop_event.wait(timeout=20.0):
                break

        # 循环结束意味着掉线或主动停止
        if not self._stop_event.is_set():
            # 非主动停止导致的循环结束，即为掉线
            self._update_status(CoreStatus.OFFLINE, "心跳丢失，已掉线")

    def _update_status(self, status: CoreStatus, msg: str) -> None:
        """
        [Internal] 更新内部状态并触发回调。

        Args:
            status (CoreStatus): 新的状态枚举。
            msg (str): 状态描述消息。
        """
        self.state.status = status
        logger.info(f"[{status.name}] {msg}")
        if self._callback:
            try:
                self._callback(status, msg)
            except Exception:
                # 即使回调报错也不应影响核心流程
                pass
