# src/drcom_core/core.py
"""
Dr.COM 认证核心库 - 认证引擎 (Engine)

本模块定义了库的最高层级接口 `DrcomCore`。
它充当"编排者"的角色，协调网络客户端、状态机和具体的协议策略。
"""

import logging
import threading
from collections.abc import Callable

from .config import DrcomConfig
from .exceptions import AuthError, ConfigError, DrcomError
from .network import NetworkClient
from .protocols.base import BaseProtocol
from .protocols.version_520d import D_Protocol
from .state import CoreStatus, DrcomState

logger = logging.getLogger(__name__)


class DrcomCore:
    """
    Dr.COM 认证核心引擎。

    这是外部应用 (CLI/GUI) 与本库交互的唯一入口点。
    它维护了单例的会话状态 (State) 和网络连接 (NetworkClient)。

    Attributes:
        config (DrcomConfig): 当前使用的配置对象 (只读)。
        state (DrcomState): 当前会话的动态状态 (包含 Salt, Token, Status)。
    """

    def __init__(
        self,
        config: DrcomConfig,
        status_callback: Callable[[CoreStatus, str], None] | None = None,
    ) -> None:
        """
        初始化核心引擎。

        Args:
            config: 已加载且校验通过的配置对象。
            status_callback: (可选) 当引擎状态发生变更时调用的回调函数。
                                函数签名应为 `(status: CoreStatus, msg: str) -> None`。
                                该回调可能会在后台线程 (心跳线程) 中被调用，请注意线程安全。

        Raises:
            ConfigError: 如果依赖组件 (如 NetworkClient) 初始化失败。
        """
        self.config = config
        self._callback = status_callback

        try:
            self.state = DrcomState()
            self.net_client = NetworkClient(config)
        except Exception as e:
            raise ConfigError(f"引擎初始化失败: {e}") from e

        self.protocol: BaseProtocol
        if config.protocol_version == "D":
            self.protocol = D_Protocol(config, self.state, self.net_client)
        else:
            raise ConfigError(f"不支持的协议版本: {config.protocol_version}")

        self._stop_event = threading.Event()
        self._heartbeat_thread: threading.Thread | None = None

        self._update_status(CoreStatus.IDLE, "引擎已就绪")

    def login(self) -> bool:
        """
        执行同步登录流程。

        此方法会阻塞当前线程，直到登录成功、失败或超时。
        流程包括：
        1. 检查当前在线状态 (若已在线则直接返回 True)。
        2. 调用协议策略执行 Challenge (获取 Salt)。
        3. 调用协议策略执行 Login (获取 Token)。

        Returns:
            bool: True 表示登录成功且状态已切换为 LOGGED_IN；False 表示登录失败。

        Raises:
            AuthError: 当服务器明确拒绝登录时抛出 (如密码错误、欠费)。
                       异常对象中包含具体的 error_code。
            NetworkError: 当网络通信发生不可恢复的错误时抛出 (如端口占用、物理断网)。
        """
        self._update_status(CoreStatus.CONNECTING, "正在登录...")

        if self.state.is_online:
            logger.warning("已处于在线状态，忽略登录请求。")
            return True

        try:
            success = self.protocol.login()
            if success:
                self._update_status(CoreStatus.LOGGED_IN, "登录成功")
                return True
            else:
                self._update_status(CoreStatus.OFFLINE, "登录失败")
                return False
        except AuthError as ae:
            self.state.last_error = str(ae)
            self._update_status(CoreStatus.OFFLINE, f"认证拒绝: {ae}")
            raise
        except DrcomError as e:
            self.state.last_error = str(e)
            self._update_status(CoreStatus.ERROR, f"登录出错: {e}")
            return False

    def start_heartbeat(self) -> None:
        """
        启动后台心跳守护线程。

        前置条件:
            必须先调用 `login()` 并返回 True (即当前状态为 LOGGED_IN)。

        行为:
            创建一个名为 "DrcomHeartbeat" 的守护线程，每隔固定时间 (通常 20s)
            执行一次 Keep-Alive 交互。如果心跳连续失败 3 次，线程将自动退出
            并将状态更新为 OFFLINE。
        """
        if self._heartbeat_thread and self._heartbeat_thread.is_alive():
            return

        if self.state.status != CoreStatus.LOGGED_IN:
            logger.error("无法启动心跳：未登录。")
            return

        self._stop_event.clear()
        self._heartbeat_thread = threading.Thread(
            target=self._heartbeat_loop, name="DrcomHeartbeat", daemon=True
        )
        self._heartbeat_thread.start()

    def stop(self) -> None:
        """
        停止引擎并清理资源。

        行为:
        1. 发送停止信号给心跳线程，并等待其结束 (最多 2s)。
        2. 尝试发送 Logout 包 (尽力而为，不保证成功)。
        3. 关闭底层的 UDP Socket。
        4. 将状态重置为 OFFLINE。
        """
        self._stop_event.set()
        if self._heartbeat_thread:
            self._heartbeat_thread.join(timeout=2)

        try:
            self.protocol.logout()
        except Exception as e:
            logger.error(f"注销时发生错误: {e}")
        finally:
            self._update_status(CoreStatus.OFFLINE, "已停止")

    def _heartbeat_loop(self) -> None:
        self._update_status(CoreStatus.HEARTBEAT, "心跳维持中")
        fail_count = 0

        while not self._stop_event.is_set():
            try:
                success = self.protocol.keep_alive()
                if success:
                    fail_count = 0
                else:
                    fail_count += 1
                    logger.warning(f"心跳失败计数: {fail_count}")
            except Exception as e:
                logger.error(f"心跳循环异常: {e}")
                fail_count += 1

            if fail_count >= 3:
                self._update_status(CoreStatus.OFFLINE, "心跳丢失，已掉线")
                break

            if self._stop_event.wait(20):
                break

    def _update_status(self, status: CoreStatus, msg: str) -> None:
        self.state.status = status
        logger.info(f"[状态变更] {status.name}: {msg}")
        if self._callback:
            try:
                self._callback(status, msg)
            except Exception:
                pass

    def __del__(self) -> None:
        if hasattr(self, "net_client") and self.net_client:
            self.net_client.close()
