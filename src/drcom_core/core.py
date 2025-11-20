# src/drcom_core/core.py
"""
Dr.COM 认证核心库 - 认证引擎 (Engine)
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
    """

    def __init__(
        self,
        config: DrcomConfig,
        status_callback: Callable[[CoreStatus, str], None] | None = None,
    ) -> None:
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
