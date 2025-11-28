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
    Dr.COM 认证核心引擎。
    """

    def __init__(
        self,
        config: DrcomConfig,
        status_callback: Optional[Callable[[CoreStatus, str], None]] = None,
    ) -> None:
        """
        初始化引擎。

        Args:
            config: 强类型配置对象。
            status_callback: 状态变更回调 (status, msg)。
        """
        self.config = config
        self._callback = status_callback

        # 1. 初始化基础组件
        try:
            self.state = DrcomState()
            self.net_client = NetworkClient(config)
        except Exception as e:
            raise ConfigError(f"网络组件初始化失败: {e}") from e

        # 2. 加载协议策略
        self.protocol: BaseProtocol
        self._load_strategy()

        # 3. 线程控制
        self._stop_event = threading.Event()
        self._heartbeat_thread: Optional[threading.Thread] = None

        self._update_status(CoreStatus.IDLE, "引擎已就绪")

    def _load_strategy(self) -> None:
        """根据配置加载对应的协议策略"""
        ver = self.config.protocol_version

        if ver == "D":
            self.protocol = Protocol520D(self.config, self.state, self.net_client)
        # elif ver == "P":
        #     self.protocol = ProtocolPPPoE(...)
        else:
            raise ConfigError(f"不支持的协议版本: {ver}")

    def login(self) -> bool:
        """
        [同步] 执行登录。
        """
        self._update_status(CoreStatus.CONNECTING, "正在登录...")

        if self.state.is_online:
            logger.warning("当前已在线，跳过登录")
            return True

        try:
            success = self.protocol.login()
            if success:
                self._update_status(CoreStatus.LOGGED_IN, "登录成功")
                return True
            else:
                # 协议层返回 False 通常意味着逻辑失败但未抛异常
                self._update_status(CoreStatus.OFFLINE, "登录失败 (未知原因)")
                return False

        except AuthError as ae:
            # 业务拒绝 (密码错误等) -> 上层需要显式处理
            self.state.last_error = str(ae)
            self._update_status(CoreStatus.OFFLINE, f"认证被拒绝: {ae}")
            raise

        except (NetworkError, DrcomError) as e:
            # 技术错误 (网络不通等) -> 记录错误，不 Crash
            self.state.last_error = str(e)
            self._update_status(CoreStatus.ERROR, f"登录异常: {e}")
            return False

    def start_heartbeat(self) -> None:
        """
        启动后台心跳守护线程。
        前提：必须先 Login 成功。
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
        停止引擎：结束心跳 -> 发送注销 -> 关闭网络。
        """
        # 1. 停止线程
        self._stop_event.set()
        if self._heartbeat_thread:
            self._heartbeat_thread.join(timeout=2.0)

        # 2. 尝试注销
        if self.state.is_online:
            try:
                self.protocol.logout()
            except Exception as e:
                logger.warning(f"注销过程异常: {e}")

        # 3. 清理网络
        # 注意：NetworkClient 通常不需要显式 close，这里主要重置状态
        self._update_status(CoreStatus.OFFLINE, "已停止")

    def _heartbeat_loop(self) -> None:
        """心跳线程体"""
        self._update_status(CoreStatus.HEARTBEAT, "心跳维持中")

        while not self._stop_event.is_set():
            try:
                # 执行一次完整的心跳交互
                if not self.protocol.keep_alive():
                    logger.error("心跳检测失败 (Protocol return False)")
                    break
            except Exception as e:
                logger.error(f"心跳线程发生未捕获异常: {e}")
                break

            # 等待 20 秒 (可中断)
            if self._stop_event.wait(timeout=20.0):
                break

        # 循环结束意味着掉线或主动停止
        if not self._stop_event.is_set():
            self._update_status(CoreStatus.OFFLINE, "心跳丢失，已掉线")

    def _update_status(self, status: CoreStatus, msg: str) -> None:
        self.state.status = status
        logger.info(f"[{status.name}] {msg}")
        if self._callback:
            try:
                self._callback(status, msg)
            except Exception:
                pass
