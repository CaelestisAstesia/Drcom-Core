# src/drcom_core/core.py
"""
Dr.COM 认证核心库 - 认证引擎 (Engine)

此类作为认证流程的编排器 (Orchestrator)。
它不包含任何特定协议（D/P/X）的逻辑，而是通过“策略模式”
来加载和管理一个具体的协议实现。

职责:
1. 初始化核心服务 (Config, State, Network)。
2. 根据配置，加载对应的协议策略 (Protocol Strategy)。
3. 管理心跳线程的生命周期 (start/stop)。
4. 将 login/logout API 调用委托给加载的策略。
"""

import logging
import sys
import threading
import traceback
from typing import Optional

# 导入核心服务
from .config import DrcomConfig

# 导入协议层依赖
from .drcom_protocol import constants
from .network import NetworkClient

# 导入协议策略接口和具体实现
from .protocols.base import BaseProtocol
from .protocols.d_version import D_Protocol  # [策略1] D 版
from .state import DrcomState

# from .protocols.p_version import P_Protocol  # [策略2] P 版 (未来扩展)

logger = logging.getLogger(__name__)


class DrcomCore:
    """
    Dr.COM 认证核心引擎 (API)。
    """

    def __init__(self, config: DrcomConfig) -> None:
        """
        初始化 DrcomCore 引擎。

        Args:
            config (DrcomConfig):
                一个已解析和验证的配置对象。

        Raises:
            SystemExit: 如果网络套接字初始化失败。
            ValueError: 如果配置的协议版本不受支持。
        """
        logger.info("Dr.Com-Core 引擎正在初始化...")

        # 1. 应用依赖注入
        try:
            self.config: DrcomConfig = config
            self.state: DrcomState = DrcomState()
            self.net_client: NetworkClient = NetworkClient(config)
            self.protocol: BaseProtocol  # 引擎只知道它有一个符合“契约”的协议

        except Exception as e:
            logger.critical(f"DrcomCore 依赖注入失败: {e}")
            logger.critical(traceback.format_exc())
            if hasattr(self, "net_client") and self.net_client:
                self.net_client.close()
            sys.exit(f"初始化过程中发生致命错误: {e}")

        # 2. [策略工厂] 根据配置，选择要实例化的“策略”（插入卡带）
        try:
            if config.protocol_version == "D":
                self.protocol = D_Protocol(config, self.state, self.net_client)
            # elif config.protocol_version == "P":
            #    self.protocol = P_Protocol(config, self.state, self.net_client)
            else:
                raise ValueError(
                    f"不支持的协议版本: '{config.protocol_version}'。 "
                    "请检查 .env 文件中的 PROTOCOL_VERSION。"
                )
        except Exception as e:
            logger.critical(f"加载协议策略失败: {e}")
            sys.exit(f"加载协议策略失败: {e}")

        # 3. 线程控制 (引擎自身的状态)
        self._heartbeat_stop_event = threading.Event()
        self._heartbeat_thread: Optional[threading.Thread] = None

        logger.info(
            f"Dr.Com-Core 引擎初始化成功 (已加载 {config.protocol_version} 协议)。"
        )

    # =========================================================================
    # 公开 API (Public API)
    # =========================================================================

    def login(self) -> bool:
        """
        [API] 执行登录流程。

        引擎将此调用委托给已加载的协议策略。
        """
        logger.info("API: 收到 login() 请求...")

        if self._heartbeat_thread and self._heartbeat_thread.is_alive():
            logger.info("API: 已登录且心跳正在运行。")
            return True

        if self.state.login_success:
            logger.info("API: 状态为已登录 (心跳未运行)，无需重复登录。")
            return True

        self.stop_heartbeat()  # 确保旧线程（如果存在）已停止

        # [策略] 将 login 委托给协议
        try:
            return self.protocol.login()
        except Exception as e:
            logger.error(f"协议 'login' 方法执行时发生意外错误: {e}", exc_info=True)
            return False

    def start_heartbeat(self) -> None:
        """
        [API] 启动后台心跳维持线程。

        引擎负责管理线程生命周期。
        """
        if self._heartbeat_thread and self._heartbeat_thread.is_alive():
            logger.warning("API: 心跳线程已在运行。")
            return

        if not self.state.login_success:
            logger.error("API: 启动心跳失败，请先调用 login() 并确保其返回 True。")
            return

        logger.info("API: 正在启动心跳线程...")
        self._heartbeat_stop_event.clear()
        self._heartbeat_thread = threading.Thread(
            target=self._heartbeat_loop,
            daemon=True,
        )
        self._heartbeat_thread.start()

    def stop_heartbeat(self) -> None:
        """
        [API] 停止后台心跳维持线程。
        """
        logger.info("API: 正在请求停止心跳线程...")
        self._heartbeat_stop_event.set()
        if self._heartbeat_thread and self._heartbeat_thread.is_alive():
            self._heartbeat_thread.join(timeout=constants.TIMEOUT_KEEP_ALIVE + 2.0)
            if self._heartbeat_thread.is_alive():
                logger.warning("API: 心跳线程未能及时停止。")
        self._heartbeat_thread = None
        logger.info("API: 心跳线程已停止。")

    def logout(self) -> None:
        """
        [API] 停止心跳并执行登出操作。

        引擎负责停止线程，并将 logout 调用委托给协议。
        """
        logger.info("API: 收到 logout() 请求...")
        self.stop_heartbeat()

        # [策略] 将 logout 委托给协议
        try:
            self.protocol.logout()
        except Exception as e:
            logger.error(f"协议 'logout' 方法执行时发生意外错误: {e}", exc_info=True)
            # 即使登出失败，也重置本地状态
            self.protocol._reset_state()

        logger.info("API: 登出流程完毕。")

    # =========================================================================
    # 内部核心逻辑 (Internal Engine Loop)
    # =========================================================================

    def _heartbeat_loop(self) -> None:
        """
        [内部] 心跳维持的内部循环 (由引擎管理)。

        此循环只负责定时，具体的“做什么”由协议策略的 keep_alive() 决定。
        """
        if not self.state.login_success or not self.state.auth_info:
            logger.error("心跳线程启动失败：尚未登录或缺少认证信息。")
            return

        logger.info(
            f"心跳线程已启动 (协议: {self.config.protocol_version})，开始维持在线状态..."
        )

        try:
            # 开始心跳主循环
            while not self._heartbeat_stop_event.is_set():
                # [策略] 将 keep_alive 委托给协议
                if not self.protocol.keep_alive():
                    self.logger.warning("心跳失败 (来自协议层)。心跳循环终止。")
                    break  # 协议逻辑说失败了，引擎就停止

                # 步骤 C: 等待间隔
                logger.debug(
                    f"本轮心跳完成，等待 {constants.SLEEP_KEEP_ALIVE_INTERVAL} 秒..."
                )
                was_interrupted = self._heartbeat_stop_event.wait(
                    timeout=constants.SLEEP_KEEP_ALIVE_INTERVAL
                )
                if was_interrupted:
                    logger.info("心跳等待间隔被中断，准备退出循环。")
                    break

        except Exception as e_loop:
            logger.error(f"心跳循环中发生意外错误: {e_loop}", exc_info=True)
        finally:
            logger.info("心跳线程已停止。")
            self.state.login_success = False  # 标记为未登录

    def __del__(self):
        """
        确保在对象销毁时关闭套接字。
        """
        logger.debug("DrcomCore 引擎正在销毁，关闭网络连接...")
        # 确保 net_client 存在（初始化成功）再尝试关闭
        if hasattr(self, "net_client") and self.net_client:
            self.net_client.close()
