"""
Dr.COM D系列策略 (Strategy) - v1.0.0 [Asyncio Edition]

职责：
1. 流程编排：Challenge -> Login -> Heartbeat -> Logout。
2. 状态维护：管理 KeepAlive2 的复杂状态机 (Init -> Loop)。
3. 异常处理：将网络异常转化为布尔值反馈给 Core 引擎。
"""

import asyncio
import logging
import random
from typing import TYPE_CHECKING

from ...exceptions import AuthError, AuthErrorCode, NetworkError, ProtocolError
from ...state import CoreStatus
from ..base import BaseProtocol
from . import packets

if TYPE_CHECKING:
    from ...config import DrcomConfig
    from ...network import NetworkClient
    from ...state import DrcomState

logger = logging.getLogger(__name__)

# --- 超时设置 (Fail Fast) ---
TIMEOUT_CHALLENGE = 3.0
TIMEOUT_LOGIN = 5.0
TIMEOUT_KEEP_ALIVE = 3.0
TIMEOUT_LOGOUT_CHALLENGE = 1.0
TIMEOUT_LOGOUT_RECV = 1.0

# --- 业务重试设置 ---
MAX_RETRIES_SERVER_BUSY = 3


class Protocol520D(BaseProtocol):
    """Dr.COM 5.2.0(D) 版协议策略实现 (Async)。"""

    def __init__(
        self,
        config: "DrcomConfig",
        state: "DrcomState",
        net_client: "NetworkClient",
    ):
        """初始化协议策略。

        Args:
            config: 全局配置对象。
            state: 共享状态对象。
            net_client: 异步网络客户端。
        """
        super().__init__(config, state, net_client)
        self.logger.info(f"Dr.COM 5.2.0(D) 策略已加载 (User: {config.username})")

    async def login(self) -> bool:
        """执行登录流程。

        包含 Challenge 握手和 Login 请求，并处理服务器繁忙重试逻辑。

        Returns:
            bool: 登录成功返回 True，失败返回 False。

        Raises:
            AuthError: 当服务器明确拒绝认证（如密码错误、欠费）时抛出。
            NetworkError: 当网络层发生不可恢复错误时抛出。
            ProtocolError: 当协议交互异常（如响应解析失败）时抛出。
        """
        self.logger.info("开始 5.2.0(D) 登录流程...")
        self.state.status = CoreStatus.CONNECTING

        try:
            # 1. 获取 Salt (Await)
            if not await self._challenge():
                return False

            # 2. 执行登录 (Await)
            if await self._login():
                self.state.status = CoreStatus.LOGGED_IN
                self.logger.info("登录成功，状态已更新为 LOGGED_IN。")
                return True
            else:
                self.state.status = CoreStatus.OFFLINE
                return False

        except (ProtocolError, NetworkError) as e:
            self.logger.error(f"登录过程中断: {e}")
            self.state.status = CoreStatus.ERROR
            raise

    async def keep_alive(self) -> bool:
        """执行一次心跳循环。

        包含 KA1 (0xFF) 和 KA2 (0x07) 序列的交互。

        Returns:
            bool: 心跳成功返回 True，失败（网络超时或协议错误）返回 False。
        """
        self.state.status = CoreStatus.HEARTBEAT
        try:
            # --- 1. KA1 (0xFF) ---
            ka1_pkt = packets.build_keep_alive1_packet(
                salt=self.state.salt,
                password=self.config.password,
                auth_info=self.state.auth_info,
                include_trailing_zeros=True,
            )

            await self.net_client.send(ka1_pkt)
            data_ka1, _ = await self.net_client.receive(TIMEOUT_KEEP_ALIVE)

            if not packets.parse_keep_alive1_response(data_ka1):
                raise ProtocolError("KA1 响应无效 (非 0x07 开头)")

            # --- 2. KA2 (0x07 Sequence) ---
            await self._manage_keep_alive2_sequence()
            return True

        except (NetworkError, ProtocolError) as e:
            self.logger.warning(f"心跳失败 (将触发重连): {e}")
            return False

    async def logout(self) -> None:
        """执行登出流程 (Fail Fast)。

        尝试获取新 Salt 并发送注销包。如果网络超时，直接在本地清除会话状态。
        """
        if not self.state.auth_info:
            self.logger.info("无会话信息，本地直接下线。")
            self.state.status = CoreStatus.OFFLINE
            return

        # 1. 尝试获取新 Salt
        try:
            pkt = packets.build_challenge_request()
            await self.net_client.send(pkt)
            data, _ = await self.net_client.receive(TIMEOUT_LOGOUT_CHALLENGE)
            new_salt = packets.parse_challenge_response(data)
            if new_salt:
                self.state.salt = new_salt
            else:
                self.logger.warning("注销前获取 Salt 无效")
        except Exception:
            self.logger.warning("注销前获取 Salt 超时，直接本地下线。")
            self._reset_state()
            return

        # 2. 发送注销包
        try:
            pkt = packets.build_logout_packet(
                username=self.config.username,
                password=self.config.password,
                salt=self.state.salt,
                mac=self.config.mac_address,
                auth_info=self.state.auth_info,
                control_check_status=self.config.control_check_status,
                adapter_num=self.config.adapter_num,
            )
            await self.net_client.send(pkt)
            # 尝试接收，不强求
            await self.net_client.receive(TIMEOUT_LOGOUT_RECV)
        except Exception:
            pass
        finally:
            self._reset_state()
            self.logger.info("本地会话已清理。")

    async def probe(self, timeout: float = 2.0) -> bool:
        """探测服务器连通性 (D版实现)。

        发送 Challenge 包 (0x01) 并等待响应 (0x02)。
        此操作是无状态的，不更新 self.state。

        Args:
            timeout: 超时时间。

        Returns:
            bool: 成功收到 0x02 响应返回 True，超时或错误返回 False。
        """
        try:
            pkt = packets.build_challenge_request()
            await self.net_client.send(pkt)
            data, _ = await self.net_client.receive(timeout)

            # parse_challenge_response 返回 bytes (Salt) 或 None
            return packets.parse_challenge_response(data) is not None
        except Exception:
            # 探测不仅捕获网络错误，也捕获所有异常以保证只返回 bool
            return False

    # =========================================================================
    # 内部实现 (Async)
    # =========================================================================

    async def _challenge(self) -> bool:
        """执行 Challenge 握手以获取 Salt。

        Returns:
            bool: 成功获取 Salt 返回 True。

        Raises:
            ProtocolError: 响应数据无效。
            NetworkError: 网络超时。
        """
        pkt = packets.build_challenge_request()
        await self.net_client.send(pkt)

        data, _ = await self.net_client.receive(TIMEOUT_CHALLENGE)
        salt = packets.parse_challenge_response(data)

        if salt:
            self.state.salt = salt
            return True
        raise ProtocolError("Challenge 响应数据无效")

    async def _login(self) -> bool:
        """执行核心登录逻辑，包含繁忙重试。

        Returns:
            bool: 登录成功返回 True。

        Raises:
            AuthError: 认证失败。
            NetworkError: 网络通信失败。
        """
        pkt = packets.build_login_packet(self.config, self.state.salt)

        for i in range(MAX_RETRIES_SERVER_BUSY):
            await self.net_client.send(pkt)
            try:
                data, (ip, _) = await self.net_client.receive(TIMEOUT_LOGIN)
            except NetworkError:
                raise

            # 简单的源 IP 校验
            if ip != self.config.server_address:
                continue

            success, auth_info, err_code = packets.parse_login_response(data)

            if success and auth_info:
                self.state.auth_info = auth_info
                return True

            if err_code == AuthErrorCode.SERVER_BUSY:
                self.logger.warning(
                    f"服务器繁忙 (0x02)，稍后重试... ({i + 1}/{MAX_RETRIES_SERVER_BUSY})"
                )
                # 指数退避或随机抖动
                await asyncio.sleep(random.uniform(1.0, 2.0))
                continue

            # 抛出具体的认证错误
            err_msg = f"认证失败 (Code: {hex(err_code) if err_code is not None else 'Unknown'})"
            raise AuthError(err_msg, err_code)

        raise NetworkError("登录失败：服务器持续繁忙")

    async def _perform_ka2_step(self, packet_type: int, is_first: bool = False) -> None:
        """执行 KA2 协议的单步交互。

        Args:
            packet_type: 包类型 (1 或 3)。
            is_first: 是否为初始化序列的首包。

        Raises:
            NetworkError: 发送或接收失败。
        """
        pkt = packets.build_keep_alive2_packet(
            packet_number=self.state.keep_alive_serial_num,
            tail=self.state.keep_alive_tail,
            packet_type=packet_type,
            host_ip_bytes=self.config.host_ip_bytes,
            keep_alive_version=self.config.keep_alive_version,
            is_first_packet=is_first,
            keep_alive2_flag=self.config.keep_alive2_flag,
        )

        await self.net_client.send(pkt)
        data, _ = await self.net_client.receive(TIMEOUT_KEEP_ALIVE)

        tail = packets.parse_keep_alive2_response(data)
        if tail:
            self.state.keep_alive_tail = tail

        self.state.keep_alive_serial_num = (self.state.keep_alive_serial_num + 1) % 256

    async def _manage_keep_alive2_sequence(self) -> None:
        """执行 KA2 状态机逻辑。

        根据是否初始化 (_ka2_initialized) 决定执行 Init 序列 (1-1-3) 还是 Loop 序列 (1-3)。
        """
        if not self.state._ka2_initialized:
            self.logger.debug("执行 KA2 初始化序列...")
            # Init Sequence: Type 1(First) -> Type 1 -> Type 3
            await self._perform_ka2_step(packet_type=1, is_first=True)
            await self._perform_ka2_step(packet_type=1)
            await self._perform_ka2_step(packet_type=3)
            self.state._ka2_initialized = True
        else:
            # Loop Sequence: Type 1 -> Type 3
            await self._perform_ka2_step(packet_type=1)
            await self._perform_ka2_step(packet_type=3)

    def _reset_state(self) -> None:
        """重置本地会话状态至离线。"""
        self.state.status = CoreStatus.OFFLINE
        self.state.salt = b""
        self.state.auth_info = b""
        self.state._ka2_initialized = False
        self.state.keep_alive_serial_num = 0
