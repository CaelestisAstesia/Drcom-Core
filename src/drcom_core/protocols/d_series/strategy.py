# src/drcom_core/protocols/d_series/strategy.py
"""
Dr.COM D系列策略 (Strategy) - v1.0.0

职责：
1. 流程编排：Challenge -> Login -> Heartbeat -> Logout。
2. 状态维护：管理 KeepAlive2 的复杂状态机 (Init -> Loop)。
3. 异常处理：将网络异常转化为布尔值反馈给 Core 引擎。

注意：
- 严禁在此处硬编码任何魔法数字，所有常量必须来自 config 或 constants。
- 必须使用 logger。
"""

import logging
import random
import time
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
# 外层做重试机制，内层超时尽量果断
TIMEOUT_CHALLENGE = 3.0
TIMEOUT_LOGIN = 5.0
TIMEOUT_KEEP_ALIVE = 3.0
TIMEOUT_LOGOUT_CHALLENGE = 1.0  # 极速超时，拿不到就走
TIMEOUT_LOGOUT_RECV = 1.0

# --- 业务重试设置 ---
# 仅针对“服务器繁忙”这种明确的业务信号
MAX_RETRIES_SERVER_BUSY = 3


class Protocol520D(BaseProtocol):
    """
    Dr.COM 5.2.0(D) 版协议策略实现。

    实现了标准 D 版的全套交互流程，包括：
    1. 挑战 (Challenge) 获取 Salt。
    2. 登录 (Login) 并处理多重加密与校验。
    3. 双重守护 (KeepAlive 1 & 2) 维持在线。
    4. 尽力而为的注销 (Logout)。
    """

    def __init__(
        self,
        config: "DrcomConfig",
        state: "DrcomState",
        net_client: "NetworkClient",
    ):
        """
        初始化 D 版策略。

        Args:
            config (DrcomConfig): 核心配置对象。
            state (DrcomState): 会话状态容器。
            net_client (NetworkClient): 网络通信客户端。
        """
        super().__init__(config, state, net_client)
        self.logger.info(f"Dr.COM 5.2.0(D) 策略已加载 (User: {config.username})")

    def login(self) -> bool:
        """
        [API] 执行登录流程。

        流程: Challenge (0x01) -> Login Packet (0x03) -> Parse Response (0x04/0x05)

        Returns:
            bool: 登录成功返回 True，失败返回 False。

        Raises:
            AuthError: 明确的认证拒绝 (如密码错误、欠费)。
            NetworkError: 网络层面的通信失败。
            ProtocolError: 协议交互异常。
        """
        self.logger.info("开始 5.2.0(D) 登录流程...")
        self.state.status = CoreStatus.CONNECTING

        try:
            # 1. 获取 Salt (原子操作，无重试)
            # 这一步失败通常意味着物理网络不通或不是 Dr.COM 环境
            if not self._challenge():
                return False

            # 2. 执行登录
            # 内部包含了针对 "Server Busy" 的有限重试逻辑
            if self._login():
                self.state.status = CoreStatus.LOGGED_IN
                self.logger.info("登录成功，状态已更新为 LOGGED_IN。")
                return True
            else:
                self.state.status = CoreStatus.OFFLINE
                return False

        except (ProtocolError, NetworkError) as e:
            self.logger.error(f"登录过程中断: {e}")
            self.state.status = CoreStatus.ERROR
            # 这里的异常会抛给 Core，由 Core 决定是否重试
            raise

    def keep_alive(self) -> bool:
        """
        [API] 执行一次心跳循环。

        D 版协议包含两套心跳机制，必须在一个周期内依次完成：
        1. KeepAlive1 (0xFF): 验证密码与 Session，防止伪造。
        2. KeepAlive2 (0x07): 维护 Sequence Number 和 Tail，防止重放。

        Returns:
            bool: 心跳成功返回 True。如果失败 (网络超时或校验错误)，
                  返回 False，且不抛出异常，由上层 Core 触发重连流程。
        """
        self.state.status = CoreStatus.HEARTBEAT
        try:
            # --- 1. KA1 (0xFF) ---
            ka1_pkt = packets.build_keep_alive1_packet(
                salt=self.state.salt,
                password=self.config.password,
                auth_info=self.state.auth_info,
                # 部分学校可能不需要尾部填充，这里暂按标准处理，未来可配置
                include_trailing_zeros=True,
            )

            # 严格模式：超时即异常，由上层触发重连
            self.net_client.send(ka1_pkt)
            data_ka1, _ = self.net_client.receive(TIMEOUT_KEEP_ALIVE)

            if not packets.parse_keep_alive1_response(data_ka1):
                raise ProtocolError("KA1 响应无效 (非 0x07 开头)")

            # --- 2. KA2 (0x07 Sequence) ---
            # 处理复杂的序列号与 Tail 更新逻辑
            self._manage_keep_alive2_sequence()
            return True

        except (NetworkError, ProtocolError) as e:
            self.logger.warning(f"心跳失败 (将触发重连): {e}")
            return False

    def logout(self) -> None:
        """
        [API] 执行登出流程 (Fail Fast)。

        尝试获取新 Salt 发送注销包。如果网络不通，直接本地下线，不阻塞用户。
        因为注销包也需要使用实时的 Salt 进行加密，旧 Salt 往往无效。
        """
        if not self.state.auth_info:
            self.logger.info("无会话信息，本地直接下线。")
            self.state.status = CoreStatus.OFFLINE
            return

        # 1. 尝试获取新 Salt (1秒超时)
        try:
            pkt = packets.build_challenge_request()
            self.net_client.send(pkt)
            data, _ = self.net_client.receive(TIMEOUT_LOGOUT_CHALLENGE)
            new_salt = packets.parse_challenge_response(data)
            if new_salt:
                self.state.salt = new_salt
                self.logger.debug("注销前成功获取新 Salt")
            else:
                self.logger.warning("注销前获取 Salt 无效，将尝试使用旧 Salt")
        except Exception:
            self.logger.warning("注销前获取 Salt 超时，跳过网络注销，直接本地下线。")
            self._reset_state()
            return

        # 2. 发送注销包 (尽力而为)
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
            self.net_client.send(pkt)
            # 尝试接收响应，但不强求
            self.net_client.receive(TIMEOUT_LOGOUT_RECV)
        except Exception:
            pass
        finally:
            self._reset_state()
            self.logger.info("本地会话已清理。")

    # =========================================================================
    # 内部实现 (Internal Implementation)
    # =========================================================================

    def _challenge(self) -> bool:
        """
        执行 Challenge 握手 (0x01 -> 0x02)。

        更新 state.salt。
        """
        pkt = packets.build_challenge_request()
        self.net_client.send(pkt)

        data, _ = self.net_client.receive(TIMEOUT_CHALLENGE)
        salt = packets.parse_challenge_response(data)

        if salt:
            self.state.salt = salt
            return True
        raise ProtocolError("Challenge 响应数据无效")

    def _login(self) -> bool:
        """
        执行 Login 握手 (0x03 -> 0x04/0x05)。

        包含针对 "Server Busy" (0x02) 的业务级重试逻辑。

        Returns:
            bool: 成功返回 True。

        Raises:
            AuthError: 认证被拒绝。
            NetworkError: 网络失败。
        """
        # 从 config 组装参数
        pkt = packets.build_login_packet(self.config, self.state.salt)

        for i in range(MAX_RETRIES_SERVER_BUSY):
            self.net_client.send(pkt)
            try:
                data, (ip, _) = self.net_client.receive(TIMEOUT_LOGIN)
            except NetworkError:
                # 登录阶段如果超时，通常意味着网络极差或 IP 错误，不进行微重试
                raise

            # 校验来源 IP (简单防欺骗)
            if ip != self.config.server_address:
                self.logger.warning(f"收到非认证服务器的数据包 (来自 {ip})，忽略。")
                continue

            success, auth_info, err_code = packets.parse_login_response(data)

            if success and auth_info:
                self.state.auth_info = auth_info
                return True

            # 处理业务错误
            if err_code == AuthErrorCode.SERVER_BUSY:
                self.logger.warning(
                    f"服务器繁忙 (0x02)，稍后重试... ({i + 1}/{MAX_RETRIES_SERVER_BUSY})"
                )
                time.sleep(random.uniform(1.0, 2.0))
                continue

            # 其他错误 (密码错误、欠费等)
            err_msg = f"认证失败 (Code: {hex(err_code) if err_code is not None else 'Unknown'})"
            # 尝试映射为中文提示
            try:
                e_enum = AuthErrorCode(err_code) if err_code is not None else None
                if e_enum:
                    # 这里可以进一步细化错误信息映射
                    pass
            except ValueError:
                pass

            raise AuthError(err_msg, err_code)

        raise NetworkError("登录失败：服务器持续繁忙")

    def _perform_ka2_step(self, packet_type: int, is_first: bool = False) -> None:
        """
        [Internal] 执行 KA2 序列中的单步交互：构建 -> 发送 -> 接收 -> 更新状态。

        Args:
            packet_type (int): 心跳包类型。
            is_first (bool): 是否为首次包 (影响 Flag 设置)。

        Returns:
            None

        Raises:
            None
        """
        # 1. 构建包
        pkt = packets.build_keep_alive2_packet(
            packet_number=self.state.keep_alive_serial_num,
            tail=self.state.keep_alive_tail,
            packet_type=packet_type,
            host_ip_bytes=self.config.host_ip_bytes,
            keep_alive_version=self.config.keep_alive_version,
            is_first_packet=is_first,
            keep_alive2_flag=self.config.keep_alive2_flag,
        )

        # 2. 发送与接收
        self.net_client.send(pkt)
        data, _ = self.net_client.receive(TIMEOUT_KEEP_ALIVE)

        # 3. 提取并更新 Tail (如果有)
        tail = packets.parse_keep_alive2_response(data)
        if tail:
            self.state.keep_alive_tail = tail

        # 4. 序列号自增 (Mod 256)
        self.state.keep_alive_serial_num = (self.state.keep_alive_serial_num + 1) % 256

    def _manage_keep_alive2_sequence(self) -> None:
        """
        [Refactor] KA2 (0x07) 状态机交互逻辑。
        使用 _perform_ka2_step 消除重复代码。
                KA2 (0x07) 状态机交互逻辑。

        D 版的 0x07 心跳包有时序要求，必须严格按照以下顺序执行：

        1. 初始化阶段 (Init Sequence) - 仅在会话刚建立时执行一次:
           - Step 1 (Packet Type 1): Client -> Server (Flag=First)
             Response: 仅用于确认，无 Payload。
           - Step 2 (Packet Type 1): Client -> Server (Flag=Normal)
             Response: 包含 Tail (用于 Step 3)。
           - Step 3 (Packet Type 3): Client -> Server (含 Host IP)
             Response: 包含 Tail (用于 Loop 阶段)。

        2. 循环保活阶段 (Loop Sequence) - 后续每次心跳执行:
           - Step 1 (Packet Type 1): Client -> Server
             Response: 包含 Tail。
           - Step 2 (Packet Type 3): Client -> Server (含 Host IP)
             Response: 包含 Tail。

        注意：
        - Serial Number (packet_number) 在每次发送后递增 (mod 256)。
        - Tail (签名) 通常由上一次响应携带，并在下一次请求中回传。
        - 任何一步网络超时或校验失败都会抛出异常，中断心跳线程。
        """
        if not self.state._ka2_initialized:
            # === 初始化阶段 (Init Sequence) ===
            self.logger.debug("执行 KA2 初始化序列...")

            # Step 1: Type 1 (First)
            self._perform_ka2_step(packet_type=1, is_first=True)

            # Step 2: Type 1 (Normal)
            self._perform_ka2_step(packet_type=1)

            # Step 3: Type 3 (With IP)
            self._perform_ka2_step(packet_type=3)

            self.state._ka2_initialized = True
            self.logger.debug("KA2 初始化完成。")

        else:
            # === 循环保活阶段 (Loop Sequence) ===
            # Loop 1: Type 1
            self._perform_ka2_step(packet_type=1)

            # Loop 2: Type 3
            self._perform_ka2_step(packet_type=3)

    def _reset_state(self):
        """重置会话状态 (Salt, AuthInfo, KA2 标志位)"""
        self.state.status = CoreStatus.OFFLINE
        self.state.salt = b""
        self.state.auth_info = b""
        self.state._ka2_initialized = False
        self.state.keep_alive_serial_num = 0
