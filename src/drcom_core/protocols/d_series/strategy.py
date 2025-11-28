# src/drcom_core/protocols/d_series/strategy.py
"""
Dr.COM D系列策略 (Strategy) - v1.0.0

职责：
1. 流程编排：Challenge -> Login -> Heartbeat -> Logout。
2. 状态维护：管理 KeepAlive2 的复杂状态机 (Init -> Loop)。
3. 异常处理：将网络异常转化为布尔值反馈给 Core 引擎。

注意：
- 严禁在此处硬编码任何魔法数字，所有常量必须来自 config 或 constants。
- 严禁使用 print，必须使用 logger。
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
# 既然外层有重试机制，内层超时应尽量果断
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

    实现了标准 D 版的全套交互流程。通过继承此类并重写部分方法，
    可以轻松扩展出 6.0D 等变种。
    """

    def __init__(
        self,
        config: "DrcomConfig",
        state: "DrcomState",
        net_client: "NetworkClient",
    ):
        super().__init__(config, state, net_client)
        self.logger.info(f"Dr.COM 5.2.0(D) 策略已加载 (User: {config.username})")

    def login(self) -> bool:
        """
        [API] 执行登录流程。

        流程: Challenge -> Login Packet -> Parse Response
        """
        self.logger.info("开始 5.2.0(D) 登录流程...")
        self.state.status = CoreStatus.CONNECTING

        try:
            # 1. 获取 Salt (原子操作，无重试)
            if not self._challenge():
                return False

            # 2. 执行登录
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

        包含:
        1. KeepAlive1 (0xFF): 验证密码与 Session。
        2. KeepAlive2 (0x07): 维护 Sequence Number 和 Tail。
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
            self._manage_keep_alive2_sequence()
            return True

        except (NetworkError, ProtocolError) as e:
            self.logger.warning(f"心跳失败 (将触发重连): {e}")
            return False

    def logout(self) -> None:
        """
        [API] 执行登出流程 (Fail Fast)。

        尝试获取新 Salt 发送注销包。如果网络不通，直接本地下线，不阻塞用户。
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
        """执行 Challenge"""
        pkt = packets.build_challenge_request()
        self.net_client.send(pkt)

        data, _ = self.net_client.receive(TIMEOUT_CHALLENGE)
        salt = packets.parse_challenge_response(data)

        if salt:
            self.state.salt = salt
            return True
        raise ProtocolError("Challenge 响应数据无效")

    def _login(self) -> bool:
        """执行 Login (仅包含 Server Busy 业务重试)"""
        # 从 config 组装参数
        pkt = packets.build_login_packet(
            username=self.config.username,
            password=self.config.password,
            salt=self.state.salt,
            mac_address=self.config.mac_address,
            host_ip_bytes=self.config.host_ip_bytes,
            primary_dns_bytes=self.config.primary_dns_bytes,
            dhcp_server_bytes=self.config.dhcp_address_bytes,  # 注意：Config字段名映射
            secondary_dns_bytes=self.config.secondary_dns_bytes,
            host_name=self.config.host_name,
            host_os=self.config.host_os,
            os_info_bytes=self.config.os_info_bytes,
            adapter_num=self.config.adapter_num,
            ipdog=self.config.ipdog,
            auth_version=self.config.auth_version,
            control_check_status=self.config.control_check_status,
            padding_after_ipdog=self.config.padding_after_ipdog,
            padding_after_dhcp=self.config.padding_after_dhcp,
            padding_auth_ext=self.config.padding_auth_ext,
            ror_enabled=self.config.ror_status,
        )

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

    def _manage_keep_alive2_sequence(self) -> None:
        """
        KA2 状态机交互逻辑。

        D 版的 0x07 心跳包有时序要求：
        - 首次心跳 (Init): Step 1 -> Step 2 -> Step 3
        - 后续心跳 (Loop): Loop 1 -> Loop 2

        任何一步失败都会导致抛出异常，从而中断心跳线程。
        """
        state = self.state
        cfg = self.config

        def send_recv(pkt: bytes, desc: str) -> bytes:
            """辅助函数：收发并记录日志"""
            self.net_client.send(pkt)
            data, _ = self.net_client.receive(TIMEOUT_KEEP_ALIVE)
            # self.logger.debug(f"{desc} 响应: {data.hex()}")
            return data

        if not state._ka2_initialized:
            # === 初始化阶段 (Init Sequence) ===
            self.logger.debug("执行 KA2 初始化序列...")

            # Step 1: Type 1 Packet (Flag=First)
            # 这一步服务器通常只回 ACK，没有 Tail
            pkt1 = packets.build_keep_alive2_packet(
                packet_number=state.keep_alive_serial_num,
                tail=b"\x00" * 4,
                packet_type=1,
                host_ip_bytes=cfg.host_ip_bytes,
                keep_alive_version=cfg.keep_alive_version,
                is_first_packet=True,
                keep_alive2_flag=cfg.keep_alive2_flag,
            )
            send_recv(pkt1, "KA2 Init Step 1")
            state.keep_alive_serial_num = (state.keep_alive_serial_num + 1) % 256

            # Step 2: Type 1 Packet (Flag=Normal)
            pkt2 = packets.build_keep_alive2_packet(
                packet_number=state.keep_alive_serial_num,
                tail=b"\x00" * 4,
                packet_type=1,
                host_ip_bytes=cfg.host_ip_bytes,
                keep_alive_version=cfg.keep_alive_version,
                is_first_packet=False,
                keep_alive2_flag=cfg.keep_alive2_flag,
            )
            resp2 = send_recv(pkt2, "KA2 Init Step 2")
            # 提取 Tail
            tail = packets.parse_keep_alive2_response(resp2)
            if tail:
                state.keep_alive_tail = tail
            state.keep_alive_serial_num = (state.keep_alive_serial_num + 1) % 256

            # Step 3: Type 3 Packet (Contains IP)
            pkt3 = packets.build_keep_alive2_packet(
                packet_number=state.keep_alive_serial_num,
                tail=state.keep_alive_tail,
                packet_type=3,
                host_ip_bytes=cfg.host_ip_bytes,
                keep_alive_version=cfg.keep_alive_version,
                is_first_packet=False,
                keep_alive2_flag=cfg.keep_alive2_flag,
            )
            resp3 = send_recv(pkt3, "KA2 Init Step 3")
            tail = packets.parse_keep_alive2_response(resp3)
            if tail:
                state.keep_alive_tail = tail
            state.keep_alive_serial_num = (state.keep_alive_serial_num + 1) % 256

            state._ka2_initialized = True
            self.logger.debug("KA2 初始化完成。")

        else:
            # === 循环保活阶段 (Loop Sequence) ===
            # Loop 1: Type 1 Packet
            pkt_l1 = packets.build_keep_alive2_packet(
                packet_number=state.keep_alive_serial_num,
                tail=state.keep_alive_tail,
                packet_type=1,
                host_ip_bytes=cfg.host_ip_bytes,
                keep_alive_version=cfg.keep_alive_version,
                is_first_packet=False,
                keep_alive2_flag=cfg.keep_alive2_flag,
            )
            resp_l1 = send_recv(pkt_l1, "KA2 Loop 1")
            tail = packets.parse_keep_alive2_response(resp_l1)
            if tail:
                state.keep_alive_tail = tail
            state.keep_alive_serial_num = (state.keep_alive_serial_num + 1) % 256

            # Loop 2: Type 3 Packet
            pkt_l2 = packets.build_keep_alive2_packet(
                packet_number=state.keep_alive_serial_num,
                tail=state.keep_alive_tail,
                packet_type=3,
                host_ip_bytes=cfg.host_ip_bytes,
                keep_alive_version=cfg.keep_alive_version,
                is_first_packet=False,
                keep_alive2_flag=cfg.keep_alive2_flag,
            )
            resp_l2 = send_recv(pkt_l2, "KA2 Loop 2")
            tail = packets.parse_keep_alive2_response(resp_l2)
            if tail:
                state.keep_alive_tail = tail
            state.keep_alive_serial_num = (state.keep_alive_serial_num + 1) % 256

    def _reset_state(self):
        """重置会话状态"""
        self.state.status = CoreStatus.OFFLINE
        self.state.salt = b""
        self.state.auth_info = b""
        self.state._ka2_initialized = False
        self.state.keep_alive_serial_num = 0
