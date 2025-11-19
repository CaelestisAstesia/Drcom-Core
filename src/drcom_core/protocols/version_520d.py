# src/drcom_core/protocols/version_520d.py
"""
Dr.COM 核心库 - D 版协议策略 (D Version Protocol Strategy)

封装 Dr.COM 5.2.0(D) 的完整认证流程。
"""

import logging
import random
import time
from typing import TYPE_CHECKING

from ..exceptions import NetworkError, ProtocolError
from ..state import CoreStatus
from . import challenge, constants, keep_alive, login, logout
from .base import BaseProtocol

if TYPE_CHECKING:
    from ..config import DrcomConfig
    from ..network import NetworkClient
    from ..state import DrcomState

logger = logging.getLogger(__name__)

# =========================================================================
# 策略控制参数 (Strategy Control Parameters)
# =========================================================================
# 这些参数属于"策略"的一部分，因此定义在此处，而不是协议常量文件中
TIMEOUT_CHALLENGE = 3
TIMEOUT_LOGIN = 5
TIMEOUT_KEEP_ALIVE = 3
TIMEOUT_LOGOUT = 2

MAX_RETRIES_CHALLENGE = 5
MAX_RETRIES_LOGIN = 3
MAX_RETRIES_LOGOUT_CHALLENGE = 1


class D_Protocol(BaseProtocol):
    """
    Dr.COM D 版协议策略实现。
    """

    def __init__(
        self,
        config: "DrcomConfig",
        state: "DrcomState",
        net_client: "NetworkClient",
    ):
        super().__init__(config, state, net_client)
        self.logger.info("Dr.COM D 版协议策略已加载。")

    def login(self) -> bool:
        """
        [API] 执行 D 版登录流程。
        """
        self.logger.info("开始 D 版登录流程...")
        self.state.status = CoreStatus.CONNECTING

        try:
            if not self._challenge():
                return False

            if self._login():
                self.state.status = CoreStatus.LOGGED_IN
                self.logger.info("D 版登录成功，状态已更新为 LOGGED_IN。")
                return True
            else:
                self.state.status = CoreStatus.OFFLINE
                return False

        except (ProtocolError, NetworkError):
            self.state.status = CoreStatus.ERROR
            raise

    def keep_alive(self) -> bool:
        """
        [API] 执行 D 版心跳循环 (KA1 -> KA2)。
        """
        self.state.status = CoreStatus.HEARTBEAT
        try:
            ka1_pkt = keep_alive.build_keep_alive1_packet(
                salt=self.state.salt,
                password=self.config.password,
                auth_info=self.state.auth_info,
                include_trailing_zeros=True,
            )

            self.net_client.send(ka1_pkt)
            resp_ka1, _ = self.net_client.receive(TIMEOUT_KEEP_ALIVE)

            if not keep_alive.parse_keep_alive1_response(resp_ka1):
                raise ProtocolError("KA1 响应无效")

            self._manage_keep_alive2_sequence()
            return True

        except (NetworkError, ProtocolError) as e:
            self.logger.warning(f"心跳失败: {e}")
            return False

    def logout(self) -> None:
        """
        [API] 执行登出流程。
        """
        if not self.state.auth_info:
            self.logger.info("无会话信息，无需登出。")
            self.state.status = CoreStatus.OFFLINE
            return

        self.logger.info("执行 D 版登出...")
        try:
            self._challenge(max_retries=MAX_RETRIES_LOGOUT_CHALLENGE)
        except Exception:
            self.logger.warning("登出前获取新 Salt 失败，使用旧 Salt。")

        try:
            pkt = logout.build_logout_packet(
                username=self.config.username,
                password=self.config.password,
                salt=self.state.salt,
                mac=self.config.mac_address,
                auth_info=self.state.auth_info,
                control_check_status=self.config.control_check_status,
                adapter_num=self.config.adapter_num,
            )
            self.net_client.send(pkt)
            try:
                self.net_client.receive(TIMEOUT_LOGOUT)
            except NetworkError:
                pass

        except Exception as e:
            self.logger.error(f"登出过程出错: {e}")
        finally:
            self._reset_state()
            self.logger.info("本地会话已清理。")

    # --- 内部实现 ---

    def _challenge(self, max_retries=MAX_RETRIES_CHALLENGE) -> bool:
        """执行 Challenge 并更新 state.salt"""
        pkt = challenge.build_challenge_request()

        for i in range(max_retries):
            try:
                self.net_client.send(pkt)
                data, _ = self.net_client.receive(TIMEOUT_CHALLENGE)
                salt = challenge.parse_challenge_response(data)
                if salt:
                    self.state.salt = salt
                    return True
            except NetworkError:
                pass
            time.sleep(1)

        raise NetworkError("Challenge 失败: 超过最大重试次数")

    def _login(self, max_retries=MAX_RETRIES_LOGIN) -> bool:
        """执行 Login 并更新 state.auth_info"""
        pkt = login.build_login_packet(
            username=self.config.username,
            password=self.config.password,
            salt=self.state.salt,
            mac_address=self.config.mac_address,
            host_ip_bytes=self.config.host_ip_bytes,
            primary_dns_bytes=self.config.primary_dns_bytes,
            dhcp_server_bytes=self.config.dhcp_address_bytes,
            host_name=self.config.host_name,
            host_os=self.config.host_os,
            adapter_num=self.config.adapter_num,
            ipdog=self.config.ipdog,
            auth_version=self.config.auth_version,
            control_check_status=self.config.control_check_status,
            magic_tail=self.config.magic_tail,
            ror_status=self.config.ror_status,
        )

        for i in range(max_retries):
            try:
                self.net_client.send(pkt)
                data, (ip, _) = self.net_client.receive(TIMEOUT_LOGIN)

                success, auth_info, err_code, msg = login.parse_login_response(
                    data, self.config.server_address, ip
                )

                if success and auth_info:
                    self.state.auth_info = auth_info
                    return True

                if err_code:
                    # 如果是服务器繁忙 (0x02)，允许重试
                    if err_code == constants.ERROR_CODE_SERVER_BUSY:
                        self.logger.warning(
                            f"登录响应：服务器繁忙 (0x02)，正在重试... ({i + 1}/{max_retries})"
                        )
                        time.sleep(random.uniform(1.0, 2.0))
                        continue

                    # 其他错误视为致命错误
                    from ..exceptions import AuthError

                    raise AuthError(msg, err_code)

            except NetworkError:
                pass  # 网络错误自动重试
            time.sleep(1)

        raise NetworkError("Login 失败: 超过最大重试次数或无响应")

    def _manage_keep_alive2_sequence(self):
        """处理复杂的 KA2 序列逻辑"""
        state = self.state
        cfg = self.config

        def send_recv_ka2(pkt, desc):
            self.net_client.send(pkt)
            data, _ = self.net_client.receive(TIMEOUT_KEEP_ALIVE)
            if not data:
                raise ProtocolError(f"{desc} 无响应")
            return data

        if not state._ka2_initialized:
            p1 = keep_alive.build_keep_alive2_packet(
                state.keep_alive_serial_num,
                b"\x00" * 4,
                1,
                cfg.host_ip_bytes,
                cfg.keep_alive_version,
                True,
            )
            send_recv_ka2(p1, "KA2 Init 1")
            state.keep_alive_serial_num = (state.keep_alive_serial_num + 1) % 256

            p2 = keep_alive.build_keep_alive2_packet(
                state.keep_alive_serial_num,
                b"\x00" * 4,
                1,
                cfg.host_ip_bytes,
                cfg.keep_alive_version,
                False,
            )
            d2 = send_recv_ka2(p2, "KA2 Init 2")
            state.keep_alive_tail = keep_alive.parse_keep_alive2_response(d2)
            state.keep_alive_serial_num = (state.keep_alive_serial_num + 1) % 256

            p3 = keep_alive.build_keep_alive2_packet(
                state.keep_alive_serial_num,
                state.keep_alive_tail,
                3,
                cfg.host_ip_bytes,
                cfg.keep_alive_version,
                False,
            )
            d3 = send_recv_ka2(p3, "KA2 Init 3")
            state.keep_alive_tail = keep_alive.parse_keep_alive2_response(d3)
            state.keep_alive_serial_num = (state.keep_alive_serial_num + 1) % 256

            state._ka2_initialized = True
        else:
            p_l1 = keep_alive.build_keep_alive2_packet(
                state.keep_alive_serial_num,
                state.keep_alive_tail,
                1,
                cfg.host_ip_bytes,
                cfg.keep_alive_version,
                False,
            )
            d_l1 = send_recv_ka2(p_l1, "KA2 Loop 1")
            state.keep_alive_tail = keep_alive.parse_keep_alive2_response(d_l1)
            state.keep_alive_serial_num = (state.keep_alive_serial_num + 1) % 256

            p_l2 = keep_alive.build_keep_alive2_packet(
                state.keep_alive_serial_num,
                state.keep_alive_tail,
                3,
                cfg.host_ip_bytes,
                cfg.keep_alive_version,
                False,
            )
            d_l2 = send_recv_ka2(p_l2, "KA2 Loop 2")
            state.keep_alive_tail = keep_alive.parse_keep_alive2_response(d_l2)
            state.keep_alive_serial_num = (state.keep_alive_serial_num + 1) % 256

    def _reset_state(self):
        self.state.status = CoreStatus.OFFLINE
        self.state.salt = b""
        self.state.auth_info = b""
        self.state._ka2_initialized = False
