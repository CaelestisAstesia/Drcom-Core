# src/drcom_core/protocols/version_520d.py
"""
Dr.COM 核心库 - D 版协议策略 (D Version Protocol Strategy)

封装 Dr.COM 5.2.0(D)
的完整认证流程：
- Login: Challenge -> Login
- KeepAlive: Keep Alive 1 (FF) -> Keep Alive 2 (07)
- Logout: Challenge -> Logout
"""

import logging
import random
import socket  # 只导入 socket.error 和 socket.timeout 用于异常处理
import time
from typing import TYPE_CHECKING, Optional

# 导入状态类
from ..state import DrcomState

# 导入协议层和常量
from . import challenge, constants, keep_alive, login, logout

# 导入协议基类
from .base import BaseProtocol

# 避免循环导入，仅用于类型提示
if TYPE_CHECKING:
    from ..config import DrcomConfig
    from ..network import NetworkClient
    from ..state import DrcomState

logger = logging.getLogger(__name__)


class D_Protocol(BaseProtocol):
    """
    实现了 Dr.COM D 版
    认证流程的策略。
    """

    def __init__(
        self,
        config: "DrcomConfig",
        state: "DrcomState",
        net_client: "NetworkClient",
    ):
        """
        初始化 D 版协议策略。
        """
        super().__init__(config, state, net_client)
        self.logger.info("Dr.COM D 版协议策略已加载。")

    # =========================================================================
    # 公共 API (由 BaseProtocol 定义)
    # =========================================================================

    def login(self) -> bool:
        """
        [API] 执行 D 版的 Challenge -> Login 流程。
        """
        self.logger.info("执行 D 版登录流程...")
        # 调用本类中的私有 D 版 Challenge
        if self._challenge():
            # 调用本类中的私有 D 版 Login
            if self._login():
                self.logger.info("D 版登录成功。")
                return True
            else:
                self.logger.error("D 版登录流程失败 (Login 阶段)。")
                return False
        else:
            self.logger.error("D 版登录流程失败 (Challenge 阶段)。")
            return False

    def keep_alive(self) -> bool:
        """
        [API] 执行 D 版的*一次*心跳循环 (KA1 -> KA2)。
        """
        self.logger.debug("执行 D 版心跳循环...")

        # 步骤 A: 执行 Keep Alive 1 (FF 包)
        ka1_packet = keep_alive.build_keep_alive1_packet(
            salt=self.state.salt,
            password=self.config.password,
            auth_info=self.state.auth_info,
            include_trailing_zeros=True,
        )
        if not ka1_packet:
            self.logger.error("构建 Keep Alive 1 (FF) 失败，心跳中断。")
            return False

        try:
            self.logger.debug("发送 Keep Alive 1 (FF)...")
            ka1_response = self._send_and_receive_ka("KA1 (FF)", ka1_packet)

            if not ka1_response or not keep_alive.parse_keep_alive1_response(
                ka1_response
            ):
                self.logger.warning("Keep Alive 1 (FF) 未收到有效响应，可能已掉线。")
                return False  # 心跳失败

        except (socket.timeout, socket.error) as e_ka1:
            self.logger.warning(
                f"Keep Alive 1 (FF) 发生网络错误: {e_ka1}，可能已掉线。"
            )
            return False  # 心跳失败
        except Exception as e_ka1_other:
            self.logger.error(
                f"处理 Keep Alive 1 (FF) 时发生意外错误: {e_ka1_other}",
                exc_info=True,
            )
            return False  # 心跳失败

        # 步骤 B: 执行 Keep Alive 2 (07 包) 序列
        if not self._manage_keep_alive2_sequence():
            self.logger.error("Keep Alive 2 (07) 序列执行失败，心跳中断。")
            return False  # 心跳失败

        return True  # 本次心跳循环成功

    def logout(self) -> None:
        """
        [API] 执行 D 版的登出流程 (Challenge -> Logout)。
        """
        if not self.state.auth_info:
            self.logger.info("未登录或缺少认证信息 (Auth Info)，无需执行登出操作。")
            return

        self.logger.info("正在尝试执行 D 版 Logout 过程...")
        original_salt = self.state.salt

        # 1. 尝试获取新的 Challenge Salt
        logout_challenge_ok = self._challenge(
            max_retries=constants.MAX_RETRIES_LOGOUT_CHALLENGE
        )
        if not logout_challenge_ok:
            self.logger.warning(
                "登出前获取新的 Challenge salt 失败。将尝试使用旧 salt。"
            )
            if not original_salt:
                self.logger.error("无可用 Salt，无法构建登出包，放弃登出。")
                self._reset_state()  # 必须清理状态
                return
            else:
                self.state.salt = original_salt  # 确保 self.state.salt 是有效的

        # 2. 构建登出包
        try:
            logout_packet = logout.build_logout_packet(
                username=self.config.username,
                password=self.config.password,
                salt=self.state.salt,
                mac=self.config.mac_address,
                auth_info=self.state.auth_info,
                control_check_status=self.config.control_check_status,
                adapter_num=self.config.adapter_num,
            )
        except ValueError as ve:
            self.logger.error(f"构建登出包时发生错误: {ve}，放弃登出。")
            self._reset_state()  # 清理状态
            return

        # 3. 发送登出包 (并尝试接收响应)
        try:
            self.logger.debug(f"发送登出数据包: {logout_packet.hex()}")
            self.net_client.send(logout_packet)

            try:
                response_data, server_addr = self.net_client.receive(
                    constants.TIMEOUT_LOGOUT
                )
                received_ip = server_addr[0] if server_addr else None
                resp_success, message = logout.parse_logout_response(
                    response_data, self.config.server_address, received_ip
                )
                self.logger.info(f"登出响应解析结果: {message} (成功={resp_success})")

            except socket.timeout:
                self.logger.info("发送登出包后未收到响应 (正常情况)。")
            except socket.error as sock_err_recv:
                self.logger.warning(f"接收登出响应时发生 Socket 错误: {sock_err_recv}")

        except socket.error as sock_err_send:
            self.logger.error(f"发送登出包时发生 Socket 错误: {sock_err_send}")
        except Exception as e:
            self.logger.error(f"执行登出操作时发生意外错误: {e}", exc_info=True)

        finally:
            self._reset_state()  # 无论成功与否，都清理本地状态

    # =========================================================================
    # D 版协议的完整内部方法
    # =========================================================================

    def _challenge(self, max_retries: int = constants.MAX_RETRIES_CHALLENGE) -> bool:
        """
        [内部] D 版 Challenge 流程。
        """
        self.logger.info("执行 D-Challenge...")
        retries = 0

        try:
            packet = challenge.build_challenge_request()
        except ValueError as e:
            self.logger.error(f"构建 Challenge 包失败: {e}")
            return False

        while retries < max_retries:
            attempt = retries + 1
            self.logger.debug(f"Challenge 尝试: {attempt}/{max_retries}")
            try:
                self.net_client.send(packet)
                resp_data, server_addr = self.net_client.receive(
                    constants.TIMEOUT_CHALLENGE
                )

                if not server_addr or server_addr[0] != self.config.server_address:
                    self.logger.warning(
                        f"收到来自非预期来源 {server_addr} 的 Challenge 响应。"
                    )
                    continue

                salt_data = challenge.parse_challenge_response(resp_data)

                if salt_data:
                    self.state.salt = salt_data
                    self.logger.info(f"Challenge 成功。 Salt: {self.state.salt.hex()}")
                    return True
                else:
                    self.logger.warning(
                        "解析 Challenge 响应失败 (包无效或 Code 错误)。"
                    )

            except socket.timeout:
                self.logger.warning(f"Challenge 第 {attempt} 次尝试超时。")
            except socket.error as e:
                self.logger.error(
                    f"Challenge 第 {attempt} 次尝试时发生 Socket 错误: {e}。"
                )
                time.sleep(constants.SLEEP_SOCKET_ERROR)
            except Exception as e:
                self.logger.error(
                    f"Challenge 第 {attempt} 次尝试时发生意外错误: {e}", exc_info=True
                )

            retries += 1
            if retries < max_retries:
                time.sleep(random.uniform(0.5, 1.5))

        self.logger.error("Challenge 过程失败 (超过最大重试次数)。")
        self.state.salt = b""
        return False

    def _login(self, max_retries: int = constants.MAX_RETRIES_LOGIN) -> bool:
        """
        [内部] D 版 Login 流程。
        """
        self.logger.info("执行 D-Login...")
        if not self.state.salt:
            self.logger.error("登录失败：未获取到 Salt。")
            return False

        try:
            login_packet = login.build_login_packet(
                username=self.config.username,
                password=self.config.password,
                salt=self.state.salt,
                mac_address=self.config.mac_address,
                host_ip_bytes=self.config.host_ip_bytes,
                host_name=self.config.host_name,
                host_os=self.config.host_os,
                primary_dns_bytes=self.config.primary_dns_bytes,
                dhcp_server_bytes=self.config.dhcp_address_bytes,
                control_check_status=self.config.control_check_status,
                adapter_num=self.config.adapter_num,
                ipdog=self.config.ipdog,
                auth_version=self.config.auth_version,
                ror_status=self.config.ror_status,
            )
        except (ValueError, KeyError) as ve:
            self.logger.error(f"构建登录包时发生配置或数据错误: {ve}", exc_info=True)
            return False

        retries = 0
        while retries < max_retries:
            attempt = retries + 1
            self.logger.info(f"第 {attempt}/{max_retries} 次尝试发送登录请求...")

            try:
                self.net_client.send(login_packet)
                response_data, server_addr = self.net_client.receive(
                    constants.TIMEOUT_LOGIN
                )

                received_ip = server_addr[0] if server_addr else None
                if not received_ip:
                    self.logger.warning("收到登录响应但无法获取来源 IP 地址。")
                    continue

                is_success, auth_info_data, error_code, message = (
                    login.parse_login_response(
                        response_data, self.config.server_address, received_ip
                    )
                )

                if is_success:
                    if auth_info_data:
                        self.state.auth_info = auth_info_data
                        self.state.login_success = True
                        self.logger.info(f"登录成功！ ({message})")
                        return True
                    else:
                        self.logger.error(
                            f"登录响应成功，但无法提取认证信息。({message})"
                        )
                        return False

                else:  # is_success is False
                    self.logger.error(f"登录失败: {message}")
                    if (
                        error_code is not None
                        and error_code in constants.NO_RETRY_ERROR_CODES
                    ):
                        self.logger.warning(
                            "此错误通常由配置或账户问题引起，停止登录尝试。"
                        )
                        return False  # 不可重试

            except socket.timeout:
                self.logger.warning(f"登录第 {attempt} 次尝试接收响应超时。")
            except socket.error as e:
                self.logger.error(f"登录第 {attempt} 次尝试时发生 Socket 错误: {e}。")
                time.sleep(constants.SLEEP_SOCKET_ERROR)
            except Exception as e:
                self.logger.error(
                    f"登录第 {attempt} 次尝试时发生意外错误: {e}", exc_info=True
                )

            retries += 1
            if retries < max_retries:
                time.sleep(random.uniform(1.0, 3.0))

        self.logger.error("登录失败 (超过最大重试次数)。")
        self.state.login_success = False
        self.state.auth_info = b""
        return False

    def _send_and_receive_ka(self, log_prefix: str, packet: bytes) -> Optional[bytes]:
        """
        [内部] 辅助函数：发送 Keep Alive 包并接收响应 (封装了网络和日志)。
        """
        try:
            self.logger.debug(f"发送 {log_prefix}: {packet.hex()}")
            self.net_client.send(packet)

            response_data, server_addr = self.net_client.receive(
                constants.TIMEOUT_KEEP_ALIVE
            )
            self.logger.debug(
                f"收到 {log_prefix} 响应: {response_data.hex()} from {server_addr}"
            )

            if not server_addr or server_addr[0] != self.config.server_address:
                self.logger.warning(
                    f"{log_prefix} 收到来自非预期来源 ({server_addr}) 的响应。"
                )
                return None  # 视为无效响应

            if not response_data or not response_data.startswith(
                constants.KEEP_ALIVE_RESP_CODE
            ):
                self.logger.warning(
                    f"{log_prefix} 收到无效响应或 Code 错误: {response_data[:1].hex() if response_data else 'None'}"
                )
                return None
            return response_data

        except (socket.timeout, socket.error):
            raise  # 将网络异常抛给调用者 (keep_alive) 处理

    def _manage_keep_alive2_sequence(self) -> bool:
        """
        [内部] D 版 Keep Alive 2 (07 包) 序列。
        """
        self.logger.debug("开始执行 Keep Alive 2 (07 包) 序列...")
        try:
            state = self.state
            cfg = self.config

            if not state._ka2_initialized:
                self.logger.info("执行 Keep Alive 2 初始化序列...")
                # Seq 1: Type 1 (First), tail=0000
                pkt1 = keep_alive.build_keep_alive2_packet(
                    packet_number=state.keep_alive_serial_num,
                    tail=b"\x00\x00\x00\x00",
                    packet_type=1,
                    host_ip_bytes=cfg.host_ip_bytes,
                    keep_alive_version=cfg.keep_alive_version,
                    is_first_packet=True,
                )
                if not pkt1:
                    return False
                resp1_data = self._send_and_receive_ka("KA2 Init Seq 1", pkt1)
                if not resp1_data:
                    return False
                state.keep_alive_serial_num = (state.keep_alive_serial_num + 1) % 256

                # Seq 2: Type 1 (Not First), tail=0000
                pkt2 = keep_alive.build_keep_alive2_packet(
                    packet_number=state.keep_alive_serial_num,
                    tail=b"\x00\x00\x00\x00",
                    packet_type=1,
                    host_ip_bytes=cfg.host_ip_bytes,
                    keep_alive_version=cfg.keep_alive_version,
                    is_first_packet=False,
                )
                if not pkt2:
                    return False
                resp2_data = self._send_and_receive_ka("KA2 Init Seq 2", pkt2)
                if not resp2_data:
                    return False
                new_tail2 = keep_alive.parse_keep_alive2_response(resp2_data)
                if not new_tail2:
                    return False
                state.keep_alive_tail = new_tail2
                state.keep_alive_serial_num = (state.keep_alive_serial_num + 1) % 256

                # Seq 3: Type 3, tail=from resp2
                pkt3 = keep_alive.build_keep_alive2_packet(
                    packet_number=state.keep_alive_serial_num,
                    tail=state.keep_alive_tail,
                    packet_type=3,
                    host_ip_bytes=cfg.host_ip_bytes,
                    keep_alive_version=cfg.keep_alive_version,
                    is_first_packet=False,
                )
                if not pkt3:
                    return False
                resp3_data = self._send_and_receive_ka("KA2 Init Seq 3", pkt3)
                if not resp3_data:
                    return False
                new_tail3 = keep_alive.parse_keep_alive2_response(resp3_data)
                if not new_tail3:
                    return False
                state.keep_alive_tail = new_tail3
                state.keep_alive_serial_num = (state.keep_alive_serial_num + 1) % 256

                state._ka2_initialized = True
                self.logger.info("Keep Alive 2 初始化序列完成。")

            else:  # KA2已初始化，执行循环序列
                self.logger.debug("执行 Keep Alive 2 循环序列...")
                # Loop Seq 1: Type 1, tail=current
                pkt_loop1 = keep_alive.build_keep_alive2_packet(
                    packet_number=state.keep_alive_serial_num,
                    tail=state.keep_alive_tail,
                    packet_type=1,
                    host_ip_bytes=cfg.host_ip_bytes,
                    keep_alive_version=cfg.keep_alive_version,
                    is_first_packet=False,
                )
                if not pkt_loop1:
                    return False
                resp_loop1_data = self._send_and_receive_ka("KA2 Loop Seq 1", pkt_loop1)
                if not resp_loop1_data:
                    return False
                new_tail_loop1 = keep_alive.parse_keep_alive2_response(resp_loop1_data)
                if not new_tail_loop1:
                    return False
                state.keep_alive_tail = new_tail_loop1
                state.keep_alive_serial_num = (state.keep_alive_serial_num + 1) % 256

                # Loop Seq 2: Type 3, tail=from resp_loop1
                pkt_loop2 = keep_alive.build_keep_alive2_packet(
                    packet_number=state.keep_alive_serial_num,
                    tail=state.keep_alive_tail,
                    packet_type=3,
                    host_ip_bytes=cfg.host_ip_bytes,
                    keep_alive_version=cfg.keep_alive_version,
                    is_first_packet=False,
                )
                if not pkt_loop2:
                    return False
                resp_loop2_data = self._send_and_receive_ka("KA2 Loop Seq 2", pkt_loop2)
                if not resp_loop2_data:
                    return False
                new_tail_loop2 = keep_alive.parse_keep_alive2_response(resp_loop2_data)
                if not new_tail_loop2:
                    return False
                state.keep_alive_tail = new_tail_loop2
                state.keep_alive_serial_num = (state.keep_alive_serial_num + 1) % 256
                self.logger.debug("Keep Alive 2 循环序列完成。")

            return True  # 整个序列成功

        except (socket.timeout, socket.error) as net_err:
            self.logger.warning(f"Keep Alive 2 序列中发生网络错误: {net_err}")
            return False
        except Exception as e:
            self.logger.error(f"Keep Alive 2 序列中发生意外错误: {e}", exc_info=True)
            return False

    def _reset_state(self):
        """[内部] D 版 清理所有会话状态"""
        self.state = DrcomState()
        self.logger.info("D 版协议状态已重置。")
