# /src/drcom_core/core.py
"""
Dr.COM 认证核心逻辑模块。

负责初始化网络、执行认证流程、
维持心跳以及处理登出。
"""

import logging
import random
import socket
import sys
import threading
import time
import traceback
from typing import Any, Dict, Optional

# 导入协议处理模块和常量
from ..drcom_protocol import constants
from ..drcom_protocol.challenge import (
    receive_challenge_response,
    send_challenge_request,
)
from ..drcom_protocol.keep_alive import (
    build_keep_alive1_packet,
    build_keep_alive2_packet,
    parse_keep_alive1_response,
    parse_keep_alive2_response,
)
from ..drcom_protocol.login import (
    build_login_packet,
    parse_login_response,
)
from ..drcom_protocol.login import (
    send_login_request as send_login_request_login,
)
from ..drcom_protocol.logout import (
    build_logout_packet,
    parse_logout_response,
    send_logout_request,
)

# 获取当前模块的 logger 实例
logger = logging.getLogger(__name__)


class DrcomCore:
    """
    Dr.COM 认证核心逻辑类 (API)。

    此类封装了 Dr.COM D 版认证的完整生命周期。
    它被设计为可重用的 API 库，通过构造函数 (constructor) 接收所有配置。

    Attributes:
        login_success (bool): 标记当前是否处于登录成功状态。
        # ... (其他内部状态)
    """

    def __init__(self, config: Dict[str, Any]) -> None:
        """
        初始化 DrcomCore 类。

        Args:
            config (Dict[str, Any]):
                包含所有必要配置的字典。调用者 (如 CLI 或 GUI)
                负责加载此配置。

        Raises:
            ValueError: 如果 config 字典中缺少必要的键。
            SystemExit: 如果套接字初始化失败。
        """
        logger.info("Dr.Com-Core 正在初始化...")
        self.salt: bytes = b""
        self.auth_info: bytes = b""
        self.login_success: bool = False
        self.core_socket: Optional[socket.socket] = None

        # 初始化 Keep Alive 2 状态
        self.keep_alive_serial_num: int = 0
        self.keep_alive_tail: bytes = b"\x00\x00\x00\x00"
        self._ka2_initialized: bool = False

        self._heartbeat_stop_event = threading.Event()
        self._heartbeat_thread: Optional[threading.Thread] = None

        try:
            # 1. 解析传入的 config 字典
            self._parse_config(config)
            # 2. 初始化网络套接字
            self._init_socket()
        except (ValueError, KeyError) as e:
            logger.critical(f"配置错误: {e}")
            raise ValueError(f"配置错误: {e}") from e
        except Exception as e:
            logger.critical(f"初始化失败: {e}")
            logger.critical(traceback.format_exc())
            sys.exit(f"初始化过程中发生致命错误: {e}")

        logger.info("Dr.Com-Core 初始化成功。")

    def _parse_config(self, config: Dict[str, Any]) -> None:
        """
        [内部] 从传入的字典中解析配置并设置实例属性。

        Raises:
            KeyError: 如果缺少必要的配置项。
            ValueError: 如果配置项格式错误（如 MAC）。
        """
        logger.debug("正在解析传入的配置字典...")
        try:
            # 网络配置
            self.server_address: str = config["SERVER_IP"]
            self.drcom_port: int = int(
                config.get("DRCOM_PORT", constants.DEFAULT_DRCOM_PORT)
            )

            # 凭据
            self.username: str = config["USERNAME"]
            self.password: str = config["PASSWORD"]

            # 主机信息
            self.host_ip: str = config["HOST_IP"]
            self.bind_ip: str = config.get(
                "BIND_IP", self.host_ip
            )  # 默认绑定到 Host IP
            mac_str: str = config["MAC"]

            # 主机环境
            self.host_name: str = config.get("HOST_NAME", constants.DEFAULT_HOST_NAME)
            self.host_os: str = config.get("HOST_OS", constants.DEFAULT_HOST_OS)
            self.primary_dns: str = config.get(
                "PRIMARY_DNS", constants.DEFAULT_PRIMARY_DNS
            )
            self.dhcp_address: str = config.get(
                "DHCP_SERVER", constants.DEFAULT_DHCP_SERVER
            )

            # 协议参数 (字节串)
            self.adapter_num: bytes = bytes.fromhex(config.get("ADAPTERNUM", "01"))
            self.ipdog: bytes = bytes.fromhex(config.get("IPDOG", "01"))
            self.auth_version: bytes = bytes.fromhex(config.get("AUTH_VERSION", "0a00"))
            self.control_check_status: bytes = bytes.fromhex(
                config.get("CONTROL_CHECK_STATUS", "20")
            )
            self.keep_alive_version: bytes = bytes.fromhex(
                config.get("KEEP_ALIVE_VERSION", constants.KEEP_ALIVE_VERSION.hex())
            )

            # ROR 状态 (布尔值)
            self.ror_status: bool = (
                str(config.get("ROR_STATUS", "False")).lower()
                in constants.BOOLEAN_TRUE_STRINGS
            )

            # MAC 地址处理
            clean_mac = mac_str.replace(":", "").replace("-", "")
            if len(clean_mac) == 12:
                self.mac_address: int = int(clean_mac, 16)
            else:
                raise ValueError(f"MAC 地址格式无效: {mac_str}")

        except KeyError as e:
            logger.critical(f"配置中缺少必要的键: {e}")
            raise KeyError(f"配置中缺少 {e}") from e
        except Exception as e:
            logger.critical(f"解析配置时出错: {e}")
            raise ValueError(f"解析配置失败: {e}") from e

        logger.info("配置解析成功。")

    # 内部核心逻辑 (Internal Methods)

    def _init_socket(self) -> None:
        """[内部] 初始化 UDP 网络套接字并绑定到指定 IP 和端口。"""
        logger.info("正在初始化网络套接字...")
        try:
            self.core_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.core_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # 绑定到配置的 BIND_IP 和 0 端口（由系统分配）
            # 绑定到 0.0.0.0 允许在所有接口上接收
            # 端口 0 意味着让操作系统选择一个可用的临时端口
            # 真正的通信端口是 self.drcom_port，在 sendto 时指定

            bind_ip_to_use = "0.0.0.0"  # 监听所有接口
            bind_port = self.drcom_port

            self.core_socket.bind((bind_ip_to_use, bind_port))

            logger.info(f"网络套接字初始化成功，已绑定到 {bind_ip_to_use}:{bind_port}")
        except socket.error as e:
            logger.error(
                f"网络套接字初始化失败: {e} (端口 {self.drcom_port} 可能已被占用)"
            )
            raise  # 将异常抛给 __init__ 处理

    def _perform_challenge(
        self, max_retries: int = constants.MAX_RETRIES_CHALLENGE
    ) -> bool:
        """
        [内部] 执行 Challenge 过程，尝试从服务器获取 Salt。

        Args:
            max_retries: 最大重试次数。

        Returns:
            bool: 成功获取 Salt 则返回 True，否则返回 False。
        """
        logger.info("正在执行 [内部] Challenge 过程...")
        if not self.core_socket:
            logger.error("Challenge 失败：网络套接字未初始化。")
            return False

        retries = 0
        while retries < max_retries:
            attempt = retries + 1
            logger.info(f"Challenge 尝试次数: {attempt}/{max_retries}")
            try:
                self.core_socket.settimeout(constants.TIMEOUT_CHALLENGE)
                send_challenge_request(
                    self.core_socket, self.server_address, self.drcom_port
                )
                salt_data, server_addr = receive_challenge_response(self.core_socket)

                # 校验响应来源和获取到的 salt 数据
                if server_addr and server_addr[0] == self.server_address and salt_data:
                    self.salt = salt_data
                    logger.info(f"Challenge 成功。获取到 Salt: {self.salt.hex()}")
                    return True
                else:
                    response_hex = salt_data.hex() if salt_data else "None"
                    logger.warning(
                        f"收到无效或非预期的 Challenge 响应来自 {server_addr}。"
                        f"响应数据: {response_hex}。"
                    )

            except socket.timeout:
                logger.warning(f"Challenge 第 {attempt} 次尝试超时。")
            except socket.error as e:
                logger.error(f"Challenge 第 {attempt} 次尝试时发生 Socket 错误: {e}。")
                time.sleep(constants.SLEEP_SOCKET_ERROR)
            except Exception as e:
                logger.error(
                    f"Challenge 第 {attempt} 次尝试时发生意外错误: {e}", exc_info=True
                )

            retries += 1
            if retries < max_retries:
                wait_time = random.uniform(0.5, 1.5)
                logger.debug(f"等待 {wait_time:.2f} 秒后重试...")
                time.sleep(wait_time)

        logger.error("Challenge 过程失败 (超过最大重试次数)。")
        self.salt = b""  # 清空 salt
        return False

    def _perform_login(self, max_retries: int = constants.MAX_RETRIES_LOGIN) -> bool:
        """
        [内部] 执行登录认证过程。

        Args:
            max_retries: 最大重试次数。

        Returns:
            bool: 登录成功则返回 True，否则返回 False。
        """
        logger.info("正在执行 [内部] Login 过程...")
        if not self.core_socket:
            logger.error("登录失败：网络套接字未初始化。")
            return False
        if not self.salt:
            logger.error("登录失败：未获取到 Salt。请先成功执行 Challenge。")
            return False
        if not all([self.username, self.password, self.host_ip, self.mac_address]):
            logger.error("登录失败：缺少必要的配置信息 (用户名、密码、IP 或 MAC)。")
            return False

        retries = 0
        while retries < max_retries:
            attempt = retries + 1
            try:
                logger.info(f"第 {attempt}/{max_retries} 次尝试构建和发送登录请求...")
                login_packet = build_login_packet(
                    username=self.username,
                    password=self.password,
                    salt=self.salt,
                    mac_address=self.mac_address,
                    host_ip=self.host_ip,
                    host_name=self.host_name,
                    host_os=self.host_os,
                    primary_dns=self.primary_dns,
                    dhcp_server=self.dhcp_address,
                    control_check_status=self.control_check_status,
                    adapter_num=self.adapter_num,
                    ipdog=self.ipdog,
                    auth_version=self.auth_version,
                    ror_status=self.ror_status,
                )

                self.core_socket.settimeout(constants.TIMEOUT_LOGIN)
                send_login_request_login(
                    self.core_socket, self.server_address, self.drcom_port, login_packet
                )

                response_data, server_addr = self.core_socket.recvfrom(1024)

                received_ip = server_addr[0] if server_addr else None
                if not received_ip:
                    logger.warning("收到登录响应但无法获取来源 IP 地址。")
                    continue

                is_success, auth_info_data, error_code, message = parse_login_response(
                    response_data, self.server_address, received_ip
                )

                if is_success:
                    if auth_info_data:
                        self.auth_info = auth_info_data
                        self.login_success = True
                        logger.info(f"登录成功！ ({message})")
                        return True
                    else:
                        logger.error(f"登录响应成功，但无法提取认证信息。({message})")
                        return False

                else:  # is_success is False
                    logger.error(f"登录失败: {message}")
                    if (
                        error_code is not None
                        and error_code in constants.NO_RETRY_ERROR_CODES
                    ):
                        logger.warning("此错误通常由配置或账户问题引起，停止登录尝试。")
                        return False

            except ValueError as ve:
                logger.error(f"构建登录包时发生配置或数据错误: {ve}")
                logger.debug(traceback.format_exc())
                return False
            except socket.timeout:
                logger.warning(f"登录第 {attempt} 次尝试接收响应超时。")
            except socket.error as e:
                logger.error(f"登录第 {attempt} 次尝试时发生 Socket 错误: {e}。")
                time.sleep(constants.SLEEP_SOCKET_ERROR)
            except Exception as e:
                logger.error(
                    f"登录第 {attempt} 次尝试时发生意外错误: {e}", exc_info=True
                )

            retries += 1
            if retries < max_retries:
                wait_time = random.uniform(1.0, 3.0)
                logger.debug(f"等待 {wait_time:.2f} 秒后重试登录...")
                time.sleep(wait_time)

        logger.error("登录失败 (超过最大重试次数)。")
        self.login_success = False
        self.auth_info = b""
        return False

    def _build_keep_alive1_packet(self) -> Optional[bytes]:
        """
        [内部] 构建 Keep Alive 1 (FF 包 / 心跳包 1)。
        调用 keep_alive 模块中的函数实现。

        Returns:
            Optional[bytes]: 构建好的 FF 心跳包，如果缺少必要信息则返回 None。
        """
        if not self.salt or not self.auth_info or not self.password:
            logger.error("缺少构建 Keep Alive 1 的必要信息 (salt, auth_info, password)")
            return None
        return build_keep_alive1_packet(
            salt=self.salt,
            password=self.password,
            auth_info=self.auth_info,
            include_trailing_zeros=True,
        )

    def _manage_keep_alive2_sequence(self) -> bool:
        """
        [内部] 管理并发送 Keep Alive 2 (07 包) 序列，并处理响应以更新状态。
        包含初始化序列 (Type 1 -> Type 1 -> Type 3) 和循环序列 (Type 1 -> Type 3)。

        Returns:
            bool: 如果序列中的所有发送和接收都成功，则返回 True，否则返回 False。
                  返回 False 将导致心跳循环中断。
        """
        if not self.core_socket or not self.host_ip:
            logger.error("无法执行 Keep Alive 2：套接字或主机 IP 未初始化。")
            return False

        logger.debug("开始执行 Keep Alive 2 (07 包) 序列...")
        try:
            if not self._ka2_initialized:
                logger.info("执行 Keep Alive 2 初始化序列...")
                # Seq 1: Type 1 (First), tail=0000
                pkt1 = build_keep_alive2_packet(
                    packet_number=self.keep_alive_serial_num,
                    tail=b"\x00\x00\x00\x00",
                    packet_type=1,
                    host_ip=self.host_ip,
                    is_first_packet=True,
                )
                if not pkt1:
                    return False
                resp1_data = self._send_and_receive_ka("KA2 Init Seq 1", pkt1)
                if not resp1_data:
                    return False
                self.keep_alive_serial_num = (self.keep_alive_serial_num + 1) % 256

                # Seq 2: Type 1 (Not First), tail=0000
                pkt2 = build_keep_alive2_packet(
                    packet_number=self.keep_alive_serial_num,
                    tail=b"\x00\x00\x00\x00",
                    packet_type=1,
                    host_ip=self.host_ip,
                    is_first_packet=False,
                )
                if not pkt2:
                    return False
                resp2_data = self._send_and_receive_ka("KA2 Init Seq 2", pkt2)
                if not resp2_data:
                    return False
                new_tail2 = parse_keep_alive2_response(resp2_data)
                if not new_tail2:
                    return False
                self.keep_alive_tail = new_tail2
                self.keep_alive_serial_num = (self.keep_alive_serial_num + 1) % 256

                # Seq 3: Type 3, tail=from resp2
                pkt3 = build_keep_alive2_packet(
                    packet_number=self.keep_alive_serial_num,
                    tail=self.keep_alive_tail,
                    packet_type=3,
                    host_ip=self.host_ip,
                    is_first_packet=False,
                )
                if not pkt3:
                    return False
                resp3_data = self._send_and_receive_ka("KA2 Init Seq 3", pkt3)
                if not resp3_data:
                    return False
                new_tail3 = parse_keep_alive2_response(resp3_data)
                if not new_tail3:
                    return False
                self.keep_alive_tail = new_tail3
                self.keep_alive_serial_num = (self.keep_alive_serial_num + 1) % 256

                self._ka2_initialized = True
                logger.info("Keep Alive 2 初始化序列完成。")

            else:  # KA2已初始化，执行循环序列
                logger.debug("执行 Keep Alive 2 循环序列...")
                # Loop Seq 1: Type 1, tail=current
                pkt_loop1 = build_keep_alive2_packet(
                    packet_number=self.keep_alive_serial_num,
                    tail=self.keep_alive_tail,
                    packet_type=1,
                    host_ip=self.host_ip,
                    is_first_packet=False,
                )
                if not pkt_loop1:
                    return False
                resp_loop1_data = self._send_and_receive_ka("KA2 Loop Seq 1", pkt_loop1)
                if not resp_loop1_data:
                    return False
                new_tail_loop1 = parse_keep_alive2_response(resp_loop1_data)
                if not new_tail_loop1:
                    return False
                self.keep_alive_tail = new_tail_loop1
                self.keep_alive_serial_num = (self.keep_alive_serial_num + 1) % 256

                # Loop Seq 2: Type 3, tail=from resp_loop1
                pkt_loop2 = build_keep_alive2_packet(
                    packet_number=self.keep_alive_serial_num,
                    tail=self.keep_alive_tail,
                    packet_type=3,
                    host_ip=self.host_ip,
                    is_first_packet=False,
                )
                if not pkt_loop2:
                    return False
                resp_loop2_data = self._send_and_receive_ka("KA2 Loop Seq 2", pkt_loop2)
                if not resp_loop2_data:
                    return False
                new_tail_loop2 = parse_keep_alive2_response(resp_loop2_data)
                if not new_tail_loop2:
                    return False
                self.keep_alive_tail = new_tail_loop2
                self.keep_alive_serial_num = (self.keep_alive_serial_num + 1) % 256
                logger.debug("Keep Alive 2 循环序列完成。")

            return True  # 整个序列成功

        except socket.timeout:
            logger.warning("Keep Alive 2 序列中发生响应超时。")
            return False
        except socket.error as e:
            logger.error(f"Keep Alive 2 序列中发生 Socket 错误: {e}")
            return False
        except Exception as e:
            logger.error(f"Keep Alive 2 序列中发生意外错误: {e}", exc_info=True)
            return False

    def _send_and_receive_ka(self, log_prefix: str, packet: bytes) -> Optional[bytes]:
        """
        [内部] 辅助函数：发送 Keep Alive 包并接收响应。

        Args:
            log_prefix: 用于日志记录的前缀字符串。
            packet: 要发送的数据包。

        Returns:
            Optional[bytes]: 成功接收到响应则返回响应数据，否则返回 None (已记录错误)。
                             如果发生超时或 Socket 错误，则重新抛出异常。
        """
        if not self.core_socket:
            logger.error(f"{log_prefix}: 套接字未初始化。")
            return None
        try:
            logger.debug(f"发送 {log_prefix}: {packet.hex()}")
            self.core_socket.settimeout(constants.TIMEOUT_KEEP_ALIVE)
            self.core_socket.sendto(packet, (self.server_address, self.drcom_port))
            response_data, server_addr = self.core_socket.recvfrom(1024)  # Buffer size
            logger.debug(
                f"收到 {log_prefix} 响应: {response_data.hex()} from {server_addr}"
            )

            # 校验来源 IP
            if not server_addr or server_addr[0] != self.server_address:
                logger.warning(
                    f"{log_prefix} 收到来自非预期来源 ({server_addr}) 的响应。"
                )
                return None  # 视为无效响应

            # 基本校验：响应不能为空且 Code 必须是 0x07
            if not response_data or not response_data.startswith(
                constants.KEEP_ALIVE_RESP_CODE
            ):
                logger.warning(
                    f"{log_prefix} 收到无效响应或 Code 错误: {response_data[:1].hex() if response_data else 'None'}"
                )
                return None
            return response_data
        except socket.timeout:
            logger.warning(f"{log_prefix} 响应超时。")
            raise  # 将超时异常抛给调用者 (_heartbeat_loop 或 _manage_keep_alive2_sequence) 处理
        except socket.error as e:
            logger.error(f"{log_prefix} 时发生 Socket 错误: {e}")
            raise  # 将 Socket 错误抛给调用者处理

    def _perform_logout(self) -> None:
        """
        [内部] 执行登出操作 (Code 0x06)。

        这是一个“尽力而为”的操作，失败时不重试。
        登出前会尝试获取新的 Challenge Salt。
        此方法会清理所有内部认证状态。
        """
        if not self.auth_info:
            logger.info("未登录或缺少认证信息 (Auth Info)，无需执行登出操作。")
            return
        if not self.core_socket:
            logger.warning("尝试登出但网络套接字未初始化。")
            return

        logger.info("正在尝试执行 [内部] Logout 过程...")
        original_salt = self.salt

        try:
            # 调用内部方法 _perform_challenge
            logout_challenge_ok = self._perform_challenge(
                max_retries=constants.MAX_RETRIES_LOGOUT_CHALLENGE
            )
            if not logout_challenge_ok:
                logger.warning(
                    "登出前获取新的 Challenge salt 失败。将尝试使用旧 salt。"
                )
                if not original_salt:
                    logger.error("无可用 Salt，无法构建登出包，放弃登出。")
                    self.login_success = False
                    self.auth_info = b""
                    self.salt = b""
                    return
                else:
                    self.salt = original_salt

            try:
                if not all(
                    [
                        self.username,
                        self.password,
                        self.salt,
                        self.mac_address,
                        self.auth_info,
                    ]
                ):
                    logger.error("构建登出包失败：缺少必要参数。")
                    return

                logout_packet = build_logout_packet(
                    username=self.username,
                    password=self.password,
                    salt=self.salt,
                    mac=self.mac_address,
                    auth_info=self.auth_info,
                    control_check_status=self.control_check_status,
                    adapter_num=self.adapter_num,
                )
            except ValueError as ve:
                logger.error(f"构建登出包时发生错误: {ve}，放弃登出。")
                return

            logger.debug(f"发送登出数据包: {logout_packet.hex()}")
            self.core_socket.settimeout(constants.TIMEOUT_LOGOUT)
            send_logout_request(
                self.core_socket, self.server_address, self.drcom_port, logout_packet
            )

            try:
                response_data, server_addr = self.core_socket.recvfrom(1024)
                received_ip = server_addr[0] if server_addr else None
                resp_success, message = parse_logout_response(
                    response_data, self.server_address, received_ip
                )
                if resp_success:
                    logger.info(f"登出响应解析结果: {message}")
                else:
                    logger.warning(f"登出响应解析结果: {message}")
            except socket.timeout:
                logger.info("发送登出包后未收到响应 (正常情况)。")
            except socket.error as sock_err_recv:
                logger.warning(f"接收登出响应时发生 Socket 错误: {sock_err_recv}")

        except socket.error as sock_err_send:
            logger.error(f"发送登出包时发生 Socket 错误: {sock_err_send}")
        except Exception as e:
            logger.error(f"执行登出操作时发生意外错误: {e}", exc_info=True)

        finally:
            # 无论成功与否，都清理本地状态
            self.login_success = False
            self.auth_info = b""
            self.salt = b""
            self.keep_alive_serial_num = 0
            self.keep_alive_tail = b"\x00\x00\x00\x00"
            self._ka2_initialized = False
            logger.info("登出流程结束。本地状态已清理 (包括 Keep Alive)。")

    def _heartbeat_loop(self) -> None:
        """
        [内部] 心跳维持的内部循环。

        此方法应在单独的线程中运行，并通过 self._heartbeat_stop_event 控制。
        循环执行 Keep Alive 1 (FF) 和 Keep Alive 2 (07) 序列。
        如果发生任何网络错误、超时或停止事件，循环将终止。
        """

        # 0. 启动检查
        if not self.login_success or not self.auth_info:
            logger.error("心跳线程启动失败：尚未登录或缺少认证信息。")
            return
        if not self.core_socket:
            logger.error("心跳线程启动失败：网络套接字未初始化。")
            return

        logger.info("心跳线程已启动，开始维持在线状态...")

        try:
            # 1. 重置/初始化 KA2 (0x07) 状态
            #    无论何时开始新的心跳循环，都应重新初始化序列号
            self.keep_alive_serial_num = 0
            self.keep_alive_tail = b"\x00\x00\x00\x00"
            self._ka2_initialized = False
            logger.debug("Keep Alive 2 状态已重置。")

            # 2. 开始心跳主循环
            #    循环条件变为检查“停止事件”是否被设置
            while not self._heartbeat_stop_event.is_set():
                # 步骤 A: 执行 Keep Alive 1 (FF 包)
                ka1_packet = self._build_keep_alive1_packet()
                if not ka1_packet:
                    logger.error("构建 Keep Alive 1 (FF) 失败，心跳中断。")
                    break

                try:
                    logger.debug("发送 Keep Alive 1 (FF)...")
                    ka1_response = self._send_and_receive_ka("KA1 (FF)", ka1_packet)

                    if not ka1_response:
                        logger.warning("Keep Alive 1 (FF) 未收到有效响应，可能已掉线。")
                        break

                    # 解析 KA1 响应（目前仅检查 Code 0x07）
                    if not parse_keep_alive1_response(ka1_response):
                        logger.warning("Keep Alive 1 (FF) 响应解析失败，可能已掉线。")
                        break

                except socket.timeout:
                    logger.warning("Keep Alive 1 (FF) 响应超时，可能已掉线。")
                    break
                except socket.error as e_ka1:
                    logger.error(
                        f"发送或接收 Keep Alive 1 (FF) 时发生 Socket 错误: {e_ka1}"
                    )
                    break
                except Exception as e_ka1_other:
                    logger.error(
                        f"处理 Keep Alive 1 (FF) 时发生意外错误: {e_ka1_other}",
                        exc_info=True,
                    )
                    break

                # 检查是否在KA1之后收到了停止信号
                if self._heartbeat_stop_event.is_set():
                    logger.info("KA1 后检测到停止信号，退出心跳循环。")
                    break

                # 步骤 B: 执行 Keep Alive 2 (07 包) 序列

                # _manage_keep_alive2_sequence 内部会处理初始化和循环序列
                if not self._manage_keep_alive2_sequence():
                    logger.error("Keep Alive 2 (07) 序列执行失败，心跳中断。")
                    break  # KA2 序列失败，退出 while 循环

                # 步骤 C: 等待间隔
                logger.debug(
                    f"本轮心跳完成，等待 {constants.SLEEP_KEEP_ALIVE_INTERVAL} 秒..."
                )

                # 使用 Event.wait() 来实现可中断的休眠
                was_interrupted = self._heartbeat_stop_event.wait(
                    timeout=constants.SLEEP_KEEP_ALIVE_INTERVAL
                )

                if was_interrupted:
                    # 收到停止信号，跳出循环
                    logger.info("心跳等待间隔被中断，准备退出循环。")
                    break

        except Exception as e_loop:
            # 捕获循环（例如 KA2 状态重置）中发生的意外错误
            logger.error(f"心跳循环中发生意外错误: {e_loop}", exc_info=True)
        finally:
            # 无论循环如何退出，都执行这里：
            logger.info("心跳线程已停止。")
            self.login_success = False  # 标记为未登录

    # =========================================================================
    # 公开 API
    # =========================================================================

    def login(self) -> bool:
        """
        [API] 执行完整的登录流程（Challenge + Login）。

        如果已登录，此方法将直接返回 True。
        如果未登录，将依次执行 Challenge 和 Login 步骤。

        Returns:
            bool: 登录成功（或已登录）返回 True，
                  登录失败（配置错误、网络超时、服务器拒绝等）返回 False。
        """
        logger.info("API: 收到 login() 请求...")
        if self._heartbeat_thread and self._heartbeat_thread.is_alive():
            logger.info("API: 已登录且心跳正在运行。")
            return True

        # 确保旧线程（如果存在）已停止
        self.stop_heartbeat()

        # 调用内部方法
        if self._perform_challenge():
            if self._perform_login():
                logger.info("API: 登录成功。")
                return True
            else:
                logger.error("API: 登录过程失败。")
                return False
        else:
            logger.error("API: Challenge 过程失败。")
            return False

    def start_heartbeat(self) -> None:
        """
        [API] 启动后台心跳维持线程。

        此方法会启动一个独立的守护线程 (Daemon Thread) 来自动执行心跳循环。

        注意：
        - 必须在 `login()` 成功后调用。
        - 如果心跳线程已在运行，此方法会跳过。
        """
        if self._heartbeat_thread and self._heartbeat_thread.is_alive():
            logger.warning("API: 心跳线程已在运行。")
            return

        if not self.login_success:
            logger.error("API: 启动心跳失败，请先调用 login() 并确保其返回 True。")
            return

        logger.info("API: 正在启动心跳线程...")
        self._heartbeat_stop_event.clear()
        self._heartbeat_thread = threading.Thread(
            target=self._heartbeat_loop,
            daemon=True,  # 设置为守护线程，主程序退出时它也会退出
        )
        self._heartbeat_thread.start()

    def stop_heartbeat(self) -> None:
        """
        [API] 停止后台心跳维持线程。

        此方法会向心跳线程发送停止信号，并等待其退出。
        """
        logger.info("API: 正在请求停止心跳线程...")
        self._heartbeat_stop_event.set()
        if self._heartbeat_thread and self._heartbeat_thread.is_alive():
            # 等待一段时间确保线程退出
            self._heartbeat_thread.join(timeout=constants.TIMEOUT_KEEP_ALIVE + 2.0)
            if self._heartbeat_thread.is_alive():
                logger.warning("API: 心跳线程未能及时停止。")
        self._heartbeat_thread = None
        logger.info("API: 心跳线程已停止。")

    def logout(self) -> None:
        """
        [API] 停止心跳并执行登出操作。

        这是一个完整的清理操作，它会：
        1. 停止正在运行的心跳线程 (`stop_heartbeat`)。
        2. 执行“尽力而为”的登出包发送 (`_perform_logout`)。
        3. 清理本地的所有认证状态（Salt, Auth Info 等）。
        """
        logger.info("API: 收到 logout() 请求...")
        self.stop_heartbeat()  # 停止心跳
        self._perform_logout()  # 调用内部方法执行登出并清理状态
        logger.info("API: 登出流程完毕。")
