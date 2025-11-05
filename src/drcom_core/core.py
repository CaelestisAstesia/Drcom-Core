# /src/drcom_core/core.py
"""
Dr.COM 认证核心逻辑模块。

负责加载配置、初始化网络、执行认证流程、
维持心跳以及处理登出。
"""

import logging
import os
import random
import socket
import sys
import threading
import time
import traceback
from pathlib import Path
from typing import Optional, Tuple

import netifaces
from dotenv import load_dotenv

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
    Dr.COM 认证核心逻辑类。

    管理认证状态、网络套接字以及与服务器的交互流程。

    Attributes:
        server_address (str): Dr.COM 服务器 IP 地址。
        drcom_port (int): Dr.COM 服务器认证端口。
        username (str): 用户名。
        password (str): 密码。
        host_ip (str): 本机 IP 地址。
        mac_address (int): 本机 MAC 地址的整数表示。
        salt (bytes): 当前有效的 Challenge Salt。
        auth_info (bytes): 登录成功后获取的认证信息 (Tail)，用于心跳。
        login_success (bool): 当前是否处于登录成功状态。
        core_socket (socket.socket): 用于与服务器通信的 UDP 套接字。
        keep_alive_serial_num (int): Keep Alive 2 (07 包) 的当前序列号。
        keep_alive_tail (bytes): Keep Alive 2 (07 包) 的当前 tail 值。
        _ka2_initialized (bool): 标记 Keep Alive 2 初始化序列是否已完成。
    """

    def __init__(self) -> None:
        """初始化 DrcomCore 类，加载配置并初始化网络。"""
        logger.info("Dr.Com-Core 正在初始化...")
        self.salt: bytes = b""
        self.auth_info: bytes = b""
        self.login_success: bool = False
        self.core_socket: Optional[socket.socket] = None

        # 初始化 Keep Alive 2 状态
        self.keep_alive_serial_num: int = 0
        self.keep_alive_tail: bytes = b"\x00\x00\x00\x00"  # 初始 tail 通常是 0
        self._ka2_initialized: bool = False  # 标记 KA2 初始化序列是否完成

        self._heartbeat_stop_event = threading.Event()
        self._heartbeat_thread: Optional[threading.Thread] = None

        try:
            self._load_config()  # 加载所有配置
            self._init_socket()  # 初始化网络套接字
        except Exception as e:
            logger.critical(f"初始化失败: {e}")
            logger.critical(traceback.format_exc())
            # 使用 sys.exit() 并提供错误信息，方便外部捕获
            sys.exit(f"初始化过程中发生致命错误: {e}")

        logger.info("Dr.Com-Core 初始化成功。")

    # 内部核心逻辑 (Internal Methods)

    def _init_socket(self) -> None:
        """初始化 UDP 网络套接字并绑定到指定 IP 和端口。"""
        logger.info("正在初始化网络套接字...")
        if not hasattr(self, "bind_ip") or not hasattr(self, "drcom_port"):
            raise RuntimeError("配置未加载，无法初始化套接字。")

        try:
            self.core_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            # 设置 SO_REUSEADDR 允许快速重启绑定相同地址
            self.core_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # 绑定到检测到的或配置的 IP 和端口
            self.core_socket.bind((self.bind_ip, self.drcom_port))
            # 注意：超时在具体操作前设置更灵活，此处不设置默认超时
            logger.info(
                f"网络套接字初始化成功，已绑定到 {self.bind_ip}:{self.drcom_port}"
            )
        except socket.error as e:
            logger.error(f"网络套接字初始化失败: {e}")
            raise  # 将异常抛给 __init__ 处理

    def _detect_campus_interface_info(
        self, campus_ip_prefix: str
    ) -> Tuple[Optional[str], Optional[str]]:
        """
        自动检测符合指定 IP 前缀的校园网接口的 IP 地址和 MAC 地址。

        Args:
            campus_ip_prefix: 校园网 IP 地址的前缀 (例如 "49.")。

        Returns:
            Tuple[Optional[str], Optional[str]]: (ip, mac_address) 元组。
                                                MAC 地址以 "XX:XX:XX:XX:XX:XX" 格式返回。
                                                找不到则返回 (None, None)。
        """
        logger.info(f"正在自动检测校园网接口信息 (IP 前缀: {campus_ip_prefix})...")
        try:
            interfaces = netifaces.interfaces()
        except Exception as e:
            logger.warning(f"无法获取网络接口列表: {e}")
            return None, None

        for interface in interfaces:
            try:
                addresses = netifaces.ifaddresses(interface)
            except ValueError:
                logger.debug(f"无法获取接口 '{interface}' 的地址信息，跳过。")
                continue  # 有些虚拟接口可能没有地址

            detected_ip: Optional[str] = None
            detected_mac: Optional[str] = None

            # 1. 查找符合前缀的 IPv4 地址
            if socket.AF_INET in addresses:
                for addr_info in addresses[socket.AF_INET]:
                    ip = addr_info.get("addr")
                    if ip and ip.startswith(campus_ip_prefix):
                        detected_ip = ip
                        logger.debug(
                            f"在接口 '{interface}' 上找到符合条件的 IP: {detected_ip}"
                        )
                        break

            # 2. 如果找到 IP，获取该接口的 MAC 地址
            if detected_ip and netifaces.AF_LINK in addresses:
                for link_info in addresses[netifaces.AF_LINK]:
                    mac = link_info.get("addr")
                    # 基本的 MAC 地址格式校验
                    if (
                        mac
                        and len(mac) == 17
                        and mac.count(constants.MAC_SEPARATOR) == 5
                    ):
                        detected_mac = mac
                        logger.debug(
                            f"在接口 '{interface}' 上找到 MAC 地址: {detected_mac}"
                        )
                        break

            # 3. 如果 IP 和 MAC 都找到，返回结果
            if detected_ip and detected_mac:
                logger.info(
                    f"成功检测到接口 '{interface}' 的 IP: {detected_ip} 和 MAC: {detected_mac}"
                )
                return detected_ip, detected_mac

        logger.warning(
            f"未能自动检测到 IP 前缀为 '{campus_ip_prefix}' 的校园网接口信息。"
        )
        return None, None

    def _load_config(self) -> None:
        """
        从 .env 文件或环境变量加载配置。
        优先尝试自动检测 IP 和 MAC 地址。
        如果缺少必要配置项，将记录错误并退出程序。
        """
        logger.info("正在加载配置...")

        # 加载 .env 文件
        env_path = Path(__file__).resolve().parent.parent.parent / ".env"
        if env_path.exists():
            logger.debug(f"发现 .env 文件: {env_path}")
            load_dotenv(dotenv_path=env_path, override=True)
        else:
            logger.warning(f".env 文件未找到: {env_path}，将仅依赖环境变量。")

        # 加载基本网络配置
        self.server_address: str = os.getenv("SERVER_IP", constants.DEFAULT_SERVER_IP)
        self.drcom_port: int = int(
            os.getenv("DRCOM_PORT", constants.DEFAULT_DRCOM_PORT)
        )
        self.campus_ip_prefix: str = os.getenv(
            "CAMPUS_IP_PREFIX", constants.DEFAULT_CAMPUS_IP_PREFIX
        )

        # 自动检测或加载 IP 和 MAC
        detected_ip: Optional[str] = None
        detected_mac_str: Optional[str] = None  # 带分隔符的 MAC
        auto_detect_enabled: bool = (
            os.getenv(
                "AUTO_DETECT_CAMPUS_INTERFACE",
                str(constants.DEFAULT_AUTO_DETECT_INTERFACE),
            ).lower()
            in constants.BOOLEAN_TRUE_STRINGS
        )

        if auto_detect_enabled:
            detected_ip, detected_mac_str = self._detect_campus_interface_info(
                self.campus_ip_prefix
            )

        # 确定最终 IP
        if detected_ip:
            self.host_ip: str = detected_ip
            logger.info(f"使用自动检测到的 IP 地址: {self.host_ip}")
        else:
            fallback_ip: Optional[str] = os.getenv("HOST_IP")
            if fallback_ip and fallback_ip != "0.0.0.0":
                self.host_ip = fallback_ip
                logger.info(f"使用环境变量或 .env 中的 HOST_IP: {self.host_ip}")
            else:
                error_msg = (
                    "无法自动检测或从配置中获取有效的校园网 IP 地址 (HOST_IP)。"
                    "请检查网络接口或手动配置。"
                )
                logger.critical(error_msg)
                sys.exit(error_msg)
        self.bind_ip: str = self.host_ip  # Socket 绑定 IP

        # 确定最终 MAC
        final_mac_str_no_sep: Optional[str] = None
        if detected_mac_str:
            final_mac_str_no_sep = detected_mac_str.replace(constants.MAC_SEPARATOR, "")
            logger.info(f"使用自动检测到的 MAC 地址: {detected_mac_str}")
        else:
            mac_from_env: Optional[str] = os.getenv("MAC")
            if mac_from_env:
                final_mac_str_no_sep = mac_from_env.replace("-", "").replace(
                    constants.MAC_SEPARATOR, ""
                )
                logger.info(f"使用环境变量或 .env 中的 MAC 地址: {mac_from_env}")
            else:
                logger.warning("未能自动检测或从配置中获取 MAC 地址。")

        # 将 MAC 字符串转为整数
        self.mac_address: int = 0
        if final_mac_str_no_sep:
            try:
                # 校验格式和长度
                if len(final_mac_str_no_sep) == 12 and all(
                    c in "0123456789abcdefABCDEF" for c in final_mac_str_no_sep
                ):
                    self.mac_address = int(final_mac_str_no_sep, 16)
                    logger.debug(f"最终使用的 MAC 地址 (整数): {hex(self.mac_address)}")
                else:
                    raise ValueError("MAC 地址格式或长度无效")
            except ValueError as e:
                logger.error(
                    f"无效的 MAC 地址格式: '{final_mac_str_no_sep}' ({e})。"
                    "请使用 12 位十六进制格式。将使用 0 作为 MAC 地址。"
                )
                self.mac_address = 0  # 返回 0 表示无效或未找到
        else:
            logger.warning("MAC 地址最终未能确定，将使用 0。")
            self.mac_address = 0  # 返回 0

        # 加载用户凭证
        self.username: Optional[str] = os.getenv("USERNAME")
        self.password: Optional[str] = os.getenv("PASSWORD")

        # 加载主机信息
        self.host_name: str = os.getenv("HOST_NAME", constants.DEFAULT_HOST_NAME)
        self.host_os: str = os.getenv("HOST_OS", constants.DEFAULT_HOST_OS)

        # 加载其他协议相关参数 (字节串)
        try:
            self.adapter_num: bytes = bytes.fromhex(os.getenv("ADAPTERNUM", "01"))
            self.ipdog: bytes = bytes.fromhex(os.getenv("IPDOG", "01"))
            self.auth_version: bytes = bytes.fromhex(os.getenv("AUTH_VERSION", "0a00"))
            self.control_check_status: bytes = bytes.fromhex(
                os.getenv("CONTROL_CHECK_STATUS", "20")
            )
            # 注意: keep_alive_version 在 constants.py 中有默认值，这里仍允许覆盖
            self.keep_alive_version: bytes = bytes.fromhex(
                os.getenv("KEEP_ALIVE_VERSION", constants.KEEP_ALIVE_VERSION.hex())
            )
        except ValueError as e:
            logger.critical(
                f"加载协议参数时发生十六进制转换错误: {e}。请检查 .env 文件或环境变量。"
            )
            sys.exit(f"配置错误: {e}")

        # 加载 ROR 状态 (布尔值)
        self.ror_status: bool = (
            os.getenv("ROR_STATUS", str(False)).lower()
            in constants.BOOLEAN_TRUE_STRINGS
        )

        # 加载网络配置
        self.dhcp_address: str = os.getenv("DHCP_SERVER", constants.DEFAULT_DHCP_SERVER)
        self.primary_dns: str = os.getenv("PRIMARY_DNS", constants.DEFAULT_PRIMARY_DNS)

        # 配置项校验
        required_configs = {
            "服务器地址 (SERVER_IP)": self.server_address,
            "用户名 (USERNAME)": self.username,
            "密码 (PASSWORD)": self.password,
            "本机IP (HOST_IP)": self.host_ip and self.host_ip != "0.0.0.0",
            "MAC 地址 (MAC)": self.mac_address != 0,
        }
        missing_configs = [
            name for name, value in required_configs.items() if not value
        ]

        if missing_configs:
            details = "; ".join(missing_configs)
            error_msg = (
                f"缺少必要的配置项: {details}。请检查网络连接、.env 文件或环境变量。"
            )
            logger.critical(error_msg)
            sys.exit(error_msg)

        logger.info("所有配置加载成功。")

    def _perform_challenge(
        self, max_retries: int = constants.MAX_RETRIES_CHALLENGE
    ) -> bool:
        """
        执行 Challenge 过程，尝试从服务器获取 Salt。

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
        执行登录认证过程。

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
        构建 Keep Alive 1 (FF 包 / 心跳包 1)。
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
        管理并发送 Keep Alive 2 (07 包) 序列，并处理响应以更新状态。
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
        辅助函数：发送 Keep Alive 包并接收响应。

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
        执行登出操作 (Code 0x06)。
        这是一个“尽力而为”的操作，失败时不重试。
        登出前会尝试获取新的 Challenge Salt。
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
            self.login_success = False
            self.auth_info = b""
            self.salt = b""
            self.keep_alive_serial_num = 0
            self.keep_alive_tail = b"\x00\x00\x00\x00"
            self._ka2_initialized = False
            logger.info("登出流程结束。本地状态已清理 (包括 Keep Alive)。")

    # 公开 API

    def login(self) -> bool:
        """
        执行完整的登录流程（Challenge + Login）。
        成功则返回 True 并设置好内部状态 (self.auth_info)，失败则返回 False。
        """
        logger.info("API: 收到 login() 请求...")
        if self.login_success:
            logger.info("API: 已登录，无需重复操作。")
            return True

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

    def _heartbeat_loop(self) -> None:
        """
        心跳维持的内部循环。
        此方法应在单独的线程中运行，并通过 self._heartbeat_stop_event 控制。
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

                # 步骤 B: 执行 Keep Alive 2 (07 包) 序列

                # _manage_keep_alive2_sequence 内部会处理初始化和循环序列
                if not self._manage_keep_alive2_sequence():
                    logger.error("Keep Alive 2 (07) 序列执行失败，心跳中断。")
                    break  # KA2 序列失败，退出 while 循环

                # 步骤 C: 等待间隔
                logger.debug(
                    f"本轮心跳完成，等待 {constants.SLEEP_KEEP_ALIVE_INTERVAL} 秒..."
                )

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

    def start_heartbeat(self) -> None:
        """API: 启动后台心跳维持线程。"""
        if self._heartbeat_thread and self._heartbeat_thread.is_alive():
            logger.warning("API: 心跳线程已在运行。")
            return

        logger.info("API: 正在启动心跳线程...")
        self._heartbeat_stop_event.clear()
        self._heartbeat_thread = threading.Thread(
            target=self._heartbeat_loop,
            daemon=True,  # 设置为守护线程，主程序退出时它也会退出
        )
        self._heartbeat_thread.start()

    def stop_heartbeat(self) -> None:
        """API: 停止后台心跳维持线程。"""
        logger.info("API: 正在请求停止心跳线程...")
        self._heartbeat_stop_event.set()
        if self._heartbeat_thread and self._heartbeat_thread.is_alive():
            # 等待一段时间确保线程退出
            self._heartbeat_thread.join(timeout=constants.TIMEOUT_KEEP_ALIVE + 2.0)
            if self._heartbeat_thread.is_alive():
                logger.warning("API: 心跳线程未能及时停止。")
        self._heartbeat_thread = None

    def logout(self) -> None:
        """API: 停止心跳并执行登出操作。"""
        logger.info("API: 收到 logout() 请求...")
        self.stop_heartbeat()  # 停止心跳
        self._perform_logout()  # 调用内部方法
        logger.info("API: 登出流程完毕。")
