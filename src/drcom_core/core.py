# /src/drcom_core/core.py
"""
Dr.COM 认证核心逻辑模块。

负责加载配置、初始化网络、执行认证流程 (Challenge -> Login)、
维持心跳 (Keep Alive) 以及处理登出。
"""

import logging
import os
import random
import socket
import sys
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
from ..drcom_protocol.login import (
    _build_login_packet,
    parse_login_response,
)
from ..drcom_protocol.login import (
    send_login_request as send_login_request_login,  # 别名区分
)
from ..drcom_protocol.logout import (
    _build_logout_packet,
    parse_logout_response,
)
from ..drcom_protocol.logout import (
    send_logout_request as send_logout_request,  # 复用发送函数但别名区分
)

# 获取当前模块的 logger 实例
logger = logging.getLogger(__name__)
# 注意：日志级别和处理器通常在 main.py 配置


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
        # ... (其他配置属性) ...
        salt (bytes): 当前有效的 Challenge Salt。
        auth_info (bytes): 登录成功后获取的认证信息 (Tail)，用于心跳。
        login_success (bool): 当前是否处于登录成功状态。
        core_socket (socket.socket): 用于与服务器通信的 UDP 套接字。
    """

    def __init__(self) -> None:
        """初始化 DrcomCore 类，加载配置并初始化网络。"""
        logger.info("Dr.Com-Core 正在初始化...")
        self.salt: bytes = b""
        self.auth_info: bytes = b""
        self.login_success: bool = False
        self.core_socket: Optional[socket.socket] = None  # 初始化为 None

        try:
            self._load_config()  # 加载所有配置
            self._init_socket()  # 初始化网络套接字
        except Exception as e:
            logger.critical(f"初始化失败: {e}")
            logger.critical(traceback.format_exc())
            # 使用 sys.exit() 并提供错误信息，方便外部捕获
            sys.exit(f"初始化过程中发生致命错误: {e}")

        logger.info("Dr.Com-Core 初始化成功。")

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

        # --- 加载 .env 文件 ---
        env_path = Path(__file__).resolve().parent.parent.parent / ".env"
        if env_path.exists():
            logger.debug(f"发现 .env 文件: {env_path}")
            load_dotenv(dotenv_path=env_path, override=True)
        else:
            logger.warning(f".env 文件未找到: {env_path}，将仅依赖环境变量。")

        # --- 加载基本网络配置 ---
        self.server_address: str = os.getenv("SERVER_IP", constants.DEFAULT_SERVER_IP)
        self.drcom_port: int = int(
            os.getenv("DRCOM_PORT", constants.DEFAULT_DRCOM_PORT)
        )
        self.campus_ip_prefix: str = os.getenv(
            "CAMPUS_IP_PREFIX", constants.DEFAULT_CAMPUS_IP_PREFIX
        )

        # --- 自动检测或加载 IP 和 MAC ---
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
            if fallback_ip:
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
                # 兼容带分隔符和不带分隔符的格式
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
                # 确保是有效的十六进制字符串
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
                    "请使用 12 位十六进制格式 (可包含分隔符)。将使用 0 作为 MAC 地址。"
                )
                self.mac_address = 0  # 保持为 0
        else:
            logger.warning("MAC 地址最终未能确定，将使用 0。")

        # --- 加载用户凭证 ---
        self.username: Optional[str] = os.getenv("USERNAME")
        self.password: Optional[str] = os.getenv("PASSWORD")

        # --- 加载主机信息 ---
        self.host_name: str = os.getenv("HOST_NAME", constants.DEFAULT_HOST_NAME)
        self.host_os: str = os.getenv("HOST_OS", constants.DEFAULT_HOST_OS)

        # --- 加载其他协议相关参数 (字节串) ---
        try:
            self.adapter_num: bytes = bytes.fromhex(os.getenv("ADAPTERNUM", "01"))
            self.ipdog: bytes = bytes.fromhex(os.getenv("IPDOG", "01"))
            self.auth_version: bytes = bytes.fromhex(os.getenv("AUTH_VERSION", "0a00"))
            self.control_check_status: bytes = bytes.fromhex(
                os.getenv("CONTROL_CHECK_STATUS", "20")
            )
            self.keep_alive_version: bytes = bytes.fromhex(
                os.getenv("KEEP_ALIVE_VERSION", "dc02")
            )
        except ValueError as e:
            logger.critical(
                f"加载协议参数时发生十六进制转换错误: {e}。请检查 .env 文件或环境变量。"
            )
            sys.exit(f"配置错误: {e}")

        # --- 加载 ROR 状态 (布尔值) ---
        self.ror_status: bool = (
            os.getenv("ROR_STATUS", str(False)).lower()
            in constants.BOOLEAN_TRUE_STRINGS
        )

        # --- 加载网络配置 ---
        self.dhcp_address: str = os.getenv("DHCP_SERVER", constants.DEFAULT_DHCP_SERVER)
        self.primary_dns: str = os.getenv("PRIMARY_DNS", constants.DEFAULT_PRIMARY_DNS)

        # --- 配置项校验 ---
        required_configs = {
            "服务器地址 (SERVER_IP)": self.server_address,
            "用户名 (USERNAME)": self.username,
            "密码 (PASSWORD)": self.password,
            "本机IP (HOST_IP)": self.host_ip
            and self.host_ip != "0.0.0.0",  # IP 不能是 0.0.0.0
            "MAC 地址 (MAC)": self.mac_address != 0,  # MAC 不能是 0
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

    def perform_challenge(
        self, max_retries: int = constants.MAX_RETRIES_CHALLENGE
    ) -> bool:
        """
        执行 Challenge 过程，尝试从服务器获取 Salt。

        Args:
            max_retries: 最大重试次数。

        Returns:
            bool: 成功获取 Salt 则返回 True，否则返回 False。
        """
        logger.info("正在执行 Challenge 过程...")
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
                # Socket 错误后稍作等待可能有助于恢复
                time.sleep(constants.SLEEP_SOCKET_ERROR)
            except Exception as e:
                logger.error(
                    f"Challenge 第 {attempt} 次尝试时发生意外错误: {e}", exc_info=True
                )

            retries += 1
            if retries < max_retries:
                # 随机等待一段时间后重试
                wait_time = random.uniform(0.5, 1.5)
                logger.debug(f"等待 {wait_time:.2f} 秒后重试...")
                time.sleep(wait_time)

        logger.error("Challenge 过程失败 (超过最大重试次数)。")
        self.salt = b""  # 清空 salt
        return False

    def perform_login(self, max_retries: int = constants.MAX_RETRIES_LOGIN) -> bool:
        """
        执行登录认证过程。

        Args:
            max_retries: 最大重试次数。

        Returns:
            bool: 登录成功则返回 True，否则返回 False。
        """
        logger.info("正在执行登录认证...")
        if not self.core_socket:
            logger.error("登录失败：网络套接字未初始化。")
            return False
        if not self.salt:
            logger.error("登录失败：未获取到 Salt。请先成功执行 Challenge。")
            return False
        # 确认必要配置存在
        if not all([self.username, self.password, self.host_ip, self.mac_address]):
            logger.error("登录失败：缺少必要的配置信息 (用户名、密码、IP 或 MAC)。")
            return False

        retries = 0
        while retries < max_retries:
            attempt = retries + 1
            try:
                # 1. 构建登录数据包
                logger.info(f"第 {attempt}/{max_retries} 次尝试构建和发送登录请求...")
                login_packet = _build_login_packet(
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

                # 2. 发送登录数据包
                self.core_socket.settimeout(constants.TIMEOUT_LOGIN)
                send_login_request_login(  # 使用别名后的发送函数
                    self.core_socket, self.server_address, self.drcom_port, login_packet
                )

                # 3. 接收登录响应
                response_data, server_addr = self.core_socket.recvfrom(
                    1024
                )  # Buffer size

                # 4. 解析登录响应
                # 确保 server_addr 不为 None 才访问其元素
                received_ip = server_addr[0] if server_addr else None
                if not received_ip:
                    logger.warning("收到登录响应但无法获取来源 IP 地址。")
                    continue  # 进行下一次重试

                is_success, auth_info_data, error_code, message = parse_login_response(
                    response_data, self.server_address, received_ip
                )

                # 5. 处理结果
                if is_success:
                    if auth_info_data:  # 确保 auth_info 不是 None
                        self.auth_info = auth_info_data
                        self.login_success = True
                        logger.info(f"登录成功！ ({message})")
                        return True  # 登录成功，退出函数
                    else:
                        # 成功响应但未能提取 auth_info 是异常情况
                        logger.error(f"登录响应成功，但无法提取认证信息。({message})")
                        # 这种情况也视为失败，但不一定需要重试
                        return False

                else:  # is_success is False
                    logger.error(f"登录失败: {message}")
                    # 根据错误码判断是否需要停止重试
                    if (
                        error_code is not None
                        and error_code in constants.NO_RETRY_ERROR_CODES
                    ):
                        logger.warning(
                            "此错误通常由配置或账户问题引起，停止登录尝试。"
                            "请检查配置或联系管理员。"
                        )
                        return False  # 确定性失败，无需重试

            except ValueError as ve:  # 捕获构建错误
                logger.error(f"构建登录包时发生配置或数据错误: {ve}")
                logger.debug(traceback.format_exc())
                return False  # 构建错误通常不应重试
            except socket.timeout:
                logger.warning(f"登录第 {attempt} 次尝试接收响应超时。")
            except socket.error as e:
                logger.error(f"登录第 {attempt} 次尝试时发生 Socket 错误: {e}。")
                time.sleep(constants.SLEEP_SOCKET_ERROR)  # Socket 错误后等待
            except Exception as e:
                logger.error(
                    f"登录第 {attempt} 次尝试时发生意外错误: {e}", exc_info=True
                )

            # 准备下一次重试
            retries += 1
            if retries < max_retries:
                wait_time = random.uniform(1.0, 3.0)  # 重试间隔
                logger.debug(f"等待 {wait_time:.2f} 秒后重试登录...")
                time.sleep(wait_time)

        logger.error("登录失败 (超过最大重试次数)。")
        self.login_success = False
        self.auth_info = b""  # 清空认证信息
        return False

    ################################################################

    def perform_logout(self) -> None:
        """
        执行登出操作 (Code 0x06)。
        这是一个“尽力而为”的操作，失败时不重试。
        登出前会尝试获取新的 Challenge Salt。
        """
        # 1. 检查是否需要登出 (是否有有效的 auth_info)
        if not self.auth_info:
            logger.info("未登录或缺少认证信息 (Auth Info)，无需执行登出操作。")
            return
        if not self.core_socket:
            logger.warning("尝试登出但网络套接字未初始化。")
            return  # 无法发送登出包

        logger.info("正在尝试执行登出...")
        original_salt = self.salt  # 保存当前的 salt 以备后用
        logout_success = False  # 标记登出操作是否完成 (客户端角度)

        try:
            # 2. 尝试获取新的 Challenge salt (仅一次)
            logout_challenge_ok = self.perform_challenge(
                max_retries=constants.MAX_RETRIES_LOGOUT_CHALLENGE
            )
            if not logout_challenge_ok:
                logger.warning(
                    "登出前获取新的 Challenge salt 失败。"
                    "将尝试使用之前的 salt (如果存在) 构建登出包。"
                )
                if not original_salt:
                    logger.error("无可用 Salt，无法构建登出包，放弃登出。")
                    # 清理状态，因为无法执行登出
                    self.login_success = False
                    self.auth_info = b""
                    self.salt = b""
                    return  # 无法继续
                else:
                    self.salt = original_salt  # 确保使用旧 salt

            # 3. 构建登出包 (使用当前 self.salt)
            try:
                # 确保登出所需参数存在
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
                    return  # 无法构建，放弃

                logout_packet = _build_logout_packet(
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
                return  # 构建失败则不发送

            # 4. 发送登出包
            logger.debug(f"发送登出数据包: {logout_packet.hex()}")
            self.core_socket.settimeout(constants.TIMEOUT_LOGOUT)
            send_logout_request(  # 使用别名后的发送函数
                self.core_socket, self.server_address, self.drcom_port, logout_packet
            )

            # 5. 尝试接收并解析响应 (仅用于日志，不影响登出状态判定)
            try:
                response_data, server_addr = self.core_socket.recvfrom(1024)
                received_ip = server_addr[0] if server_addr else None
                resp_success, message = parse_logout_response(
                    response_data, self.server_address, received_ip
                )
                if resp_success:
                    logger.info(f"登出响应解析结果: {message}")
                    logout_success = True  # 收到成功响应
                else:
                    logger.warning(f"登出响应解析结果: {message}")
                    # 即使收到非预期响应，客户端已发送登出包，也可能视为已尝试
                    logout_success = True  # 或 False，取决于策略
            except socket.timeout:
                logger.info("发送登出包后未收到响应 (正常情况，视为客户端已尝试登出)。")
                logout_success = True  # 超时视为成功登出 (客户端已尽力)
            except socket.error as sock_err_recv:
                logger.warning(f"接收登出响应时发生 Socket 错误: {sock_err_recv}")
                logout_success = True  # 即使接收出错，也认为客户端已尝试登出

        except socket.error as sock_err_send:
            logger.error(f"发送登出包时发生 Socket 错误: {sock_err_send}")
            # 发送失败，登出未成功，但仍需清理状态
        except Exception as e:
            logger.error(f"执行登出操作时发生意外错误: {e}", exc_info=True)
            # 发生意外错误，状态未知，但仍清理

        finally:
            # 无论登出尝试是否成功或遇到何种错误，都清理客户端状态
            self.login_success = False
            self.auth_info = b""
            self.salt = b""  # 清理 salt
            logger.info("登出流程结束。本地状态已清理。")

    def run(self) -> None:
        """启动认证和心跳的主循环。"""
        logger.info("启动 Dr.Com 核心认证流程...")
        try:
            while True:
                if not self.login_success:
                    logger.info("当前未登录，尝试进行认证...")
                    if self.perform_challenge():
                        if self.perform_login():
                            # 登录成功，启动心跳
                            logger.info("登录成功，启动心跳维持...")
                            self.start_keep_alive()
                            # 从 start_keep_alive 返回意味着心跳中断或失败
                            logger.info("心跳已停止，将尝试重新认证。")
                            # start_keep_alive 的 finally 块已设置 self.login_success = False
                        else:  # perform_login 返回 False
                            # 登录过程遇到不可重试错误或已达最大次数
                            logger.error("登录过程失败，无法继续。")
                            # 可以选择等待后退出，或直接退出
                            logger.info(
                                f"程序将在 {constants.SLEEP_LOGIN_FAIL_EXIT} 秒后退出。"
                            )
                            time.sleep(constants.SLEEP_LOGIN_FAIL_EXIT)
                            break  # 退出主循环
                    else:  # perform_challenge 返回 False
                        logger.error("Challenge 失败，无法进行登录。")
                        logger.info(
                            f"将在 {constants.SLEEP_CHALLENGE_FAIL_RETRY} 秒后重试 Challenge..."
                        )
                        time.sleep(constants.SLEEP_CHALLENGE_FAIL_RETRY)
                        # 继续下一次循环尝试 Challenge
                else:
                    # 理论上不应进入此分支，因为 login_success 为 True 时应在 start_keep_alive 循环中
                    logger.warning(
                        "检测到异常状态 (login_success=True 但未在心跳中)，"
                        f"将在 {constants.SLEEP_ABNORMAL_STATE_RETRY} 秒后强制重置状态并尝试重新认证。"
                    )
                    self.login_success = False  # 强制重置状态
                    time.sleep(constants.SLEEP_ABNORMAL_STATE_RETRY)
                    # 继续下一次循环尝试认证

        except KeyboardInterrupt:
            logger.info("用户请求退出 (Ctrl+C)。")
        except SystemExit as e:
            logger.info(f"程序因调用 sys.exit() 而退出: {e}")
            # 通常在初始化或配置加载失败时发生
        except Exception as e:
            logger.critical(f"主循环发生严重错误，程序即将退出: {e}", exc_info=True)
            # 记录详细错误信息
        finally:
            logger.info("执行最终清理...")
            # 尝试执行登出操作 (如果 core_socket 存在且之前可能登录过)
            if self.core_socket:
                self.perform_logout()  # perform_logout 内部会检查 auth_info

            # 关闭 socket
            if self.core_socket and not self.core_socket._closed:
                try:
                    self.core_socket.close()
                    logger.info("网络套接字已关闭。")
                except Exception as e_close:
                    logger.error(f"最终关闭 socket 时出错: {e_close}")
            else:
                logger.debug("最终清理：网络套接字不存在或已关闭。")

            logger.info("Dr.Com Core 已停止。")
