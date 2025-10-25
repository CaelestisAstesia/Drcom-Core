# /src/drcom_core/core.py

import logging
import os
import random
import socket
import sys
import time
import traceback
from pathlib import Path
from typing import Optional, Tuple

import netifaces  # 依赖 netifaces 来获取网络接口信息
from dotenv import load_dotenv

# 导入 Challenge 模块
from ..drcom_protocol.challenge import (
    receive_challenge_response,
    send_challenge_request,
)

# 导入 Login 模块
from ..drcom_protocol.login import (
    _build_login_packet,
    parse_login_response,
)
from ..drcom_protocol.login import (
    send_login_request as send_login_request_login,  # 别名以区分
)

# 导入 Logout 模块
# 确保 logout.py 中的函数已正确导入
from ..drcom_protocol.logout import (
    _build_logout_packet,
    parse_logout_response,
)
from ..drcom_protocol.logout import (
    send_login_request as send_logout_request,  # 复用发送函数，但别名区分
)

# 配置日志记录
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
# (Handler 配置由 main.py 完成)
# 日志配置结束


class DrcomCore:
    """Dr.COM 认证核心逻辑类"""

    def __init__(self) -> None:
        """初始化 Dr.com-Core 类。"""
        logger.info("Dr.Com-Core 正在初始化。")
        try:
            self._load_config()  # 加载所有配置 (包含 IP 和 MAC 检测)
            self._init_socket()  # 初始化网络套接字
        except Exception as e:
            logger.critical(f"初始化失败: {e}")
            logger.critical(traceback.format_exc())
            sys.exit(f"初始化过程中发生错误，程序退出。错误详情: {e}")

        self.salt: bytes = b""
        self.auth_info: bytes = b""
        self.login_success: bool = False
        logger.info("Dr.Com-Core 初始化成功。")

    def _init_socket(self) -> None:
        """初始化 UDP 网络套接字"""
        logger.info("正在初始化网络套接字。")
        try:
            self.core_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.core_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # 绑定到检测到的或配置的 IP 和端口
            self.core_socket.bind((self.bind_ip, self.drcom_port))
            # 注意：登出时可能需要更短的超时
            # self.core_socket.settimeout(5) # 在具体操作前设置超时更灵活
            logger.info(
                f"网络套接字初始化成功，已绑定到 {self.bind_ip}:{self.drcom_port}"
            )
        except socket.error as e:
            logger.error(f"网络套接字初始化失败: {e}")
            raise

    # ... (省略 _detect_campus_interface_info 和 _load_config 方法，保持不变) ...
    def _detect_campus_interface_info(
        self, campus_ip_prefix: str
    ) -> Tuple[Optional[str], Optional[str]]:
        """
        自动检测符合条件的校园网接口的 IP 地址和 MAC 地址。

        Args:
            campus_ip_prefix: 校园网 IP 地址的前缀 (例如 "49.")。

        Returns:
            Tuple[Optional[str], Optional[str]]: 包含 IP 地址和 MAC 地址的元组 (ip, mac_address)。
                                                如果找不到符合条件的接口，则返回 (None, None)。
                                                MAC 地址以 "XX:XX:XX:XX:XX:XX" 格式返回。
        """
        logger.info(f"正在自动检测校园网接口信息 (IP 前缀: {campus_ip_prefix})...")
        try:
            # 遍历所有网络接口名称
            for interface in netifaces.interfaces():
                addresses = netifaces.ifaddresses(interface)
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
                            break  # 找到一个符合条件的 IP 即可

                # 2. 如果找到了符合条件的 IP，尝试获取该接口的 MAC 地址
                if detected_ip and netifaces.AF_LINK in addresses:
                    # AF_LINK 通常包含 MAC 地址信息
                    for link_info in addresses[netifaces.AF_LINK]:
                        mac = link_info.get("addr")
                        # 进行简单的 MAC 地址格式校验 (例如，长度和分隔符)
                        if mac and len(mac) == 17 and mac.count(":") == 5:
                            detected_mac = mac
                            logger.debug(
                                f"在接口 '{interface}' 上找到 MAC 地址: {detected_mac}"
                            )
                            break  # 找到 MAC 地址

                # 3. 如果 IP 和 MAC 都找到了，返回结果
                if detected_ip and detected_mac:
                    logger.info(
                        f"成功检测到接口 '{interface}' 的 IP: {detected_ip} 和 MAC: {detected_mac}"
                    )
                    return detected_ip, detected_mac

        except Exception as e:
            logger.warning(f"自动检测接口信息时发生错误: {e}")

        # 如果遍历完所有接口都没有找到匹配的 IP 和 MAC
        logger.warning("未能自动检测到符合条件的校园网接口信息。")
        return None, None

    def _load_config(self) -> None:
        """从 .env 文件或环境变量加载配置，优先自动检测 IP 和 MAC。"""
        logger.info("正在加载配置...")
        env_path = Path(__file__).resolve().parent.parent.parent / ".env"
        if env_path.exists():
            logger.debug(f"发现 .env 文件: {env_path}")
            load_dotenv(
                dotenv_path=env_path, override=True
            )  # override=True 允许环境变量覆盖 .env
        else:
            logger.warning(f".env 文件未找到: {env_path}，将仅依赖环境变量。")

        # 加载服务器地址和端口
        self.server_address: Optional[str] = os.getenv("SERVER_IP", "10.100.61.3")
        self.drcom_port: int = int(os.getenv("DRCOM_PORT", "61440"))

        # 加载校园网 IP 前缀
        self.campus_ip_prefix: str = os.getenv("CAMPUS_IP_PREFIX", "49.")

        # ---- IP 和 MAC 处理逻辑 ----
        detected_ip: Optional[str] = None
        detected_mac: Optional[str] = None
        if os.getenv("AUTO_DETECT_CAMPUS_INTERFACE", "True").lower() in (
            "true",
            "1",
            "t",
        ):
            detected_ip, detected_mac = self._detect_campus_interface_info(
                self.campus_ip_prefix
            )

        # 处理 IP 地址
        if detected_ip:
            logger.info(f"使用自动检测到的 IP 地址: {detected_ip}")
            self.host_ip = detected_ip
        else:
            logger.warning(
                "自动检测 IP 地址失败，尝试从 .env 文件或环境变量中获取 HOST_IP。"
            )
            fallback_ip = os.getenv("HOST_IP")
            if fallback_ip:
                logger.info(f"使用 .env 文件或环境变量中的 HOST_IP: {fallback_ip}")
                self.host_ip = fallback_ip
            else:
                error_msg = "无法自动检测校园网 IP，且未配置 HOST_IP。请检查网络连接或手动配置 HOST_IP。"
                logger.critical(error_msg)
                sys.exit(error_msg)
        self.bind_ip: str = self.host_ip  # 将 socket 绑定的 IP 设为最终获取到的 IP

        # 处理 MAC 地址
        final_mac_str: Optional[str] = None
        if detected_mac:
            logger.info(f"使用自动检测到的 MAC 地址: {detected_mac}")
            final_mac_str = detected_mac.replace(":", "")  # 去除分隔符
        else:
            logger.warning(
                "自动检测 MAC 地址失败，尝试从 .env 文件或环境变量中获取 MAC..."
            )
            mac_str_from_env: Optional[str] = os.getenv("MAC")
            if mac_str_from_env:
                logger.info(
                    f"使用 .env 文件或环境变量中配置的 MAC 地址: {mac_str_from_env}"
                )
                final_mac_str = mac_str_from_env.replace("-", "").replace(
                    ":", ""
                )  # 去除分隔符
            else:
                logger.warning(
                    "未能从自动检测或 .env 中获取 MAC 地址。某些认证可能失败。"
                )
                final_mac_str = None

        # 将最终确定的 MAC 地址字符串转换为整数
        self.mac_address: int = 0
        if final_mac_str:
            try:
                self.mac_address = int(final_mac_str, 16)
                logger.debug(f"最终使用的 MAC 地址 (整数): {hex(self.mac_address)}")
            except ValueError:
                logger.error(
                    f"无效的 MAC 地址格式: {final_mac_str}。请使用十六进制格式。将使用 0 作为 MAC 地址。"
                )
                self.mac_address = 0
        else:
            logger.warning("MAC 地址最终为 0。")
        # ---- IP 和 MAC 处理逻辑结束 ----

        # 加载用户凭证
        self.username: Optional[str] = os.getenv("USERNAME")
        self.password: Optional[str] = os.getenv("PASSWORD")

        # 加载主机信息
        self.host_name: str = os.getenv("HOST_NAME", "Drcom_Python_Client")
        self.host_os: str = os.getenv("HOST_OS", "Python")

        # 加载其他协议相关的 bytes 类型配置
        self.adapter_num: bytes = bytes.fromhex(os.getenv("ADAPTERNUM", "01"))
        self.ipdog: bytes = bytes.fromhex(os.getenv("IPDOG", "01"))
        self.auth_version: bytes = bytes.fromhex(os.getenv("AUTH_VERSION", "0a00"))
        self.control_check_status: bytes = bytes.fromhex(
            os.getenv("CONTROL_CHECK_STATUS", "20")
        )
        self.keep_alive_version: bytes = bytes.fromhex(
            os.getenv("KEEP_ALIVE_VERSION", "dc02")
        )

        # 加载布尔类型的 ROR 状态
        self.ror_status: bool = os.getenv("ROR_STATUS", "False").lower() in (
            "true",
            "1",
            "t",
        )

        # 加载可能需要的其他网络配置
        self.dhcp_address: str = os.getenv("DHCP_SERVER", "0.0.0.0")
        self.primary_dns: str = os.getenv("PRIMARY_DNS", "114.114.114.114")

        # 配置项校验
        required_configs = {
            "服务器地址 (SERVER_IP)": self.server_address,
            "用户名 (USERNAME)": self.username,
            "密码 (PASSWORD)": self.password,
            "本机IP (自动检测或配置)": self.host_ip,  # 增加IP校验
            "MAC 地址 (自动检测或配置)": self.mac_address != 0,  # MAC不为0才算有效
        }
        missing_configs = [
            name for name, value in required_configs.items() if not value
        ]
        if missing_configs:
            details = []
            if "服务器地址 (SERVER_IP)" in missing_configs:
                details.append("未配置 SERVER_IP")
            if "用户名 (USERNAME)" in missing_configs:
                details.append("未配置 USERNAME")
            if "密码 (PASSWORD)" in missing_configs:
                details.append("未配置 PASSWORD")
            if "本机IP (自动检测或配置)" in missing_configs:
                details.append("无法获取本机 IP 地址")
            if "MAC 地址 (自动检测或配置)" in missing_configs:
                details.append("无法获取有效的 MAC 地址")

            error_msg = f"缺少必要的配置项: {'; '.join(details)}。请检查网络连接、.env 文件或环境变量。"
            logger.critical(error_msg)
            sys.exit(error_msg)

        logger.info("所有配置加载成功。")

    def perform_challenge(self, max_retries: int = 5) -> bool:
        """执行 Challenge 过程，从服务器获取 salt。"""
        logger.info("正在执行 Challenge 过程...")
        retries = 0
        while retries < max_retries:
            try:
                # 设置本次操作的超时
                self.core_socket.settimeout(3)  # 挑战超时可以短一些
                send_challenge_request(
                    self.core_socket, self.server_address, self.drcom_port
                )
                salt_data, server_addr = receive_challenge_response(self.core_socket)

                if server_addr and server_addr[0] == self.server_address and salt_data:
                    self.salt = salt_data
                    logger.info(f"Challenge 成功。获取到 Salt: {self.salt.hex()}")
                    return True
                else:
                    logger.warning(
                        f"收到无效或非预期的 Challenge 响应来自 {server_addr}。响应数据: {salt_data.hex() if salt_data else 'None'}。正在重试 ({retries + 1}/{max_retries})..."
                    )
            except socket.timeout:
                logger.warning(
                    f"Challenge 第 {retries + 1}/{max_retries} 次尝试超时。正在重试..."
                )
            except socket.error as e:
                logger.error(
                    f"Challenge 第 {retries + 1}/{max_retries} 次尝试时发生 Socket 错误: {e}。正在重试..."
                )
                time.sleep(1)  # Socket错误后稍作等待
            except Exception as e:
                logger.error(
                    f"Challenge 第 {retries + 1}/{max_retries} 次尝试时发生意外错误: {e}"
                )
                logger.debug(traceback.format_exc())

            retries += 1
            if retries < max_retries:
                wait_time = random.uniform(0.5, 1.5)
                logger.debug(f"等待 {wait_time:.2f} 秒后重试...")
                time.sleep(wait_time)

        logger.error("Challenge 过程失败 (超过最大重试次数)。")
        self.salt = b""  # 清空 salt
        return False

    def perform_login(self, max_retries: int = 3) -> bool:
        """
        执行登录认证过程。
        调用 login.py 中的函数来构建、发送和解析登录包。
        """
        logger.info("正在执行登录认证...")
        if not self.salt:
            logger.error("登录失败：未获取到 Salt。请先成功执行 Challenge。")
            return False

        retries = 0
        while retries < max_retries:
            try:
                # 1. 构建登录数据包
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
                logger.info(f"第 {retries + 1}/{max_retries} 次尝试发送登录请求...")
                self.core_socket.settimeout(5)  # 设置登录响应超时
                send_login_request_login(  # 使用别名后的发送函数
                    self.core_socket,
                    self.server_address,
                    self.drcom_port,
                    login_packet,
                )

                # 3. 接收登录响应
                response_data, server_addr = self.core_socket.recvfrom(1024)

                # 4. 解析登录响应
                is_success, auth_info, error_code, message = parse_login_response(
                    response_data, self.server_address, server_addr[0]
                )

                # 5. 根据解析结果处理
                if is_success:
                    self.auth_info = auth_info
                    self.login_success = True
                    logger.info(f"登录成功！ ({message})")
                    return True  # 登录成功，退出函数
                else:
                    logger.error(f"登录失败: {message}")
                    # 根据错误码判断是否需要重试
                    # 0x03: 密码错误, 0x04: 余额不足, 0x05: 账号冻结, 0x07/0x0B/0x16: IP/MAC不匹配, 0x17: 强制DHCP
                    # 这些错误通常不需要重试
                    no_retry_codes = [0x03, 0x04, 0x05, 0x07, 0x0B, 0x16, 0x17]
                    if error_code is not None and error_code in no_retry_codes:
                        logger.info(
                            "此错误通常由配置或账户问题引起，停止登录尝试。请检查配置或联系管理员。"
                        )
                        return False  # 无需重试的错误，直接返回失败
                    else:
                        logger.info(
                            f"将进行重试 ({retries + 1}/{max_retries})..."
                        )  # 其他错误，继续循环

            except ValueError as ve:  # 捕获构建错误
                logger.error(f"构建登录包时发生错误: {ve}")
                logger.debug(traceback.format_exc())
                return False  # 构建错误通常是配置问题，不重试
            except socket.timeout:
                logger.warning(
                    f"登录第 {retries + 1}/{max_retries} 次尝试接收响应超时。正在重试..."
                )
            except socket.error as e:
                logger.error(
                    f"登录第 {retries + 1}/{max_retries} 次尝试时发生 Socket 错误: {e}。正在重试..."
                )
                time.sleep(1)  # Socket错误后稍作等待
            except Exception as e:
                logger.error(
                    f"登录第 {retries + 1}/{max_retries} 次尝试时发生意外错误: {e}"
                )
                logger.debug(traceback.format_exc())

            retries += 1
            if retries < max_retries:
                wait_time = random.uniform(1, 3)  # 重试间隔
                logger.debug(f"等待 {wait_time:.2f} 秒后重试登录...")
                time.sleep(wait_time)

        logger.error("登录失败 (超过最大重试次数)。")
        self.login_success = False
        self.auth_info = b""  # 清空认证信息
        return False

    # ... (省略心跳相关方法，保持占位符) ...
    def _build_keep_alive1_packet(self) -> bytes:
        """构建 Keep Alive 1 (FF 包)"""
        logger.debug("构建 Keep Alive 1 包 (占位符)...")
        # --- 实际实现 ---
        # 需要 self.salt, self.auth_info, self.password
        if not self.salt or not self.auth_info or not self.password:
            logger.error("缺少构建 Keep Alive 1 的必要信息 (salt, auth_info, password)")
            return b""  # 返回空字节串表示失败

        try:
            password_bytes = self.password.encode("utf-8", "ignore")
            timestamp_packed = struct.pack("!H", int(time.time()) % 0xFFFF)
            md5_data = b"\x03\x01" + self.salt + password_bytes
            md5_hash = hashlib.md5(md5_data).digest()

            packet = (
                b"\xff"
                + md5_hash
                + b"\x00\x00\x00"
                + self.auth_info
                + timestamp_packed
                + b"\x00\x00\x00\x00"
            )
            return packet
        except Exception as e:
            logger.error(f"构建 Keep Alive 1 包时出错: {e}")
            logger.debug(traceback.format_exc())
            return b""
        # --- 实现结束 ---

    def _manage_keep_alive2_sequence(self) -> None:
        """管理并发送 Keep Alive 2 (07 包) 序列 (占位符)"""
        # 这个逻辑比较复杂，需要维护序列号 (svr_num) 和 tail 状态
        # 需要发送 Type 1 -> Type 1 -> Type 3 包，并处理响应更新 tail
        logger.debug("发送 Keep Alive 2 序列 (占位符)...")
        # ... (需要详细实现) ...
        pass

    def start_keep_alive(self) -> None:
        """启动心跳维持循环。(占位符逻辑)"""
        if not self.login_success or not self.auth_info:
            logger.error("无法启动心跳：尚未登录或缺少认证信息。")
            return

        logger.info("开始发送心跳包...")
        try:
            while True:
                # 1. 发送 Keep Alive 1 (调用实际构建函数)
                keep_alive1_packet = self._build_keep_alive1_packet()
                if not keep_alive1_packet:  # 构建失败
                    logger.error("构建 Keep Alive 1 失败，心跳中断。")
                    break

                logger.debug(f"发送 Keep Alive 1: {keep_alive1_packet.hex()}")
                self.core_socket.settimeout(3)  # 心跳响应超时可以短一些
                self.core_socket.sendto(
                    keep_alive1_packet, (self.server_address, self.drcom_port)
                )
                try:
                    resp1, _ = self.core_socket.recvfrom(1024)
                    logger.debug(f"收到 Keep Alive 1 响应: {resp1.hex()}")
                    # TODO: 根据响应更新状态或 tail (如果需要)
                    if not resp1.startswith(b"\x07"):  # 简单检查响应头
                        logger.warning("Keep Alive 1 收到非预期响应头")
                        # 这里可以选择是继续还是中断心跳
                        # continue # 暂时选择继续

                except socket.timeout:
                    logger.warning("Keep Alive 1 响应超时，可能已掉线。")
                    # 超时通常意味着连接断开，应该中断心跳并尝试重连
                    break  # 中断心跳循环
                except socket.error as e_ka1:
                    logger.error(f"Keep Alive 1 过程中发生 Socket 错误: {e_ka1}")
                    break  # 中断心跳

                # 2. 发送 Keep Alive 2 序列 (占位符)
                self._manage_keep_alive2_sequence()
                # 如果 Keep Alive 2 内部发生错误，也应该 break

                # 3. 等待一段时间
                logger.debug("等待 20 秒发送下一轮心跳...")
                time.sleep(20)

        except KeyboardInterrupt:
            logger.info("收到中断信号，停止心跳。")
            # 不再向上抛出，由 run() 的 finally 处理退出
        except Exception as e:
            logger.error(f"心跳循环中发生意外错误: {e}")
            logger.error(traceback.format_exc())
        finally:
            logger.info("心跳循环结束。")
            self.login_success = False  # 标记为未登录，以便 run() 尝试重连

    def perform_logout(self) -> None:
        """
        执行登出操作 (Code 0x06)。
        这是一个“尽力而为”的操作，失败时不重试。
        """
        # 1. 检查是否需要登出
        #    如果从未成功登录过，或者没有 auth_info，则无需登出
        if not self.auth_info:
            logger.info("未登录或缺少认证信息，无需执行登出操作。")
            return

        logger.info("正在尝试执行登出...")
        original_salt = self.salt  # 保存原始salt以备后用（虽然logout通常用新salt）
        logout_success = False

        try:
            # 2. 尝试获取新的 Challenge salt
            #    只尝试一次，失败也无妨，可以用旧的试试，或者直接放弃
            logout_challenge_ok = self.perform_challenge(max_retries=1)
            if not logout_challenge_ok:
                logger.warning(
                    "登出前获取新的 Challenge salt 失败，将尝试使用旧 salt (如果存在)。"
                )
                if not original_salt:  # 如果连旧 salt 都没有
                    logger.error("无可用 salt，无法构建登出包，放弃登出。")
                    return  # 直接返回
                else:
                    self.salt = original_salt  # 确保使用旧 salt

            # 3. 构建登出包
            try:
                logout_packet = _build_logout_packet(
                    username=self.username,
                    password=self.password,  # 登出包通常也需要密码
                    salt=self.salt,  # 使用获取到的新 salt 或旧 salt
                    mac=self.mac_address,
                    auth_info=self.auth_info,
                    control_check_status=self.control_check_status,
                    adapter_num=self.adapter_num,
                )
            except ValueError as ve:
                logger.error(f"构建登出包失败: {ve}，放弃登出。")
                return  # 构建失败，直接返回

            # 4. 发送登出包
            logger.debug(f"发送登出数据包: {logout_packet.hex()}")
            self.core_socket.settimeout(2)  # 登出响应超时设置短一些
            send_logout_request(  # 使用别名后的发送函数
                self.core_socket,
                self.server_address,
                self.drcom_port,
                logout_packet,
            )

            # 5. 尝试接收并解析响应，仅用于日志记录
            try:
                response_data, server_addr = self.core_socket.recvfrom(1024)
                logout_success, message = parse_logout_response(
                    response_data, self.server_address, server_addr[0]
                )
                if logout_success:
                    logger.info(f"登出成功: {message}")
                else:
                    logger.warning(f"登出响应解析结果: {message}")
            except socket.timeout:
                # 超时是正常情况，服务器可能不响应登出请求
                logger.info("发送登出包后未收到响应 (属正常情况)。")
                logout_success = True  # 视为登出成功（客户端已尽力）
            except socket.error as sock_err_recv:
                logger.warning(f"接收登出响应时发生 Socket 错误: {sock_err_recv}")
                # 即使接收出错，也认为客户端已尝试登出
                logout_success = True

        except socket.error as sock_err_send:
            logger.error(f"发送登出包时发生 Socket 错误: {sock_err_send}")
            # 发送失败，记录错误即可
        except Exception as e:
            logger.error(f"执行登出操作时发生意外错误: {e}")
            logger.debug(traceback.format_exc())
            # 发生意外错误

        finally:
            # 无论成功与否，都清理状态
            self.login_success = False
            self.auth_info = b""
            self.salt = b""  # 清理 salt
            logger.info("登出流程结束。")

    def run(self) -> None:
        """启动认证和心跳的主循环"""
        logger.info("启动 Dr.Com 核心认证流程。")
        try:
            while True:
                if not self.login_success:
                    logger.info("尝试进行认证。")
                    if self.perform_challenge():
                        if self.perform_login():
                            # 登录成功后启动心跳
                            self.start_keep_alive()  # start_keep_alive 内部处理心跳循环和中断
                            # 从 start_keep_alive 返回意味着心跳中断或失败
                            logger.info("心跳已停止，将尝试重新认证。")
                            # 无需手动设置 self.login_success = False，心跳函数退出时会设置
                        else:
                            # 登录失败，根据 perform_login 的返回值决定是否继续
                            # 如果 perform_login 返回 False，意味着是无需重试的错误或已达最大次数
                            logger.error("登录过程失败，程序将在 30 秒后退出。")
                            time.sleep(30)
                            break  # 退出主循环
                    else:
                        logger.error("Challenge 失败，将在 60 秒后重试。")
                        time.sleep(60)
                else:
                    # 这个分支理论上不应该进入，因为 login_success = True 时会进入 start_keep_alive
                    # 如果进入这里，说明状态异常
                    logger.warning(
                        "检测到异常状态 (login_success=True 但未在心跳中)，将在 10 秒后尝试重新认证。"
                    )
                    self.login_success = False  # 重置状态
                    time.sleep(10)

        except KeyboardInterrupt:
            logger.info("用户请求退出 (Ctrl+C)。")
        except SystemExit as e:
            logger.info(f"程序因调用 sys.exit() 而退出: {e}")
        except Exception as e:
            logger.critical(f"主循环发生严重错误: {e}")
            logger.critical(traceback.format_exc())
        finally:
            logger.info("执行最终清理...")
            self.perform_logout()  # 尝试登出

            # 关闭 socket
            if (
                hasattr(self, "core_socket") and self.core_socket
            ):  # 检查 core_socket 是否已初始化
                try:
                    self.core_socket.close()
                    logger.info("网络套接字已关闭。")
                except Exception as e_close:
                    logger.error(f"关闭 socket 时出错: {e_close}")
            logger.info("Dr.Com Core 已停止。")
