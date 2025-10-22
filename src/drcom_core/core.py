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

from ..drcom_protocol.challenge import (
    receive_challenge_response,
    send_challenge_request,
)

# --- 配置日志记录 ---
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)  # 保持 DEBUG 级别
# (Handler 配置由 main.py 完成)
# --- 日志配置结束 ---


class DrcomCore:
    """Dr.COM 认证核心逻辑类"""

    def __init__(self) -> None:
        """初始化 Dr.com-Core 类。"""
        logger.info("Dr.Com-Core 正在初始化...")
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
        logger.info("正在初始化网络套接字...")
        try:
            self.core_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.core_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # 绑定到检测到的或配置的 IP 和端口
            self.core_socket.bind((self.bind_ip, self.drcom_port))
            self.core_socket.settimeout(5)
            logger.info(
                f"网络套接字初始化成功，已绑定到 {self.bind_ip}:{self.drcom_port}"
            )
        except socket.error as e:
            logger.error(f"网络套接字初始化失败: {e}")
            raise

    def _detect_campus_interface_info(
        self, campus_ip_prefix: str
    ) -> Tuple[Optional[str], Optional[str]]:
        """
        自动检测符合条件的校园网接口的 IP 地址和 MAC 地址。

        Args:
            campus_ip_prefix: 校园网 IP 地址的前缀 (例如 "49." 或 "10.")。

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
                            break  # 找到 MAC 地址即可

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

        # --- 加载服务器地址和端口 ---
        self.server_address: Optional[str] = os.getenv("SERVER_IP")
        self.drcom_port: int = int(os.getenv("DRCOM_PORT", "61440"))

        # --- 加载校园网 IP 前缀 ---
        self.campus_ip_prefix: str = os.getenv("CAMPUS_IP_PREFIX", "49.")

        # --- 优先自动检测 IP 和 MAC ---
        detected_ip, detected_mac = self._detect_campus_interface_info(
            self.campus_ip_prefix
        )

        # --- 处理 IP 地址 ---
        if detected_ip:
            logger.info(f"使用自动检测到的 IP 地址: {detected_ip}")
            self.host_ip = detected_ip
        else:
            # 如果自动检测 IP 失败，尝试从环境变量回退
            logger.warning(
                "自动检测 IP 失败，尝试从 .env 文件或环境变量中获取 HOST_IP..."
            )
            fallback_ip = os.getenv("HOST_IP")
            if fallback_ip:
                logger.info(f"使用 .env 文件或环境变量中的 HOST_IP: {fallback_ip}")
                self.host_ip = fallback_ip
            else:
                # IP 地址是必需的
                error_msg = "无法自动检测校园网 IP，且未配置 HOST_IP。请检查网络连接或配置 HOST_IP。"
                logger.critical(error_msg)
                sys.exit(error_msg)
        # 将 socket 绑定的 IP 设为最终获取到的 IP
        self.bind_ip: str = self.host_ip

        # --- 处理 MAC 地址 ---
        final_mac_str: Optional[str] = None
        if detected_mac:
            logger.info(f"使用自动检测到的 MAC 地址: {detected_mac}")
            final_mac_str = detected_mac.replace(
                ":", ""
            )  # 使用检测到的值，并去除分隔符
        else:
            # 如果自动检测 MAC 失败，尝试从环境变量回退
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
                )  # 使用配置的值，并去除分隔符
            else:
                logger.warning(
                    "未能从自动检测或 .env 中获取 MAC 地址。某些认证可能失败。"
                )
                final_mac_str = None  # 或者 '000000000000'

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

        # --- 加载用户凭证 ---
        self.username: Optional[str] = os.getenv("USERNAME")
        self.password: Optional[str] = os.getenv("PASSWORD")

        # --- 加载主机信息 ---
        self.host_name: str = os.getenv("HOST_NAME", "Drcom_Python_Client")
        self.host_os: str = os.getenv("HOST_OS", "Python")

        # --- 加载其他协议相关的 bytes 类型配置 ---
        self.adapter_num: bytes = bytes.fromhex(os.getenv("ADAPTERNUM", "01"))
        self.ipdog: bytes = bytes.fromhex(os.getenv("IPDOG", "01"))
        self.auth_version: bytes = bytes.fromhex(os.getenv("AUTH_VERSION", "0a00"))
        self.control_check_status: bytes = bytes.fromhex(
            os.getenv("CONTROL_CHECK_STATUS", "20")
        )
        self.keep_alive_version: bytes = bytes.fromhex(
            os.getenv("KEEP_ALIVE_VERSION", "dc02")
        )

        # --- 加载布尔类型的 ROR 状态 ---
        self.ror_status: bool = os.getenv("ROR_STATUS", "False").lower() in (
            "true",
            "1",
            "t",
        )

        # --- 加载可能需要的其他网络配置 ---
        self.dhcp_address: str = os.getenv("DHCP_SERVER", "0.0.0.0")
        self.primary_dns: str = os.getenv("PRIMARY_DNS", "114.114.114.114")

        # --- 配置项校验 ---
        required_configs = {
            "服务器地址 (SERVER_IP)": self.server_address,
            "用户名 (USERNAME)": self.username,
            "密码 (PASSWORD)": self.password,
            # MAC 地址现在有自动检测，但如果最终为 0 仍需注意
            "MAC 地址 (自动检测或配置)": self.mac_address != 0,
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
            if "MAC 地址 (自动检测或配置)" in missing_configs:
                details.append("自动检测 MAC 失败且未配置 MAC 地址或格式错误")

            error_msg = f"缺少必要的配置项: {'; '.join(details)}。请检查网络连接、.env 文件或环境变量。"
            logger.critical(error_msg)
            sys.exit(error_msg)

        logger.info("所有配置加载成功。")

    def perform_challenge(self, max_retries: int = 5) -> bool:
        """执行 Challenge 过程，从服务器获取 salt。"""
        # (此方法逻辑保持不变，使用 logger 记录日志)
        logger.info("正在执行 Challenge 过程...")
        retries = 0
        while retries < max_retries:
            try:
                send_challenge_request(
                    self.core_socket, self.server_address, self.drcom_port
                )
                self.core_socket.settimeout(5)
                salt_data, server_addr = receive_challenge_response(self.core_socket)

                if server_addr and server_addr[0] == self.server_address and salt_data:
                    self.salt = salt_data
                    logger.info(f"Challenge 成功。获取到 Salt: {self.salt.hex()}")
                    return True
                else:
                    logger.warning(
                        f"收到无效或非预期的 Challenge 响应来自 {server_addr}。响应数据: {salt_data.hex() if salt_data else 'None'}。正在重试..."
                    )
            except socket.timeout:
                logger.warning(f"Challenge 第 {retries + 1} 次尝试超时。正在重试...")
            except socket.error as e:
                logger.error(
                    f"Challenge 第 {retries + 1} 次尝试时发生 Socket 错误: {e}。正在重试..."
                )
                time.sleep(1)
            except Exception as e:
                logger.error(f"Challenge 第 {retries + 1} 次尝试时发生意外错误: {e}")
                logger.debug(traceback.format_exc())

            retries += 1
            if retries < max_retries:
                wait_time = random.uniform(0.5, 1.5)
                logger.debug(f"等待 {wait_time:.2f} 秒后重试...")
                time.sleep(wait_time)

        logger.error("Challenge 过程失败 (超过最大重试次数)。")
        self.salt = b""
        return False

    # TODO: 实现登录包构建逻辑 (需要使用 self.mac_address 这个整数)
    def _build_login_packet(self) -> bytes:
        """根据当前配置和获取到的 salt 构建登录 (Code 0x03) 数据包"""
        # --- 这里需要实现登录包构建，确保使用 self.mac_address (整数) ---
        logger.debug("正在构建登录数据包 (占位符)...")
        if not self.salt:
            logger.error("无法构建登录包：Salt 为空。")
            raise ValueError("Salt is missing for building login packet.")
        # ... (实际的构建逻辑) ...
        # 异或操作示例: xor_result = some_int_value ^ self.mac_address
        # 转换回 bytes: binascii.unhexlify(format(xor_result, '012x'))[-6:]
        return b"\x03..."  # <--- 需要替换!

    # TODO: 实现登录逻辑
    def perform_login(self, max_retries: int = 3) -> bool:
        """执行登录认证过程。"""
        # (此方法逻辑基本不变，确保调用 _build_login_packet)
        logger.info("正在执行登录认证...")
        if not self.salt:
            logger.error("登录失败：未获取到 Salt。请先执行 Challenge。")
            return False

        retries = 0
        while retries < max_retries:
            try:
                login_packet = self._build_login_packet()  # 调用构建函数
                logger.info(f"第 {retries + 1} 次尝试发送登录请求...")
                self.core_socket.sendto(
                    login_packet, (self.server_address, self.drcom_port)
                )
                self.core_socket.settimeout(5)
                response_data, server_addr = self.core_socket.recvfrom(1024)
                logger.debug(f"收到登录响应: {response_data.hex()}")

                if (
                    response_data
                    and server_addr[0] == self.server_address
                    and response_data.startswith(b"\x04")
                ):
                    logger.info("登录成功！")
                    self.auth_info = response_data[23:39]
                    logger.debug(f"获取到 Auth Info (Tail): {self.auth_info.hex()}")
                    self.login_success = True
                    return True
                else:
                    error_code = response_data[4] if len(response_data) > 4 else None
                    logger.error(
                        f"登录失败。服务器响应: {response_data.hex()} (错误码: {hex(error_code) if error_code is not None else 'N/A'})"
                    )
                    # 添加对常见错误码的解释
                    if error_code == 0x01:
                        logger.error(
                            " -> 错误原因：账号正在使用中或认证 MAC/IP 不匹配。"
                        )
                    elif error_code == 0x03:
                        logger.error(" -> 错误原因：账号或密码错误。")
                    elif error_code == 0x04:
                        logger.error(" -> 错误原因：账号余额不足或流量/时长超限。")
                    elif error_code == 0x05:
                        logger.error(" -> 错误原因：账号被冻结或暂停使用。")
                    elif error_code == 0x07:
                        logger.error(" -> 错误原因：IP 地址不匹配。")
                    elif error_code == 0x0B:
                        logger.error(" -> 错误原因：MAC 地址不匹配。")
                    elif error_code == 0x14:
                        logger.error(" -> 错误原因：登录 IP 数量超限。")
                    elif error_code == 0x15:
                        logger.error(" -> 错误原因：客户端版本不匹配或账号被禁用。")
                    elif error_code == 0x16:
                        logger.error(" -> 错误原因：IP 和 MAC 地址同时绑定错误。")
                    elif error_code == 0x17:
                        logger.error(" -> 错误原因：服务器要求使用 DHCP 获取 IP。")
                    # 对于密码错误等情况，不需要重试
                    if error_code in [0x03, 0x04, 0x05, 0x07, 0x0B, 0x16, 0x17]:
                        return False  # 直接返回失败
                    else:  # 其他错误可以尝试重试
                        pass  # 继续循环

            except socket.timeout:
                logger.warning(f"登录第 {retries + 1} 次尝试超时。正在重试...")
            except socket.error as e:
                logger.error(
                    f"登录第 {retries + 1} 次尝试时发生 Socket 错误: {e}。正在重试..."
                )
                time.sleep(1)
            except ValueError as e:  # 捕获 _build_login_packet 可能抛出的异常
                logger.error(f"构建登录包时出错: {e}")
                return False  # 构建失败，无法继续
            except Exception as e:
                logger.error(f"登录第 {retries + 1} 次尝试时发生意外错误: {e}")
                logger.debug(traceback.format_exc())

            retries += 1
            if retries < max_retries:
                wait_time = random.uniform(1, 2)
                logger.debug(f"等待 {wait_time:.2f} 秒后重试登录...")
                time.sleep(wait_time)

        logger.error("登录失败 (超过最大重试次数)。")
        return False

    # TODO: 实现心跳包构建和发送逻辑
    def _build_keep_alive1_packet(self) -> bytes:
        """构建 Keep Alive 1 (FF 包)"""
        logger.debug("构建 Keep Alive 1 包 (占位符)...")
        # ... (需要 salt, auth_info/tail, password) ...
        return b"\xff..."  # <--- 需要替换!

    def _manage_keep_alive2_sequence(self) -> None:
        """管理并发送 Keep Alive 2 (07 包) 序列"""
        # 这个逻辑比较复杂，可能需要维护序列号 (svr_num) 和 tail 状态
        # 需要发送 Type 1 -> Type 1 -> Type 3 包，并处理响应更新 tail
        logger.debug("发送 Keep Alive 2 序列 (占位符)...")
        # ... (实现发送和接收逻辑) ...
        pass

    def start_keep_alive(self) -> None:
        """启动心跳维持循环。"""
        # (此方法逻辑框架不变，需要调用 _build_keep_alive1_packet 和 _manage_keep_alive2_sequence)
        if not self.login_success or not self.auth_info:
            logger.error("无法启动心跳：尚未登录或缺少认证信息。")
            return

        logger.info("开始发送心跳包...")
        try:
            while True:
                # 1. 发送 Keep Alive 1
                keep_alive1_packet = self._build_keep_alive1_packet()
                logger.debug(f"发送 Keep Alive 1: {keep_alive1_packet.hex()}")
                self.core_socket.sendto(
                    keep_alive1_packet, (self.server_address, self.drcom_port)
                )
                try:
                    self.core_socket.settimeout(3)  # 心跳响应超时可以短一些
                    resp1, _ = self.core_socket.recvfrom(1024)
                    logger.debug(f"收到 Keep Alive 1 响应: {resp1.hex()}")
                    # TODO: 可能需要根据响应更新状态或 tail
                except socket.timeout:
                    logger.warning("Keep Alive 1 响应超时")
                    # 超时是否需要重发或认为连接已断开？

                # 2. 发送 Keep Alive 2 序列
                self._manage_keep_alive2_sequence()

                # 3. 等待一段时间
                logger.debug("等待 20 秒...")
                time.sleep(20)

        except KeyboardInterrupt:
            logger.info("收到中断信号，停止心跳。")
        except socket.error as e:
            logger.error(f"心跳过程中发生 Socket 错误: {e}")
        except Exception as e:
            logger.error(f"心跳过程中发生意外错误: {e}")
            logger.error(traceback.format_exc())
        finally:
            logger.info("心跳循环结束。")
            self.login_success = False

    # TODO: 实现登出包构建逻辑
    def _build_logout_packet(self) -> bytes:
        """构建登出 (Code 0x06) 数据包"""
        logger.debug("构建登出数据包 (占位符)...")
        # ... (可能需要新的 salt, username, password, mac, auth_info) ...
        return b"\x06..."  # <--- 需要替换!

    def perform_logout(self) -> None:
        """执行登出操作"""
        # (此方法逻辑框架不变，需要调用 _build_logout_packet)
        if (
            not self.login_success and not self.auth_info
        ):  # 即使未标记成功但有 auth_info 也尝试登出
            logger.info("未登录或无认证信息，无需登出。")
            return

        logger.info("正在执行登出...")
        try:
            # 登出是否需要新的 salt？根据旧代码似乎是需要的
            if self.perform_challenge(max_retries=1):  # 尝试获取一次新的 salt
                logout_packet = self._build_logout_packet()  # 使用新的 salt 构建
                logger.debug(f"构建的登出数据包: {logout_packet.hex()}")
                self.core_socket.sendto(
                    logout_packet, (self.server_address, self.drcom_port)
                )
                # ... (处理响应的代码不变) ...
                try:
                    self.core_socket.settimeout(3)
                    response_data, server_addr = self.core_socket.recvfrom(1024)
                    # ... (检查响应) ...
                    if response_data and response_data.startswith(b"\x04"):
                        logger.info("登出成功。")
                    else:
                        logger.warning(f"收到非预期的登出响应: {response_data.hex()}")
                except socket.timeout:
                    logger.info("发送登出包后未收到响应（可能已成功）。")
            else:
                logger.warning("登出前获取 Challenge salt 失败，放弃登出。")

        except socket.error as e:
            logger.error(f"登出时发生 Socket 错误: {e}")
        except ValueError as e:  # 捕获 _build_logout_packet 可能的异常
            logger.error(f"构建登出包时出错: {e}")
        except Exception as e:
            logger.error(f"登出时发生意外错误: {e}")
            logger.debug(traceback.format_exc())
        finally:
            self.login_success = False  # 标记为未登录

    def run(self) -> None:
        """启动认证和心跳的主循环"""
        # (此方法逻辑保持不变)
        logger.info("启动 Dr.Com 核心认证流程...")
        try:
            while True:
                if not self.login_success:
                    logger.info("尝试进行认证...")
                    if self.perform_challenge():
                        if self.perform_login():
                            self.start_keep_alive()
                        else:
                            logger.error("登录失败，将在 30 秒后重试...")
                            time.sleep(30)
                    else:
                        logger.error("Challenge 失败，将在 60 秒后重试...")
                        time.sleep(60)
                else:
                    logger.warning("心跳意外终止，将在 10 秒后尝试重新认证...")
                    self.login_success = False
                    time.sleep(10)

        except KeyboardInterrupt:
            logger.info("用户请求退出...")
        except Exception as e:
            logger.critical(f"主循环发生严重错误: {e}")
            logger.critical(traceback.format_exc())
        finally:
            logger.info("执行最终清理...")
            self.perform_logout()
            if (
                hasattr(self, "core_socket") and self.core_socket
            ):  # 检查 core_socket 是否已初始化
                try:
                    self.core_socket.close()
                    logger.info("网络套接字已关闭。")
                except Exception as e:
                    logger.error(f"关闭 socket 时出错: {e}")
            logger.info("Dr.Com 核心已停止。")
