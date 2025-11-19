# src/drcom_core/config.py
"""
Dr.COM 核心库 - 配置模块

负责定义配置的数据结构 (DrcomConfig)
并提供从原始字典 (如 .env 加载的) 进行解析和验证的功能。
"""

import logging
import socket  # 仅在此文件允许导入 socket，用于 IP 验证/转换
from dataclasses import dataclass, field
from typing import Any, Dict

# 导入新定义的异常
from .exceptions import ConfigError

# 从协议层导入常量 (仅保留协议相关的魔数)
from .protocols import constants

logger = logging.getLogger(__name__)

# =========================================================================
# 默认配置策略 (Default Policies)
# =========================================================================
# 这些默认值属于"策略"，因此从 protocols/constants.py 移动到了这里
DEFAULT_DRCOM_PORT = 61440
DEFAULT_HOST_NAME = "Drcom-Core-Client"
DEFAULT_HOST_OS = "Windows 10"
DEFAULT_DHCP_SERVER = "0.0.0.0"
DEFAULT_PRIMARY_DNS = "1.1.1.1"
DEFAULT_BIND_IP = "0.0.0.0"
# 用于判断环境变量布尔值的字符串
BOOLEAN_TRUE_STRINGS = {"true", "1", "t", "yes", "on"}


@dataclass(frozen=True)
class DrcomConfig:
    """
    DrcomCore 的强类型配置对象。
    此对象包含所有已验证和已转换的数据，一旦创建不可修改 (Immutable)。
    """

    # --- 核心身份凭据 ---
    username: str
    password: str
    server_address: str
    mac_address: int  # 已转换为整数的 MAC

    # --- 网络环境 ---
    host_ip_bytes: bytes
    primary_dns_bytes: bytes = field(
        default_factory=lambda: socket.inet_aton(DEFAULT_PRIMARY_DNS)
    )
    dhcp_address_bytes: bytes = field(
        default_factory=lambda: socket.inet_aton(DEFAULT_DHCP_SERVER)
    )
    bind_ip: str = DEFAULT_BIND_IP
    drcom_port: int = DEFAULT_DRCOM_PORT

    # --- 协议行为控制  ---
    protocol_version: str = "D"
    magic_tail: bool = False  # 是否启用随机包尾 (对抗检测)
    ror_status: bool = False  # 是否启用 ROR 加密 (部分学校需要)

    # --- 主机指纹 ---
    host_name: str = DEFAULT_HOST_NAME
    host_os: str = DEFAULT_HOST_OS

    # --- 协议参数 (字节形式) ---
    adapter_num: bytes = b"\x01"
    ipdog: bytes = b"\x01"
    auth_version: bytes = b"\x0a\x00"
    control_check_status: bytes = b"\x20"
    keep_alive_version: bytes = constants.KEEP_ALIVE_VERSION

    def __post_init__(self):
        """
        在对象初始化后立即执行的验证逻辑。
        确保 Config 对象只要被创建，其内部数据一定是合法的。
        """
        # 验证 AUTH_VERSION 长度
        if len(self.auth_version) != 2:
            raise ConfigError(
                f"AUTH_VERSION 长度必须为 2 字节 (当前: {self.auth_version.hex()})。"
            )

        # 验证 MAC 地址范围 (简单检查)
        if not (0 <= self.mac_address <= 0xFFFFFFFFFFFF):
            raise ConfigError(f"MAC 地址数值超出有效范围: {hex(self.mac_address)}")

        # 验证端口
        if not (1 <= self.drcom_port <= 65535):
            raise ConfigError(f"端口号无效: {self.drcom_port}")


def load_config_from_dict(raw_config: Dict[str, Any]) -> DrcomConfig:
    """
    [API] 从原始字典 (如 os.getenv) 加载并验证配置。
    这是 `drcom-core` 库推荐的配置入口。

    Args:
        raw_config: 包含配置键值对的字典。

    Returns:
        DrcomConfig: 验证通过的配置对象。

    Raises:
        ConfigError: 如果缺少必要键、格式错误或验证失败。
    """
    logger.debug("正在解析配置字典...")

    try:
        # 1. 提取必需字段 (Str)
        required_keys = ["USERNAME", "PASSWORD", "SERVER_IP", "HOST_IP", "MAC"]
        missing_keys = [k for k in required_keys if not raw_config.get(k)]
        if missing_keys:
            raise ConfigError(f"缺少必要的配置项: {', '.join(missing_keys)}")

        username = str(raw_config["USERNAME"]).strip()
        password = str(raw_config["PASSWORD"]).strip()
        server_ip = str(raw_config["SERVER_IP"]).strip()
        host_ip_str = str(raw_config["HOST_IP"]).strip()
        mac_str = str(raw_config["MAC"]).strip()

        # 2. 转换复杂类型 (IP -> bytes, MAC -> int)
        try:
            host_ip_bytes = socket.inet_aton(host_ip_str)
        except OSError as e:
            raise ConfigError(f"HOST_IP 格式无效 ({host_ip_str}): {e}") from e

        try:
            # 移除常见分隔符
            clean_mac = mac_str.replace(":", "").replace("-", "").replace(".", "")
            if len(clean_mac) != 12:
                raise ValueError("长度不为12位")
            mac_address = int(clean_mac, 16)
        except ValueError as e:
            raise ConfigError(f"MAC 地址格式无效 ({mac_str}): {e}") from e

        # 3. 辅助函数：解析可选 IP
        def get_ip_bytes(key: str, default: str) -> bytes:
            val = raw_config.get(key, default)
            try:
                return socket.inet_aton(str(val))
            except OSError:
                logger.warning(f"{key} IP格式无效 ('{val}')，使用默认值 {default}")
                return socket.inet_aton(default)

        # 4. 辅助函数：解析 Hex 字节串
        def get_hex_bytes(key: str, default_hex: str) -> bytes:
            val = raw_config.get(key, default_hex)
            try:
                # 处理可能的 "0x" 前缀
                clean_val = str(val).lower().replace("0x", "").replace("\\x", "")
                # 确保长度为偶数
                if len(clean_val) % 2 != 0:
                    clean_val = "0" + clean_val
                return bytes.fromhex(clean_val)
            except ValueError:
                logger.warning(f"{key} Hex格式无效 ('{val}')，使用默认值 {default_hex}")
                return bytes.fromhex(default_hex)

        # 5. 辅助函数：解析布尔值
        def get_bool(key: str, default: bool) -> bool:
            val = raw_config.get(key)
            if val is None:
                return default
            return str(val).lower() in BOOLEAN_TRUE_STRINGS

        # 6. 构建 Config 对象
        config = DrcomConfig(
            username=username,
            password=password,
            server_address=server_ip,
            mac_address=mac_address,
            host_ip_bytes=host_ip_bytes,
            # 可选网络参数
            primary_dns_bytes=get_ip_bytes("PRIMARY_DNS", DEFAULT_PRIMARY_DNS),
            dhcp_address_bytes=get_ip_bytes("DHCP_SERVER", DEFAULT_DHCP_SERVER),
            bind_ip=str(raw_config.get("BIND_IP", DEFAULT_BIND_IP)),
            drcom_port=int(raw_config.get("DRCOM_PORT", DEFAULT_DRCOM_PORT)),
            # 协议控制
            protocol_version=str(raw_config.get("PROTOCOL_VERSION", "D")).upper(),
            magic_tail=get_bool("MAGIC_TAIL", False),
            ror_status=get_bool("ROR_STATUS", False),
            # 指纹
            host_name=str(raw_config.get("HOST_NAME", DEFAULT_HOST_NAME)),
            host_os=str(raw_config.get("HOST_OS", DEFAULT_HOST_OS)),
            # 协议参数
            adapter_num=get_hex_bytes("ADAPTERNUM", "01"),
            ipdog=get_hex_bytes("IPDOG", "01"),
            auth_version=get_hex_bytes("AUTH_VERSION", "0a00"),
            control_check_status=get_hex_bytes("CONTROL_CHECK_STATUS", "20"),
            keep_alive_version=get_hex_bytes("KEEP_ALIVE_VERSION", "dc02"),
        )

        logger.info("配置加载并验证成功。")
        return config

    except ConfigError:
        raise
    except Exception as e:
        # 捕获其他意外错误 (如 int转换失败等)
        raise ConfigError(f"配置解析发生未知错误: {e}") from e
