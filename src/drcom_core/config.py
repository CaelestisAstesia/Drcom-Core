# src/drcom_core/config.py
"""
Dr.COM 核心库 - 配置模块

负责定义配置的数据结构 (DrcomConfig)
并提供从原始字典 (如 .env 加载的) 进行解析和验证的功能。
"""

import logging
import socket  # 仅在此文件（配置层）允许导入 socket，用于 IP 验证/转换
from dataclasses import dataclass
from typing import Any, Dict

# 从协议层导入默认值
from .drcom_protocol import constants

logger = logging.getLogger(__name__)


@dataclass(frozen=True)  # frozen=True 使配置对象在创建后不可修改
class DrcomConfig:
    """
    DrcomCore 的强类型配置对象。
    此对象包含所有已验证和已转换的数据。
    """

    # 协议版本控制
    protocol_version: str  # e.g., "D", "P", "X"

    # 网络配置
    server_address: str
    drcom_port: int

    # 凭据
    username: str
    password: str

    # 主机信息
    mac_address: int  # MAC 地址已解析为整数
    bind_ip: str

    # 主机环境 (带默认值)
    host_name: str
    host_os: str

    # 协议层所需的字节
    host_ip_bytes: bytes
    primary_dns_bytes: bytes
    dhcp_address_bytes: bytes

    # 协议参数 (已解析为 bytes)
    adapter_num: bytes
    ipdog: bytes
    auth_version: bytes
    control_check_status: bytes
    keep_alive_version: bytes

    # ROR 状态
    ror_status: bool

    def __post_init__(self):
        # 可以在这里添加对解析后配置的进一步验证
        if len(self.auth_version) != 2:
            logger.warning(
                f"AUTH_VERSION 长度不是 2 字节 ({self.auth_version.hex()})，可能导致认证失败。"
            )


def load_config_from_dict(raw_config: Dict[str, Any]) -> DrcomConfig:
    """
    [API] 从原始字典 (如 os.getenv) 加载并验证配置。
    这是 `drcom-core` 库推荐的配置入口。

    Raises:
        KeyError: 如果缺少必要的配置项。
        ValueError: 如果配置项格式错误（如 MAC 或 IP）。
    """
    logger.debug("开始从字典解析配置...")

    try:
        # 1. 提取必需的键 (str)
        username = str(raw_config["USERNAME"])
        password = str(raw_config["PASSWORD"])
        server_ip = str(raw_config["SERVER_IP"])
        host_ip_str = str(raw_config["HOST_IP"])
        mac_str = str(raw_config["MAC"])

        if not all([username, password, server_ip, host_ip_str, mac_str]):
            raise KeyError("USERNAME, PASSWORD, SERVER_IP, HOST_IP, MAC 不能为空")

        # 2. 提取可选的键 (str)
        primary_dns_str = str(
            raw_config.get("PRIMARY_DNS", constants.DEFAULT_PRIMARY_DNS)
        )
        dhcp_server_str = str(
            raw_config.get("DHCP_SERVER", constants.DEFAULT_DHCP_SERVER)
        )

        # 读取协议版本
        protocol_version = str(raw_config.get("PROTOCOL_VERSION", "D")).upper()

        # 3. 转换 IP 字符串为字节
        try:
            host_ip_bytes = socket.inet_aton(host_ip_str)
            primary_dns_bytes = socket.inet_aton(primary_dns_str)
            dhcp_address_bytes = socket.inet_aton(dhcp_server_str)
        except OSError as e:
            # 捕获无效的 IP 字符串
            raise ValueError(f"配置中的 IP 地址无效: {e}") from e

        # 4. 转换 MAC 字符串为整数
        clean_mac = mac_str.replace(":", "").replace("-", "")
        if len(clean_mac) != 12:
            raise ValueError(f"MAC 地址格式无效: {mac_str}")
        mac_address = int(clean_mac, 16)

        # 5. 辅助函数：安全地从 hex 加载 bytes
        def get_bytes(key: str, default: str) -> bytes:
            val_hex = raw_config.get(key, default)
            try:
                # 确保 val_hex 是字符串，防止 None 导致 TypeError
                return bytes.fromhex(str(val_hex))
            except (TypeError, ValueError):
                logger.warning(
                    f"配置项 {key} 的值 '{val_hex}' 不是有效的 hex，将使用默认值 '{default}'。"
                )
                return bytes.fromhex(default)

        # 6. 构建 DrcomConfig 对象
        config = DrcomConfig(
            protocol_version=protocol_version,  # [新增]
            server_address=server_ip,
            username=username,
            password=password,
            mac_address=mac_address,
            host_ip_bytes=host_ip_bytes,
            primary_dns_bytes=primary_dns_bytes,
            dhcp_address_bytes=dhcp_address_bytes,
            drcom_port=int(raw_config.get("DRCOM_PORT", constants.DEFAULT_DRCOM_PORT)),
            bind_ip=str(raw_config.get("BIND_IP", "0.0.0.0")),
            host_name=str(raw_config.get("HOST_NAME", constants.DEFAULT_HOST_NAME)),
            host_os=str(raw_config.get("HOST_OS", constants.DEFAULT_HOST_OS)),
            # 字节参数
            adapter_num=get_bytes("ADAPTERNUM", "01"),
            ipdog=get_bytes("IPDOG", "01"),
            auth_version=get_bytes("AUTH_VERSION", "0a00"),
            control_check_status=get_bytes("CONTROL_CHECK_STATUS", "20"),
            keep_alive_version=get_bytes(
                "KEEP_ALIVE_VERSION", constants.KEEP_ALIVE_VERSION.hex()
            ),
            # 布尔参数
            ror_status=str(raw_config.get("ROR_STATUS", "False")).lower()
            in constants.BOOLEAN_TRUE_STRINGS,
        )

        logger.info(f"DrcomConfig 对象创建成功 (协议版本: {config.protocol_version})。")
        return config

    except KeyError as e:
        logger.critical(f"配置中缺少必要的键: {e}")
        raise KeyError(f"配置中缺少 {e}") from e
    except (ValueError, TypeError) as e:
        logger.critical(f"解析配置时出错（值格式错误）: {e}")
        raise ValueError(f"解析配置失败: {e}") from e
