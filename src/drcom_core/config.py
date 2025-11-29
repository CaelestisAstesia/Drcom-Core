"""
Dr.COM 核心库 - 配置模块

负责配置的加载、解析与强类型转换。
支持从 TOML 文件、环境变量或字典中加载配置，并自动适配协议差异。
"""

import logging
import os
import socket
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .exceptions import ConfigError

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class DrcomConfig:
    """DrcomCore 的强类型配置对象。

    所有字段均为只读 (frozen=True)，确保配置在运行时不可变。

    Attributes:
        username: 认证用户名。
        password: 认证密码。
        server_address: 认证服务器 IP 地址 (IPv4)。
        server_port: 认证服务器端口 (通常为 61440)。
        bind_ip: 本地绑定 IP (通常为 0.0.0.0)。
        protocol_version: 协议版本标识 (如 'D', 'P')。
        mac_address: 本机 MAC 地址 (整数形式)。
        host_ip_bytes: 本机 IP 地址 (4 bytes)。
        primary_dns_bytes: 主 DNS 地址 (4 bytes)。
        secondary_dns_bytes: 次 DNS 地址 (4 bytes)。
        dhcp_address_bytes: DHCP 服务器地址 (4 bytes)。
        host_name: 主机名。
        host_os: 操作系统名称。
        os_info_bytes: 操作系统详细信息指纹。
        adapter_num: 网卡数量/序号标志位。
        ipdog: IPDog 监控开关位。
        auth_version: 协议版本号。
        control_check_status: 控制校验位。
        keep_alive_version: 心跳版本号。
        ror_status: 是否启用 ROR (循环右移) 加密算法。
        padding_after_ipdog: IPDog 字段后的填充位。
        padding_after_dhcp: DHCP 字段后的填充位。
        padding_auth_ext: 扩展认证区前的填充位。
        pppoe_flag: PPPoE 模式标志位 (P版专用)。
        keep_alive2_flag: KeepAlive2 的特殊标志位 (P版专用)。
    """

    # --- 1. 核心身份与连接 ---
    username: str
    password: str
    server_address: str
    server_port: int
    bind_ip: str
    protocol_version: str

    # --- 2. D 版专用参数 ---
    # 网络指纹
    mac_address: int
    host_ip_bytes: bytes
    primary_dns_bytes: bytes
    secondary_dns_bytes: bytes
    dhcp_address_bytes: bytes

    # 主机指纹
    host_name: str
    host_os: str
    os_info_bytes: bytes

    # 协议参数
    adapter_num: bytes
    ipdog: bytes
    auth_version: bytes
    control_check_status: bytes
    keep_alive_version: bytes
    ror_status: bool

    # --- 3. 动态填充区 ---
    padding_after_ipdog: bytes
    padding_after_dhcp: bytes
    padding_auth_ext: bytes

    # --- 4. P 版专用参数 ---
    pppoe_flag: bytes
    keep_alive2_flag: bytes

    def __repr__(self) -> str:
        """隐藏密码字段的安全字符串表示。"""
        return (
            f"<{self.__class__.__name__} "
            f"server={self.server_address}:{self.server_port}, "
            f"username='{self.username}', "
            f"password='******', "
            f"bind_ip='{self.bind_ip}', "
            f"protocol={self.protocol_version}>"
        )

    def __repr__(self) -> str:
        """
        覆盖默认的 repr，隐藏密码字段，防止日志泄露敏感信息。
        """
        return (
            f"<{self.__class__.__name__} "
            f"server={self.server_address}:{self.server_port}, "
            f"username='{self.username}', "
            f"password='******', "
            f"bind_ip='{self.bind_ip}', "
            f"protocol={self.protocol_version}>"
        )


def create_config_from_dict(raw_data: dict[str, Any]) -> DrcomConfig:
    """通用工厂：将字典转换为强类型配置对象。

    负责字段的清洗、默认值注入和类型转换。

    Args:
        raw_data: 原始配置字典 (来自 TOML 或 Env)。

    Returns:
        DrcomConfig: 验证并转换后的配置对象。

    Raises:
        ConfigError: 当必要字段缺失或格式错误时抛出。
    """
    try:
        # --- 内部辅助函数 ---
        def _req(key: str) -> Any:
            """获取必要字段，缺失则报错"""
            if key not in raw_data:
                raise ConfigError(f"配置缺失: 缺少必要字段 '{key}'")
            return raw_data[key]

        def _get(key: str, default: Any) -> Any:
            """获取可选字段，缺失则使用默认值"""
            return raw_data.get(key, default)

        def _to_bytes_ip(key: str, default: str = "0.0.0.0") -> bytes:
            """将 IP 字符串转换网络字节序 (4 bytes)"""
            val = str(raw_data.get(key, default))
            try:
                return socket.inet_aton(val)
            except OSError:
                raise ConfigError(f"IP 格式无效 '{key}': {val}")

        def _to_bytes_hex(key: str, default: bytes | None = None) -> bytes:
            """增强型 Hex 解析：支持 0x 前缀、空格、自动补零。"""
            if key not in raw_data:
                if default is not None:
                    return default
                raise ConfigError(f"配置缺失: 缺少 '{key}'")

            val = str(raw_data[key])
            try:
                # 清洗输入: 转小写，移除前缀，移除空格和转义符
                clean = (
                    val.lower().replace("0x", "").replace("\\x", "").replace(" ", "")
                )
                # 奇数长度补零
                if len(clean) % 2 != 0:
                    clean = "0" + clean
                return bytes.fromhex(clean)
            except ValueError:
                raise ConfigError(f"Hex 格式无效 '{key}': {val}")

        def _to_mac_int(key: str) -> int:
            """将 MAC 地址字符串转换为整数。"""
            val = str(_req(key))
            try:
                clean = val.replace(":", "").replace("-", "").replace(".", "")
                if len(clean) != 12:
                    raise ValueError
                return int(clean, 16)
            except ValueError:
                raise ConfigError(f"MAC 格式无效: {val}")

        # --- 构建对象 ---
        return DrcomConfig(
            # 基础
            username=str(_req("username")),
            password=str(_req("password")),
            server_address=str(_req("server_ip")),
            server_port=int(_get("drcom_port", 61440)),
            bind_ip=str(_get("bind_ip", "0.0.0.0")),
            protocol_version=str(_get("protocol_version", "D")).upper(),
            # D版网络
            mac_address=_to_mac_int("mac"),
            host_ip_bytes=_to_bytes_ip("host_ip"),
            primary_dns_bytes=_to_bytes_ip("primary_dns"),
            secondary_dns_bytes=_to_bytes_ip("secondary_dns"),
            dhcp_address_bytes=_to_bytes_ip("dhcp_server"),
            # 指纹
            host_name=str(_get("host_name", "Drcom-Core")),
            host_os=str(_get("host_os", "Windows 10")),
            os_info_bytes=_to_bytes_hex(
                "os_info_hex",
                b"\x94\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x28\x0a\x00\x00\x02\x00\x00\x00",
            ),
            # 协议参数
            adapter_num=_to_bytes_hex("adapter_num", b"\x01"),
            ipdog=_to_bytes_hex("ipdog", b"\x01"),
            auth_version=_to_bytes_hex("auth_version", b"\x2c\x00"),
            control_check_status=_to_bytes_hex("control_check_status", b"\x20"),
            keep_alive_version=_to_bytes_hex("keep_alive_version", b"\xdc\x02"),
            ror_status=bool(_get("ror_status", False)),
            # 动态填充
            padding_after_ipdog=_to_bytes_hex("padding_after_ipdog", b"\x00" * 4),
            padding_after_dhcp=_to_bytes_hex("padding_after_dhcp", b"\x00" * 8),
            padding_auth_ext=_to_bytes_hex("padding_auth_ext", b"\x00" * 2),
            # P版参数
            pppoe_flag=_to_bytes_hex("pppoe_flag", b"\x2a"),
            keep_alive2_flag=_to_bytes_hex("keep_alive2_flag", b"\xdc"),
        )

    except Exception as e:
        if isinstance(e, ConfigError):
            raise
        raise ConfigError(f"配置生成失败: {e}") from e


def load_config_from_toml(file_path: Path, profile: str = "default") -> DrcomConfig:
    """从 TOML 文件加载配置。

    支持多层级查找策略:
    1. [profile.xxx]: 优先查找指定的 profile 块。
    2. [drcom]: 兼容旧版配置块。
    3. Root: 兼容根目录直接配置。

    Args:
        file_path: TOML 文件路径。
        profile: 配置预设名。默认为 "default"。

    Returns:
        DrcomConfig: 配置对象。

    Raises:
        ConfigError: 文件读取失败或 Profile 不存在。
    """
    if not file_path.exists():
        raise ConfigError(f"配置文件未找到: {file_path}")

    try:
        with open(file_path, "rb") as f:
            data = tomllib.load(f)
    except Exception as e:
        raise ConfigError(f"读取 TOML 失败: {e}") from e

    raw_config = {}

    # 优先查找 profile
    if "profile" in data:
        if profile not in data["profile"]:
            # 如果指定了非 default 的 profile 且没找到，报错
            if profile != "default":
                raise ConfigError(f"未找到预设: [profile.{profile}]")
        else:
            raw_config = data["profile"][profile]

    # 兼容旧格式 [drcom]
    elif "drcom" in data:
        if profile != "default":
            logger.warning(f"配置仅包含 [drcom] 节，忽略 profile='{profile}'。")
        raw_config = data["drcom"]
    else:
        # 兼容根目录直接配置
        raw_config = data

    return create_config_from_dict(raw_config)


def load_config_from_env() -> DrcomConfig:
    """从环境变量加载配置 (Docker/Cloud Friendly)。

    自动读取所有以 `DRCOM_` 开头的环境变量，并映射到配置字段。
    例如: `DRCOM_USERNAME` -> `username`。

    Returns:
        DrcomConfig: 配置对象。

    Raises:
        ConfigError: 未检测到任何相关环境变量。
    """
    # 字段映射表 (Config Field -> Env Suffix)
    env_map = {
        # 基础
        "username": "USERNAME",
        "password": "PASSWORD",
        "server_ip": "SERVER_IP",
        "drcom_port": "PORT",
        "bind_ip": "BIND_IP",
        "protocol_version": "PROTOCOL_VERSION",
        # D版
        "mac": "MAC",
        "host_ip": "HOST_IP",
        "primary_dns": "PRIMARY_DNS",
        "secondary_dns": "SECONDARY_DNS",
        "dhcp_server": "DHCP_SERVER",
        "host_name": "HOST_NAME",
        "host_os": "HOST_OS",
        "os_info_hex": "OS_INFO_HEX",
        "adapter_num": "ADAPTER_NUM",
        "ipdog": "IPDOG",
        "auth_version": "AUTH_VERSION",
        "control_check_status": "CONTROL_CHECK_STATUS",
        "keep_alive_version": "KEEP_ALIVE_VERSION",
        "ror_status": "ROR_STATUS",
        # 填充
        "padding_after_ipdog": "PADDING_AFTER_IPDOG",
        "padding_after_dhcp": "PADDING_AFTER_DHCP",
        "padding_auth_ext": "PADDING_AUTH_EXT",
        # P版
        "pppoe_flag": "PPPOE_FLAG",
        "keep_alive2_flag": "KEEP_ALIVE2_FLAG",
    }

    raw_data = {}

    for cfg_key, env_suffix in env_map.items():
        env_key = f"DRCOM_{env_suffix}"
        val = os.environ.get(env_key)
        if val is not None:
            raw_data[cfg_key] = val

    if not raw_data:
        raise ConfigError("未检测到 DRCOM_ 前缀的环境变量")

    return create_config_from_dict(raw_data)
