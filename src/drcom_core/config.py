# src/drcom_core/config.py
"""
Dr.COM 核心库 - 配置模块 (v1.0.0)

功能特性：
1. 多源加载: 支持 TOML 文件 (带 Profile)、环境变量 (Docker)、内存字典。
2. 强类型校验: 自动清洗 Hex/IP 格式，转换为 bytes/int。
3. 协议适配: 支持动态配置协议填充位 (Padding) 和魔数，适配魔改版协议。
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
    """
    [Model] DrcomCore 的强类型配置对象。

    该类定义了 drcom-core 运行所需的所有参数。
    所有字段均为只读 (frozen=True)，确保配置在运行时不可变。
    """

    # =========================================================================
    # 1. 核心身份与连接 (Identity & Connection)
    # =========================================================================
    username: str
    """认证用户名"""

    password: str
    """认证密码"""

    server_address: str
    """认证服务器 IP 地址 (IPv4)"""

    server_port: int
    """认证服务器端口 (通常为 61440)"""

    bind_ip: str
    """本地绑定 IP (通常为 0.0.0.0 或本机特定网卡 IP)"""

    # 协议版本: 'D', 'P' 等
    protocol_version: str
    """协议版本标识 (如 'D' 代表 5.2.0(D) 版, 'P' 代表 PPPoE 版)"""

    # =========================================================================
    # 2. D 版专用参数 (D-Series Specifics)
    # =========================================================================
    # --- 网络指纹 ---
    mac_address: int
    """本机 MAC 地址 (整数形式，用于异或加密)"""

    host_ip_bytes: bytes
    """本机 IP 地址 (4字节 bytes)"""

    primary_dns_bytes: bytes
    """主 DNS 地址 (4字节 bytes)"""

    secondary_dns_bytes: bytes  # [Merged]
    """次 DNS 地址 (4字节 bytes)"""

    dhcp_address_bytes: bytes
    """DHCP 服务器地址 (4字节 bytes)"""

    # --- 主机指纹 ---
    host_name: str
    """主机名 (用于协议填充)"""

    host_os: str
    """操作系统名称 (用于协议填充)"""

    os_info_bytes: bytes
    """操作系统详细信息指纹 (Hex bytes)"""

    # --- 协议参数 (Hex) ---
    adapter_num: bytes
    """网卡数量/序号标志位"""

    ipdog: bytes
    """IPDog 监控开关位"""

    auth_version: bytes
    """协议版本号 (如 \\x2c\\x00)"""

    control_check_status: bytes
    """控制校验位"""

    keep_alive_version: bytes
    """心跳版本号 (如 \\xdc\\x02)"""

    ror_status: bool
    """是否启用 ROR (循环右移) 加密算法"""

    # =========================================================================
    # 3. 动态填充区 (Dynamic Padding) - [Merged from Protocol Analysis]
    # =========================================================================
    padding_after_ipdog: bytes
    """IPDog 字段后的填充位 (用于适配魔改协议)"""

    padding_after_dhcp: bytes
    """DHCP 字段后的填充位"""

    padding_auth_ext: bytes
    """扩展认证区前的填充位"""

    # =========================================================================
    # 4. P 版专用参数 (P-Series) - [Merged]
    # =========================================================================
    pppoe_flag: bytes
    """PPPoE 模式标志位"""

    keep_alive2_flag: bytes
    """KeepAlive2 的特殊标志位"""


def create_config_from_dict(raw_data: dict[str, Any]) -> DrcomConfig:
    """
    [Factory] 通用工厂：将字典转换为强类型配置对象。

    负责字段的清洗、默认值注入和类型转换 (如 Hex 字符串转 bytes, IP 字符串转 bytes)。

    Args:
        raw_data (dict[str, Any]): 原始配置字典 (来自 TOML 或 Env)。

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
            """
            增强型 Hex 解析：支持 0x 前缀、空格、自动补零。
            例如: '0x12 34' -> b'\x12\x34'
            """
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
            """
            将 MAC 地址字符串转换为整数。
            支持格式: AA:BB:CC..., AA-BB-CC..., AABBCC...
            """
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
            secondary_dns_bytes=_to_bytes_ip("secondary_dns"),  # Default 0.0.0.0
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
            # 动态填充 (New)
            padding_after_ipdog=_to_bytes_hex("padding_after_ipdog", b"\x00" * 4),
            padding_after_dhcp=_to_bytes_hex("padding_after_dhcp", b"\x00" * 8),
            padding_auth_ext=_to_bytes_hex("padding_auth_ext", b"\x00" * 2),
            # P版参数 (New)
            pppoe_flag=_to_bytes_hex("pppoe_flag", b"\x2a"),
            keep_alive2_flag=_to_bytes_hex("keep_alive2_flag", b"\xdc"),
        )

    except Exception as e:
        if isinstance(e, ConfigError):
            raise
        raise ConfigError(f"配置生成失败: {e}") from e


def load_config_from_toml(file_path: Path, profile: str = "default") -> DrcomConfig:
    """
    [Loader] 从 TOML 文件加载配置。

    支持多层级查找策略:
    1. [profile.xxx]: 优先查找指定的 profile 块。
    2. [drcom]: 兼容旧版配置块。
    3. Root: 兼容根目录直接配置。

    Args:
        file_path (Path): TOML 文件路径。
        profile (str, optional): 配置预设名。默认为 "default"。

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
            # 如果是 default 且没找到，尝试回退到 [drcom] 或 根目录，视逻辑而定
            # 这里保持您的逻辑：严格检查
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
    """
    [Loader] 从环境变量加载配置 (Docker/Cloud Friendly)。

    自动读取所有以 `DRCOM_` 开头的环境变量，并映射到配置字段。

    映射规则示例:
    - DRCOM_USERNAME -> username
    - DRCOM_SERVER_IP -> server_ip
    - DRCOM_OS_INFO_HEX -> os_info_hex

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
