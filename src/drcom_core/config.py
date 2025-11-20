# src/drcom_core/config.py
"""
Dr.COM 核心库 - 配置模块

采用三层架构设计：
1. Model: DrcomConfig 数据类 (不可变，强类型)。
2. Factory: validate_and_create_config 函数 (负责清洗、转换和校验原始数据)。
3. Loader: load_config_from_toml 函数 (负责 I/O 读取)。
"""

import logging
import socket
import tomllib  # Python 3.11+ 标准库
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .exceptions import ConfigError

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class DrcomConfig:
    """
    [Model] DrcomCore 的强类型配置对象。
    """

    # --- 核心身份凭据 ---
    username: str
    password: str
    server_address: str
    mac_address: int

    # --- 网络环境 ---
    host_ip_bytes: bytes
    primary_dns_bytes: bytes
    dhcp_address_bytes: bytes
    bind_ip: str
    drcom_port: int

    # --- 协议控制 ---
    protocol_version: str
    ror_status: bool

    # --- 主机指纹 ---
    host_name: str
    host_os: str
    os_info_bytes: bytes

    # --- 协议参数 (字节形式) ---
    adapter_num: bytes
    ipdog: bytes
    auth_version: bytes
    control_check_status: bytes
    keep_alive_version: bytes


def validate_and_create_config(raw_data: dict[str, Any]) -> DrcomConfig:
    """
    [Factory] 配置工厂函数。
    负责将输入的原始字典转换为强类型的 DrcomConfig 对象。
    """
    try:
        # --- 内部辅助函数：字段提取与转换 ---

        def _req(key: str) -> Any:
            if key not in raw_data:
                raise ConfigError(f"配置缺失: 缺少必要的键 '{key}'")
            return raw_data[key]

        def _to_bytes_ip(key: str) -> bytes:
            val = _req(key)
            try:
                return socket.inet_aton(str(val))
            except OSError:
                raise ConfigError(f"配置错误: '{key}' IP 格式无效 ({val})")

        def _to_bytes_hex(key: str) -> bytes:
            val = str(_req(key))
            try:
                clean = (
                    val.lower().replace("0x", "").replace("\\x", "").replace(" ", "")
                )
                if len(clean) % 2 != 0:
                    clean = "0" + clean
                return bytes.fromhex(clean)
            except ValueError:
                raise ConfigError(f"配置错误: '{key}' Hex 格式无效 ({val})")

        def _to_mac_int(key: str) -> int:
            val = str(_req(key))
            try:
                clean = val.replace(":", "").replace("-", "").replace(".", "")
                if len(clean) != 12:
                    raise ValueError
                return int(clean, 16)
            except ValueError:
                raise ConfigError(f"配置错误: MAC 地址格式无效 ({val})")

        # --- 构建与校验 ---
        username = str(_req("username"))
        password = str(_req("password"))
        server_ip = str(_req("server_ip"))
        mac = _to_mac_int("mac")

        if not (0 <= mac <= 0xFFFFFFFFFFFF):
            raise ConfigError("配置错误: MAC 地址数值溢出")

        host_ip = _to_bytes_ip("host_ip")
        dns = _to_bytes_ip("primary_dns")
        dhcp = _to_bytes_ip("dhcp_server")
        bind_ip = str(raw_data.get("bind_ip", "0.0.0.0"))
        port = int(raw_data.get("drcom_port", 61440))

        if not (1 <= port <= 65535):
            raise ConfigError(f"配置错误: 端口号 {port} 超出范围")

        p_ver = str(_req("protocol_version")).upper()
        ror = bool(raw_data.get("ror_status", False))

        h_name = str(_req("host_name"))
        h_os = str(_req("host_os"))
        os_info = _to_bytes_hex("os_info_hex")

        adp_num = _to_bytes_hex("adapter_num")
        ipdog = _to_bytes_hex("ipdog")
        auth_ver = _to_bytes_hex("auth_version")
        chk_status = _to_bytes_hex("control_check_status")
        ka_ver = _to_bytes_hex("keep_alive_version")

        if len(auth_ver) != 2:
            raise ConfigError("配置错误: auth_version 必须为 2 字节")
        if len(ka_ver) != 2:
            raise ConfigError("配置错误: keep_alive_version 必须为 2 字节")

        return DrcomConfig(
            username=username,
            password=password,
            server_address=server_ip,
            mac_address=mac,
            host_ip_bytes=host_ip,
            primary_dns_bytes=dns,
            dhcp_address_bytes=dhcp,
            bind_ip=bind_ip,
            drcom_port=port,
            protocol_version=p_ver,
            ror_status=ror,
            host_name=h_name,
            host_os=h_os,
            os_info_bytes=os_info,
            adapter_num=adp_num,
            ipdog=ipdog,
            auth_version=auth_ver,
            control_check_status=chk_status,
            keep_alive_version=ka_ver,
        )

    except Exception as e:
        if isinstance(e, ConfigError):
            raise
        raise ConfigError(f"配置校验失败: {e}") from e


def load_config_from_toml(file_path: Path) -> DrcomConfig:
    """
    [Loader] 从 TOML 文件加载配置。
    """
    if not file_path.exists():
        raise ConfigError(f"配置文件未找到: {file_path}")

    try:
        with open(file_path, "rb") as f:
            data = tomllib.load(f)
    except (OSError, tomllib.TOMLDecodeError) as e:
        raise ConfigError(f"读取 TOML 配置文件失败: {e}") from e

    raw_config = data.get("drcom", data)
    return validate_and_create_config(raw_config)
