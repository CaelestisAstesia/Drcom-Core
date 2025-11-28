# src/drcom_core/config.py
"""
Dr.COM 核心库 - 配置模块 (v1.0.0)

支持三种加载策略：
1. 文件加载 (TOML): 支持 [profile] 和 [drcom] 结构。
2. 环境加载 (Env): 读取 DRCOM_ 前缀的环境变量 (适合 Docker)。
3. 内存加载 (Dict): 直接传入字典 (适合 GUI/集成)。
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
    """[Model] DrcomCore 的强类型配置对象"""

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


def create_config_from_dict(raw_data: dict[str, Any]) -> DrcomConfig:
    """
    [Factory] 通用工厂：将字典转换为配置对象。
    """
    try:
        # --- 内部辅助函数 ---
        def _req(key: str) -> Any:
            # 优先读字典，没有则抛错
            if key not in raw_data:
                raise ConfigError(f"配置缺失: 缺少 '{key}'")
            return raw_data[key]

        def _to_bytes_ip(key: str) -> bytes:
            val = _req(key)
            try:
                return socket.inet_aton(str(val))
            except OSError:
                raise ConfigError(f"IP 格式无效 '{key}': {val}")

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
                raise ConfigError(f"Hex 格式无效 '{key}': {val}")

        def _to_mac_int(key: str) -> int:
            val = str(_req(key))
            try:
                clean = val.replace(":", "").replace("-", "").replace(".", "")
                if len(clean) != 12:
                    raise ValueError
                return int(clean, 16)
            except ValueError:
                raise ConfigError(f"MAC 格式无效: {val}")

        # --- 字段提取 ---
        # 允许部分字段有默认值 (增强鲁棒性)
        return DrcomConfig(
            username=str(_req("username")),
            password=str(_req("password")),
            server_address=str(_req("server_ip")),
            mac_address=_to_mac_int("mac"),
            host_ip_bytes=_to_bytes_ip("host_ip"),
            primary_dns_bytes=_to_bytes_ip("primary_dns"),
            dhcp_address_bytes=_to_bytes_ip("dhcp_server"),
            bind_ip=str(raw_data.get("bind_ip", "0.0.0.0")),
            drcom_port=int(raw_data.get("drcom_port", 61440)),
            protocol_version=str(_req("protocol_version")).upper(),
            ror_status=bool(raw_data.get("ror_status", False)),
            host_name=str(_req("host_name")),
            host_os=str(_req("host_os")),
            os_info_bytes=_to_bytes_hex("os_info_hex"),
            adapter_num=_to_bytes_hex("adapter_num"),
            ipdog=_to_bytes_hex("ipdog"),
            auth_version=_to_bytes_hex("auth_version"),
            control_check_status=_to_bytes_hex("control_check_status"),
            keep_alive_version=_to_bytes_hex("keep_alive_version"),
        )
    except Exception as e:
        if isinstance(e, ConfigError):
            raise
        raise ConfigError(f"配置校验失败: {e}") from e


def load_config_from_toml(file_path: Path, profile: str = "default") -> DrcomConfig:
    """
    [Loader] 从 TOML 文件加载。支持 [profile.xxx] 和 [drcom]。
    """
    if not file_path.exists():
        raise ConfigError(f"配置文件未找到: {file_path}")

    try:
        with open(file_path, "rb") as f:
            data = tomllib.load(f)
    except Exception as e:
        raise ConfigError(f"读取 TOML 失败: {e}") from e

    raw_config = {}
    if "profile" in data:
        if profile not in data["profile"]:
            raise ConfigError(f"未找到预设: [profile.{profile}]")
        raw_config = data["profile"][profile]
    elif "drcom" in data:
        if profile != "default":
            logger.warning(f"旧版配置格式，忽略 profile='{profile}'，使用 [drcom]。")
        raw_config = data["drcom"]
    else:
        raw_config = data

    return create_config_from_dict(raw_config)


def load_config_from_env() -> DrcomConfig:
    """
    [Loader] 从环境变量加载配置 (Docker/Cloud Friendly)。

    规则：将配置项大写并加上 DRCOM_ 前缀。
    例如: username -> DRCOM_USERNAME
         server_ip -> DRCOM_SERVER_IP
    """
    # 必需字段映射表
    keys = [
        "username",
        "password",
        "server_ip",
        "mac",
        "host_ip",
        "primary_dns",
        "dhcp_server",
        "protocol_version",
        "host_name",
        "host_os",
        "os_info_hex",
        "adapter_num",
        "ipdog",
        "auth_version",
        "control_check_status",
        "keep_alive_version",
    ]

    raw_data = {}

    # 1. 读取必需字段
    for k in keys:
        env_key = f"DRCOM_{k.upper()}"
        val = os.environ.get(env_key)
        if val is not None:
            raw_data[k] = val

    # 2. 读取可选字段
    if os.environ.get("DRCOM_BIND_IP"):
        raw_data["bind_ip"] = os.environ["DRCOM_BIND_IP"]
    if os.environ.get("DRCOM_PORT"):
        raw_data["drcom_port"] = os.environ["DRCOM_PORT"]
    if os.environ.get("DRCOM_ROR_STATUS"):
        raw_data["ror_status"] = os.environ["DRCOM_ROR_STATUS"]

    # 3. 校验
    try:
        # 简单检查：如果 username 都没有，说明没配置环境变量
        if "username" not in raw_data:
            raise ConfigError("环境变量中未找到 DRCOM_USERNAME")

        return create_config_from_dict(raw_data)
    except ConfigError as e:
        raise ConfigError(f"环境变量配置无效: {e}") from e
