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
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict

# 检查 Python 版本以确保 tomllib 可用 (Python 3.11+)
if sys.version_info >= (3, 11):
    import tomllib
else:
    raise RuntimeError("Drcom-Core 需要 Python 3.11+ 以支持标准库 tomllib。")

from .exceptions import ConfigError

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class DrcomConfig:
    """
    [Model] DrcomCore 的强类型配置对象。
    此对象仅用于存储清洗后的数据，假设所有字段在初始化前已通过校验。
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
    # 注意：host_name 和 host_os 仅作为字符串保留，
    # 复杂的二进制指纹信息由 os_info_bytes 承载。
    host_name: str
    host_os: str
    os_info_bytes: bytes
    """
    系统环境指纹数据 (包含 Version, Platform ID 等)。
    由上层应用 (CLI) 生成或从配置中以 Hex 字符串形式加载。
    """

    # --- 协议参数 (字节形式) ---
    adapter_num: bytes
    ipdog: bytes
    auth_version: bytes
    control_check_status: bytes
    keep_alive_version: bytes


def validate_and_create_config(raw_data: Dict[str, Any]) -> DrcomConfig:
    """
    [Factory] 配置工厂函数。

    负责将输入的原始字典（来源可能是 TOML、CLI 参数或 GUI 输入）
    转换为强类型的 DrcomConfig 对象。

    在此处集中处理所有的类型转换、格式清洗和数据校验。
    """
    try:
        # --- 内部辅助函数：字段提取与转换 ---

        def _req(key: str) -> Any:
            """获取必填项"""
            if key not in raw_data:
                raise ConfigError(f"配置缺失: 缺少必要的键 '{key}'")
            return raw_data[key]

        def _to_bytes_ip(key: str) -> bytes:
            """IP 字符串 -> 4字节 bytes"""
            val = _req(key)
            try:
                return socket.inet_aton(str(val))
            except OSError:
                raise ConfigError(f"配置错误: '{key}' IP 格式无效 ({val})")

        def _to_bytes_hex(key: str) -> bytes:
            """Hex 字符串 -> bytes"""
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
            """MAC 字符串 -> int"""
            val = str(_req(key))
            try:
                clean = val.replace(":", "").replace("-", "").replace(".", "")
                if len(clean) != 12:
                    raise ValueError
                return int(clean, 16)
            except ValueError:
                raise ConfigError(f"配置错误: MAC 地址格式无效 ({val})")

        # --- 构建与校验 ---

        # 核心参数
        username = str(_req("username"))
        password = str(_req("password"))
        server_ip = str(_req("server_ip"))
        mac = _to_mac_int("mac")

        # 验证 MAC 范围
        if not (0 <= mac <= 0xFFFFFFFFFFFF):
            raise ConfigError("配置错误: MAC 地址数值溢出")

        # 网络参数
        host_ip = _to_bytes_ip("host_ip")
        dns = _to_bytes_ip("primary_dns")
        dhcp = _to_bytes_ip("dhcp_server")
        bind_ip = str(raw_data.get("bind_ip", "0.0.0.0"))  # 允许缺省，默认 0.0.0.0
        port = int(raw_data.get("drcom_port", 61440))

        if not (1 <= port <= 65535):
            raise ConfigError(f"配置错误: 端口号 {port} 超出范围")

        # 协议参数
        p_ver = str(_req("protocol_version")).upper()
        ror = bool(raw_data.get("ror_status", False))

        # 指纹参数
        h_name = str(_req("host_name"))
        h_os = str(_req("host_os"))

        # 重要的 OS 指纹数据块
        # 如果配置文件里没有 os_info_hex，则需要 CLI 注入。
        # 这里我们允许它从配置加载，键名为 os_info_hex
        os_info = _to_bytes_hex("os_info_hex")

        # 协议魔数
        adp_num = _to_bytes_hex("adapter_num")
        ipdog = _to_bytes_hex("ipdog")
        auth_ver = _to_bytes_hex("auth_version")
        chk_status = _to_bytes_hex("control_check_status")
        ka_ver = _to_bytes_hex("keep_alive_version")

        # 长度校验
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
        # 捕获所有转换错误并包装
        if isinstance(e, ConfigError):
            raise
        raise ConfigError(f"配置校验失败: {e}") from e


def load_config_from_toml(file_path: Path) -> DrcomConfig:
    """
    [Loader] 从 TOML 文件加载配置。

    只负责 I/O 读取，具体的校验逻辑委托给 validate_and_create_config。
    """
    if not file_path.exists():
        raise ConfigError(f"配置文件未找到: {file_path}")

    try:
        with open(file_path, "rb") as f:
            data = tomllib.load(f)
    except (OSError, tomllib.TOMLDecodeError) as e:
        raise ConfigError(f"读取 TOML 配置文件失败: {e}") from e

    # 提取 [drcom] 节或使用根字典
    raw_config = data.get("drcom", data)

    # 委托给工厂函数进行校验和创建
    return validate_and_create_config(raw_config)
