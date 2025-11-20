# tests/test_config.py
import socket
from pathlib import Path

import pytest

from drcom_core import ConfigError
from drcom_core.config import load_config_from_toml, validate_and_create_config


# --- 辅助函数：生成有效字典 ---
def _get_valid_raw_dict():
    return {
        "username": "u",
        "password": "p",
        "server_ip": "1.1.1.1",
        "mac": "001122334455",
        "host_ip": "1.1.1.1",
        "primary_dns": "1.1.1.1",
        "dhcp_server": "1.1.1.1",
        "bind_ip": "0.0.0.0",
        "drcom_port": 61440,
        "protocol_version": "D",
        "ror_status": False,
        "host_name": "h",
        "host_os": "o",
        "os_info_hex": "00" * 20,  # 模拟 Hex 字符串
        "adapter_num": "01",
        "ipdog": "01",
        "auth_version": "2c00",
        "control_check_status": "20",
        "keep_alive_version": "dc02",
    }


# --- Factory 测试 (核心逻辑) ---


def test_validate_valid_dict():
    """测试使用完全合法的字典创建配置"""
    raw_data = _get_valid_raw_dict()
    config = validate_and_create_config(raw_data)

    assert config.username == "u"
    assert config.mac_address == 0x001122334455
    assert config.host_ip_bytes == socket.inet_aton("1.1.1.1")
    assert len(config.os_info_bytes) == 20
    assert config.ror_status is False


def test_validate_missing_field():
    """测试缺少必填字段"""
    raw_data = {"username": "test"}  # 缺少大量字段
    with pytest.raises(ConfigError, match="配置缺失"):
        validate_and_create_config(raw_data)


def test_validate_invalid_mac():
    """测试 MAC 地址格式错误"""
    raw_data = _get_valid_raw_dict()
    raw_data["mac"] = "INVALID_MAC"
    with pytest.raises(ConfigError, match="MAC 地址格式无效"):
        validate_and_create_config(raw_data)


def test_validate_invalid_ip():
    """测试 IP 地址格式错误"""
    raw_data = _get_valid_raw_dict()
    raw_data["host_ip"] = "999.999.999.999"
    with pytest.raises(ConfigError, match="IP 格式无效"):
        validate_and_create_config(raw_data)


def test_validate_hex_format():
    """测试 Hex 字符串清洗 (0x 前缀, 空格)"""
    raw_data = _get_valid_raw_dict()
    raw_data["adapter_num"] = "0x 01"  # 应该被清洗为 b'\x01'
    config = validate_and_create_config(raw_data)
    assert config.adapter_num == b"\x01"


# --- Loader 测试 (I/O) ---


def test_load_toml_file(tmp_path):
    """测试从 TOML 文件加载"""
    toml_content = """
    [drcom]
    username = "toml_user"
    password = "123"
    server_ip = "1.1.1.1"
    mac = "001122334455"
    host_ip = "1.1.1.1"
    primary_dns = "1.1.1.1"
    dhcp_server = "1.1.1.1"
    protocol_version = "D"
    host_name = "h"
    host_os = "o"
    os_info_hex = "0000"
    adapter_num = "01"
    ipdog = "01"
    auth_version = "2c00"
    control_check_status = "20"
    keep_alive_version = "dc02"
    """
    f = tmp_path / "config.toml"
    f.write_text(toml_content, encoding="utf-8")

    config = load_config_from_toml(f)
    assert config.username == "toml_user"


def test_load_toml_not_found():
    """测试文件不存在"""
    with pytest.raises(ConfigError, match="配置文件未找到"):
        load_config_from_toml(Path("non_existent.toml"))
