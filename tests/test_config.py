# tests/test_config.py
import pytest

from drcom_core import ConfigError, load_config_from_dict


def test_load_valid_config(valid_env_dict):
    """测试标准情况下的加载"""
    config = load_config_from_dict(valid_env_dict)

    assert config.username == "test_user"
    assert config.server_address == "10.10.10.1"
    # 验证 MAC 地址是否正确转为整数
    assert config.mac_address == 0x001122334455
    # 验证布尔值解析
    assert config.magic_tail is True
    assert config.ror_status is False


def test_hex_bytes_parsing(valid_env_dict):
    """测试 Hex 字符串到 bytes 的转换"""
    # 测试带 0x 前缀的情况
    valid_env_dict["CONTROL_CHECK_STATUS"] = "0x20"
    # 测试奇数长度 (应该自动补0)
    valid_env_dict["ADAPTERNUM"] = "1"  # -> 01

    config = load_config_from_dict(valid_env_dict)
    assert config.control_check_status == b"\x20"
    assert config.adapter_num == b"\x01"


def test_missing_required_field(valid_env_dict):
    """测试缺少必要字段"""
    del valid_env_dict["PASSWORD"]
    with pytest.raises(ConfigError, match="缺少必要的配置项"):
        load_config_from_dict(valid_env_dict)


def test_invalid_mac_format(valid_env_dict):
    """测试错误的 MAC 地址"""
    valid_env_dict["MAC"] = "NOT_A_MAC_ADDRESS"
    with pytest.raises(ConfigError, match="MAC 地址格式无效"):
        load_config_from_dict(valid_env_dict)


def test_invalid_ip_format(valid_env_dict):
    """测试错误的 IP 地址"""
    valid_env_dict["SERVER_IP"] = "999.999.999.999"
    with pytest.raises(ConfigError, match="HOST_IP 格式无效"):
        # 注意：load_config_from_dict 内部对 SERVER_IP 的校验可能在 HOST_IP 之后或之前
        valid_env_dict["HOST_IP"] = "invalid_ip"
        load_config_from_dict(valid_env_dict)
