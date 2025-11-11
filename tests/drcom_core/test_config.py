# tests/drcom_core/test_config.py
import pytest

from drcom_core import load_config_from_dict
from drcom_core.config import DrcomConfig
from drcom_core.protocols import constants

# 1. 定义一个最小化的、"快乐路径"的配置
valid_config_dict = {
    "USERNAME": "testuser",
    "PASSWORD": "testpass",
    "SERVER_IP": "1.2.3.4",
    "HOST_IP": "10.0.0.1",
    "MAC": "00:11:22:33:44:55",
}


def test_config_happy_path():
    """
    测试：使用一个有效的字典加载配置
    """
    # 1. 准备 (Arrange)
    config_dict = valid_config_dict.copy()

    # 2. 执行 (Act)
    config = load_config_from_dict(config_dict)

    # 3. 断言 (Assert)
    assert isinstance(config, DrcomConfig)
    assert config.username == "testuser"
    assert config.password == "testpass"
    assert config.server_address == "1.2.3.4"
    assert config.mac_address == 0x001122334455  # 验证 MAC 地址被正确转换
    assert config.host_ip_bytes == b"\n\x00\x00\x01"  # 验证 IP 被正确转换


def test_config_missing_key():
    """
    测试：缺少必要的键 (USERNAME) 时，应抛出 KeyError
    """
    # 1. 准备 (Arrange)
    config_dict = valid_config_dict.copy()
    del config_dict["USERNAME"]  # 模拟 USERNAME 缺失

    # 2. 执行 & 断言 (Act & Assert)
    with pytest.raises(KeyError) as e:
        load_config_from_dict(config_dict)

    # 验证异常信息是否包含了我们期望的键
    assert "USERNAME" in str(e.value)


def test_config_invalid_mac_format():
    """
    测试：MAC 地址格式错误时，应抛出 ValueError
    """
    # 1. 准备 (Arrange)
    config_dict = valid_config_dict.copy()
    config_dict["MAC"] = "not-a-mac"  # 格式错误

    # 2. 执行 & 断言 (Act & Assert)
    with pytest.raises(ValueError) as e:
        load_config_from_dict(config_dict)

    assert "MAC 地址格式无效" in str(e.value)


def test_config_invalid_ip_format():
    """
    测试：IP 地址格式错误时，应抛出 ValueError
    """
    # 1. 准备 (Arrange)
    config_dict = valid_config_dict.copy()
    config_dict["HOST_IP"] = "10.0.0.999"  # IP 无效

    # 2. 执行 & 断言 (Act & Assert)
    with pytest.raises(ValueError) as e:
        load_config_from_dict(config_dict)

    assert "IP 地址无效" in str(e.value)


def test_config_default_values():
    """
    测试：当可选键缺失时，是否正确使用了默认值
    """
    # 1. 准备 (Arrange)
    config_dict = valid_config_dict.copy()
    # (不提供 HOST_NAME, AUTH_VERSION 等)

    # 2. 执行 (Act)
    config = load_config_from_dict(config_dict)

    # 3. 断言 (Assert)
    # 验证 dataclass 是否从 constants.py 获取了默认值
    assert config.host_name == constants.DEFAULT_HOST_NAME
    assert config.keep_alive_version == constants.KEEP_ALIVE_VERSION
    assert config.auth_version == b"\x0a\x00"  # '0a00' (默认值)
