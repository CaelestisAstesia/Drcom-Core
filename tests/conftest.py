# tests/conftest.py
import pytest

from drcom_core import load_config_from_dict


@pytest.fixture
def valid_env_dict():
    """返回一个包含所有必需字段的有效配置字典"""
    return {
        "USERNAME": "test_user",
        "PASSWORD": "test_password",
        "SERVER_IP": "10.10.10.1",
        "HOST_IP": "192.168.1.100",
        "MAC": "00-11-22-33-44-55",  # 测试标准格式
        "DRCOM_PORT": "61440",
        # 可选参数
        "HOST_NAME": "Test-PC",
        "HOST_OS": "Windows Test",
        "MAGIC_TAIL": "true",  # 测试布尔值解析
        "ROR_STATUS": "0",
    }


@pytest.fixture
def valid_config(valid_env_dict):
    """返回一个已解析的 DrcomConfig 对象"""
    return load_config_from_dict(valid_env_dict)
