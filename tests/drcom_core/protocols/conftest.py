# tests/protocols/conftest.py
"""
Pytest 配置文件，用于存放 protocols/ 目录测试的公共 Fixtures。
"""

import pytest

from drcom_core.protocols import constants

# --- 模拟的用户配置 ---


@pytest.fixture(scope="module")
def username() -> str:
    return "testuser"


@pytest.fixture(scope="module")
def password() -> str:
    return "testpass123"


@pytest.fixture(scope="module")
def mac_address() -> int:
    # 0x112233445566
    return 18838586676582


@pytest.fixture(scope="module")
def mac_bytes() -> bytes:
    # 0x112233445566
    return b"\x11\x22\x33\x44\x55\x66"


@pytest.fixture(scope="module")
def host_ip_bytes() -> bytes:
    # 192.168.1.10
    return b"\xc0\xa8\x01\x0a"


@pytest.fixture(scope="module")
def primary_dns_bytes() -> bytes:
    # 114.114.114.114
    return b"\x72\x72\x72\x72"


@pytest.fixture(scope="module")
def dhcp_server_bytes() -> bytes:
    # 192.168.1.1
    return b"\xc0\xa8\x01\x01"


@pytest.fixture(scope="module")
def host_name() -> str:
    return "Test-PC"


@pytest.fixture(scope="module")
def host_os() -> str:
    return "Windows 11"


# --- 模拟的协议参数 ---


@pytest.fixture(scope="module")
def control_check_status() -> bytes:
    return b"\x20"


@pytest.fixture(scope="module")
def adapter_num() -> bytes:
    return b"\x01"


@pytest.fixture(scope="module")
def ipdog() -> bytes:
    return b"\x01"


@pytest.fixture(scope="module")
def auth_version() -> bytes:
    return b"\x2c\x00"


@pytest.fixture(scope="module")
def keep_alive_version() -> bytes:
    return constants.KEEP_ALIVE_VERSION  # b'\xdc\x02'


# --- 模拟的动态会话数据 ---


@pytest.fixture
def salt() -> bytes:
    """一个模拟的 4 字节 Challenge Salt"""
    return b"\x1a\x2b\x3c\x4d"


@pytest.fixture
def auth_info() -> bytes:
    """一个模拟的 16 字节 Auth Info (Tail)，来自登录成功响应"""
    return b"\xaa" * 16
