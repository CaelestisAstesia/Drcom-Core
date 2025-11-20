# tests/conftest.py
import sys
from pathlib import Path

import pytest

# 确保 src 目录在 sys.path 中
src_path = Path(__file__).resolve().parent.parent / "src"
if str(src_path) not in sys.path:
    sys.path.insert(0, str(src_path))

from drcom_core.config import DrcomConfig


@pytest.fixture
def valid_config():
    """
    [Fixture] 返回一个符合 v1.0.0a3 标准的 DrcomConfig 对象。
    包含所有必填字段（如 os_info_bytes），用于依赖注入。
    """
    return DrcomConfig(
        username="test_user",
        password="test_password",
        server_address="10.10.10.1",
        mac_address=0x001122334455,  # 00:11:22:33:44:55
        host_ip_bytes=b"\xc0\xa8\x01\x64",  # 192.168.1.100
        primary_dns_bytes=b"\x01\x01\x01\x01",  # 1.1.1.1
        dhcp_address_bytes=b"\xc0\xa8\x01\x01",  # 192.168.1.1
        bind_ip="0.0.0.0",
        drcom_port=61440,
        protocol_version="D",
        ror_status=False,
        host_name="Test-PC",
        host_os="Windows Test",
        # 模拟一段 20 字节的 OS Info (Windows 10 指纹)
        os_info_bytes=bytes.fromhex("940000000600000000000000280a000002000000"),
        adapter_num=b"\x01",
        ipdog=b"\x01",
        auth_version=b"\x2c\x00",
        control_check_status=b"\x20",
        keep_alive_version=b"\xdc\x02",
    )
