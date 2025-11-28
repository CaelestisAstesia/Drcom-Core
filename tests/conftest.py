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
    [Fixture] 返回一个符合 v1.0.0 标准的 DrcomConfig 对象。
    [Fix] 已更新适配 config.py 中的新增字段 (padding, flags)。
    """
    return DrcomConfig(
        username="test_user",
        password="test_password",
        server_address="10.10.10.1",
        server_port=61440,  # [Fix] 以前可能是 drcom_port，现在模型统一为 server_port
        bind_ip="0.0.0.0",
        protocol_version="D",
        # --- D版网络 ---
        mac_address=0x001122334455,
        host_ip_bytes=b"\xc0\xa8\x01\x64",  # 192.168.1.100
        primary_dns_bytes=b"\x01\x01\x01\x01",
        secondary_dns_bytes=b"\x00\x00\x00\x00",  # [New]
        dhcp_address_bytes=b"\xc0\xa8\x01\x01",
        # --- 指纹 ---
        host_name="Test-PC",
        host_os="Windows Test",
        os_info_bytes=bytes.fromhex("940000000600000000000000280a000002000000"),
        # --- 协议参数 ---
        adapter_num=b"\x01",
        ipdog=b"\x01",
        auth_version=b"\x2c\x00",
        control_check_status=b"\x20",
        keep_alive_version=b"\xdc\x02",
        ror_status=False,
        # --- 动态填充 (New Fields) ---
        padding_after_ipdog=b"\x00" * 4,
        padding_after_dhcp=b"\x00" * 8,
        padding_auth_ext=b"\x00" * 2,
        # --- P版参数 (New Fields) ---
        pppoe_flag=b"\x2a",
        keep_alive2_flag=b"\xdc",
    )
