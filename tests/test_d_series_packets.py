# tests/test_d_series_packets.py
"""
测试 D 系列协议封包构建器 (Packets)。
[Fix] 适配了新的 build_login_packet 签名 (使用 Config 对象)。
"""

from drcom_core.config import DrcomConfig
from drcom_core.protocols.d_series import constants, packets

# =========================================================================
# Challenge (0x01/0x02)
# =========================================================================


def test_build_challenge_request():
    """验证 Challenge 请求包结构"""
    padding = b"\x00" * 15
    pkt = packets.build_challenge_request(padding)
    assert pkt.startswith(constants.Code.CHALLENGE_REQ)
    assert len(pkt) == 20
    assert pkt[4] == 0x09
    assert pkt[5:] == padding


def test_parse_challenge_response():
    """验证 Challenge 响应解析"""
    # Case 1: 正常包
    # 结构: Code(1 byte) + Padding(...) + Salt(4 bytes at index 4)
    salt = b"\x11\x22\x33\x44"
    data = constants.Code.CHALLENGE_RESP + b"\x00\x00\x00" + salt + b"\x00" * 20

    assert packets.parse_challenge_response(data) == salt

    # Case 2: 错误 Code
    assert packets.parse_challenge_response(b"\x03" + b"\x00" * 20) is None
    # Case 3: 长度不足
    assert packets.parse_challenge_response(b"\x02\x00") is None
    # Case 4: None
    assert packets.parse_challenge_response(None) is None


# =========================================================================
# Login (0x03/0x04)
# =========================================================================


def _create_dummy_config() -> DrcomConfig:
    """辅助函数：创建一个测试用的配置对象"""
    return DrcomConfig(
        username="test",
        password="123",
        server_address="127.0.0.1",
        server_port=61440,
        bind_ip="0.0.0.0",
        protocol_version="D",
        mac_address=0x001122334455,
        host_ip_bytes=b"\x01" * 4,
        primary_dns_bytes=b"\x02" * 4,
        dhcp_address_bytes=b"\x03" * 4,
        secondary_dns_bytes=b"\x00" * 4,
        host_name="host",
        host_os="os",
        os_info_bytes=b"\xff" * 20,
        control_check_status=b"\x20",
        adapter_num=b"\x01",
        ipdog=b"\x01",
        auth_version=b"\x2c\x00",
        padding_after_ipdog=b"\x00" * 4,
        padding_after_dhcp=b"\x00" * 8,
        padding_auth_ext=b"\x00" * 2,
        ror_status=False,
        pppoe_flag=b"\x2a",
        keep_alive2_flag=b"\xdc",
        keep_alive_version=b"\xdc\x02",
    )


def test_build_login_packet_structure():
    """测试登录包构建（使用 Config 对象）"""
    config = _create_dummy_config()
    salt = b"\x00" * 4

    # [Fix] 新的调用方式
    pkt = packets.build_login_packet(config, salt)

    assert pkt.startswith(constants.Code.LOGIN_REQ)
    # 检查是否包含了一些特征数据 (如 os_info_bytes 的 \xff)
    assert b"\xff" * 20 in pkt
    # 长度检查 (大概范围)
    assert len(pkt) > 300


def test_build_login_packet_randomness():
    """测试登录包的尾部随机填充"""
    config = _create_dummy_config()
    salt = b"\x00" * 4

    pkt1 = packets.build_login_packet(config, salt)
    pkt2 = packets.build_login_packet(config, salt)

    # 即使参数完全一样，因为有随机尾部填充，两个包也应该不同
    assert pkt1 != pkt2
    assert len(pkt1) == len(pkt2)


def test_parse_login_response():
    auth_info = b"A" * 16
    data_ok = (
        bytes([constants.Code.LOGIN_RESP_SUCC])
        + b"\x00" * 22
        + auth_info
        + b"\x00" * 10
    )
    success, info, err = packets.parse_login_response(data_ok)
    assert success is True
    assert info == auth_info

    data_fail = (
        bytes([constants.Code.LOGIN_RESP_FAIL]) + b"\x00" * 3 + b"\x03" + b"\x00"
    )
    success, info, err = packets.parse_login_response(data_fail)
    assert success is False
    assert err == 0x03


# =========================================================================
# Keep Alive
# =========================================================================


def test_keep_alive1_build_parse():
    pkt = packets.build_keep_alive1_packet(b"salt", "pass", b"token" * 3)
    assert pkt.startswith(constants.Code.KEEP_ALIVE_1)
    assert packets.parse_keep_alive1_response(constants.Code.MISC) is True


def test_keep_alive2_build():
    pkt_init = packets.build_keep_alive2_packet(
        packet_number=1,
        tail=b"\x00" * 4,
        packet_type=1,
        host_ip_bytes=b"\x00" * 4,
        keep_alive_version=b"\xdc\x02",
        is_first_packet=True,
    )
    # 检查是否包含 Init Magic
    assert pkt_init[6:8] == b"\x0f\x27"


def test_parse_keep_alive2_tail():
    tail = b"\xaa\xbb\xcc\xdd"
    data = constants.Code.MISC + b"\x00" * 15 + tail + b"\x00" * 10
    assert packets.parse_keep_alive2_response(data) == tail


# =========================================================================
# Logout
# =========================================================================


def test_logout_build():
    """测试登出包"""
    pkt = packets.build_logout_packet(
        "u", "p", b"salt", 0x0, b"token", b"\x20", b"\x01"
    )
    # Header: Code(1 byte) + Type(1 byte)
    assert pkt.startswith(constants.Code.LOGOUT_REQ)  # b'\x06'
    assert pkt[1] == 0x01  # Type
