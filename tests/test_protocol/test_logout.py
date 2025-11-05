# tests/test_protocol/test_logout.py

import hashlib

import pytest

from src.drcom_protocol import constants, logout

# Fixtures


@pytest.fixture
def logout_config():
    """提供 build_logout_packet 所需的基本数据"""
    return {
        "username": "testuser",
        "password": "testpassword",
        "salt": b"\x55\x66\x77\x88",  # 登出时获取的新 salt
        "mac": 0x001122334455,
        "auth_info": b"\x44\x72\x63\x6f" + (b"\x00" * 12),  # 16字节 tail
        "control_check_status": b"\x20",
        "adapter_num": b"\x01",
    }


# 测试 build_logout_packet


def test_build_logout_packet_success(logout_config):
    """
    测试 build_logout_packet 是否能正确构建
    """
    # 1. 准备
    cfg = logout_config

    # 计算预期的 MD5A (基于新 salt)
    md5a_data = (
        constants.MD5_SALT_PREFIX + cfg["salt"] + cfg["password"].encode("utf-8")
    )
    expected_md5a = hashlib.md5(md5a_data).digest()

    # 计算预期的 MAC_XOR
    mac_xor_md5_part = expected_md5a[: constants.MAC_XOR_PADDING_LENGTH]
    md5_part_int = int.from_bytes(mac_xor_md5_part, byteorder="big")
    xor_result = md5_part_int ^ cfg["mac"]
    expected_xor_bytes = xor_result.to_bytes(
        constants.MAC_XOR_PADDING_LENGTH, byteorder="big", signed=False
    )

    # 2. 执行
    packet = logout.build_logout_packet(
        username=cfg["username"],
        password=cfg["password"],
        salt=cfg["salt"],
        mac=cfg["mac"],
        auth_info=cfg["auth_info"],
        control_check_status=cfg["control_check_status"],
        adapter_num=cfg["adapter_num"],
    )

    # 3. 断言
    assert packet is not None
    assert packet.startswith(constants.LOGOUT_REQ_CODE + constants.LOGOUT_TYPE)  # 0601
    assert packet[4:20] == expected_md5a
    assert packet[20:56] == cfg["username"].encode("utf-8").ljust(
        constants.USERNAME_PADDING_LENGTH, b"\x00"
    )
    assert packet[56:57] == cfg["control_check_status"]
    assert packet[57:58] == cfg["adapter_num"]
    assert packet[58:64] == expected_xor_bytes
    assert packet[64:80] == cfg["auth_info"]
    assert len(packet) == 80


def test_build_logout_packet_invalid_params(logout_config):
    """测试 build_logout_packet 的参数校验"""
    cfg = logout_config

    # Auth Info 长度错误
    with pytest.raises(ValueError, match="无效的 Auth Info"):
        logout.build_logout_packet(
            cfg["username"],
            cfg["password"],
            cfg["salt"],
            cfg["mac"],
            b"\x11\x22",  # Auth Info 错误
            cfg["control_check_status"],
            cfg["adapter_num"],
        )

    # Salt 长度错误
    with pytest.raises(ValueError, match="无效的 Salt"):
        logout.build_logout_packet(
            cfg["username"],
            cfg["password"],
            b"\x11",  # Salt 错误
            cfg["mac"],
            cfg["auth_info"],
            cfg["control_check_status"],
            cfg["adapter_num"],
        )


# 测试 parse_logout_response


def test_parse_logout_no_response():
    """测试 (最常见) 未收到响应的情况"""
    is_success, msg = logout.parse_logout_response(
        response_data=None, expected_server_ip="1.2.3.4", received_from_ip=None
    )
    assert is_success is True
    assert "未收到响应" in msg


def test_parse_logout_success_code():
    """测试收到 0x04 成功响应"""
    is_success, msg = logout.parse_logout_response(
        response_data=b"\x04\x00\x00...",  # Code 0x04
        expected_server_ip="1.2.3.4",
        received_from_ip="1.2.3.4",
    )
    assert is_success is True
    assert "确认登出成功" in msg


def test_parse_logout_wrong_ip():
    """测试收到其他 IP 的响应"""
    is_success, msg = logout.parse_logout_response(
        response_data=b"\x04\x00\x00...",
        expected_server_ip="1.2.3.4",
        received_from_ip="5.6.7.8",  # IP 不匹配
    )
    assert is_success is False
    assert "来源不匹配" in msg


def test_parse_logout_fail_code():
    """测试收到非 0x04 的异常响应"""
    is_success, msg = logout.parse_logout_response(
        response_data=b"\x05\x00\x00...",  # 异常 Code 0x05
        expected_server_ip="1.2.3.4",
        received_from_ip="1.2.3.4",
    )
    assert is_success is False
    assert "非预期" in msg
