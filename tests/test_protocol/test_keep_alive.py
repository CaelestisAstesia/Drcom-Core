# tests/test_protocol/test_keep_alive.py

import hashlib
import socket
import struct
from unittest.mock import patch

import pytest

from src.drcom_protocol import constants, keep_alive

# Fixtures (准备测试数据)


@pytest.fixture
def base_config():
    """提供 Keep Alive 1 (FF) 所需的基本数据"""
    return {
        "salt": b"\x11\x22\x33\x44",
        "password": "testpassword",
        "auth_info": b"\xde\xad\xbe\xef" * 4,  # 16字节 tail
    }


@pytest.fixture
def ka2_config():
    """提供 Keep Alive 2 (07) 所需的基本数据"""
    return {
        "host_ip": "10.1.2.3",
        "tail": b"\xaa\xbb\xcc\xdd",
    }


# 测试 Keep Alive 1 (FF 包)


def test_build_keep_alive1_packet_success(base_config):
    """
    测试 build_keep_alive1_packet 能否成功构建一个完整的包
    """
    # 1. 准备
    salt = base_config["salt"]
    password = base_config["password"]
    auth_info = base_config["auth_info"]

    # 模拟固定的时间戳
    mock_time = 1678886400  # (int)
    test_timestamp = struct.pack("!H", mock_time % 0xFFFF)  # b'\x60\x00'

    # 计算预期的 MD5
    md5_data = constants.MD5_SALT_PREFIX + salt + password.encode("utf-8")
    expected_md5 = hashlib.md5(md5_data).digest()

    # 2. 执行
    with patch("time.time", return_value=mock_time):
        packet = keep_alive.build_keep_alive1_packet(
            salt, password, auth_info, include_trailing_zeros=True
        )

    # 3. 断言
    assert packet is not None
    assert packet.startswith(constants.KEEP_ALIVE_CLIENT_CODE)  # \xff
    assert packet[1:17] == expected_md5
    assert packet[17:20] == constants.KEEP_ALIVE_EMPTY_BYTES_3  # \x00*3
    assert packet[20:36] == auth_info  # 16字节 tail
    assert packet[36:38] == test_timestamp
    assert packet[38:42] == constants.KEEP_ALIVE_EMPTY_BYTES_4  # \x00*4
    assert len(packet) == 42  # 1+16+3+16+2+4


def test_build_keep_alive1_packet_no_trailing_zeros(base_config):
    """
    测试 build_keep_alive1_packet (不带末尾0)
    """
    with patch("time.time", return_value=0):  # 时间戳不重要
        packet = keep_alive.build_keep_alive1_packet(
            base_config["salt"],
            base_config["password"],
            base_config["auth_info"],
            include_trailing_zeros=False,  # <测试这个
        )
    assert packet is not None
    assert len(packet) == 38  # 42 - 4


def test_build_keep_alive1_invalid_params(base_config):
    """测试 build_keep_alive1_packet 的参数校验"""
    # 无 Salt
    assert (
        keep_alive.build_keep_alive1_packet(
            b"", base_config["password"], base_config["auth_info"]
        )
        is None
    )
    # 无 Password
    assert (
        keep_alive.build_keep_alive1_packet(
            base_config["salt"], "", base_config["auth_info"]
        )
        is None
    )
    # Auth Info 长度错误
    assert (
        keep_alive.build_keep_alive1_packet(
            base_config["salt"], base_config["password"], b"\x11\x22"
        )
        is None
    )


# 测试 Keep Alive 2 (07 包)


def test_build_keep_alive2_packet_type1_first(ka2_config):
    """
    测试 build_keep_alive2_packet (Type 1, 第一个包)
    """
    packet = keep_alive.build_keep_alive2_packet(
        packet_number=0,
        tail=b"\x00\x00\x00\x00",
        packet_type=1,
        host_ip=ka2_config["host_ip"],
        is_first_packet=True,  # <测试这个
    )

    assert packet is not None
    assert packet.startswith(b"\x07\x00")  # Code=07, Number=0
    assert packet[2:5] == constants.KA2_HEADER_PREFIX  # 28000b
    assert packet[5:6] == b"\x01"  # Type=1
    assert packet[6:8] == constants.KA2_FIRST_PACKET_VERSION  # 0f27
    assert packet[8:16] == constants.KA2_FIXED_PART1 + constants.KA2_FIXED_PART1_PADDING
    assert packet[16:20] == b"\x00\x00\x00\x00"  # 初始 Tail
    assert packet[20:24] == constants.KA2_TAIL_PADDING  # \x00*4
    assert packet[24:40] == constants.KA2_TYPE1_SPECIFIC_PART  # \x00*16
    assert len(packet) == 40


def test_build_keep_alive2_packet_type1_loop(ka2_config):
    """
    测试 build_keep_alive2_packet (Type 1, 循环中)
    """
    packet = keep_alive.build_keep_alive2_packet(
        packet_number=128,
        tail=ka2_config["tail"],
        packet_type=1,
        host_ip=ka2_config["host_ip"],
        is_first_packet=False,  # <测试这个
    )

    assert packet is not None
    assert packet.startswith(b"\x07\x80")  # Code=07, Number=128
    assert packet[6:8] == constants.KEEP_ALIVE_VERSION  # 默认版本 dc02
    assert packet[16:20] == ka2_config["tail"]  # 检查 Tail 是否正确传入
    assert packet[24:40] == constants.KA2_TYPE1_SPECIFIC_PART  # \x00*16
    assert len(packet) == 40


def test_build_keep_alive2_packet_type3(ka2_config):
    """
    测试 build_keep_alive2_packet (Type 3)
    """
    packet = keep_alive.build_keep_alive2_packet(
        packet_number=1,
        tail=ka2_config["tail"],
        packet_type=3,  # <测试这个
        host_ip=ka2_config["host_ip"],
        is_first_packet=False,
    )

    assert packet is not None
    assert packet.startswith(b"\x07\x01")  # Code=07, Number=1
    assert packet[5:6] == b"\x03"  # Type=3
    assert packet[16:20] == ka2_config["tail"]  # 检查 Tail

    # 检查 Type 3 特定部分
    expected_ip_bytes = socket.inet_aton(ka2_config["host_ip"])
    expected_specific_part = (
        constants.KA2_TYPE3_CRC_DEFAULT  # \x00*4
        + expected_ip_bytes  # 4 字节 IP
        + constants.KA2_TYPE3_PADDING_END  # \x00*8
    )
    assert packet[24:40] == expected_specific_part
    assert len(packet) == 40
