# tests/protocols/test_keep_alive.py

import struct
import time

import pytest

from drcom_core.protocols import constants, keep_alive

# --- Keep Alive 1 (FF 包) ---


def test_build_keep_alive1_packet(salt, password, auth_info):
    """
    测试 Keep Alive 1 (FF) 包的构建。
    """
    packet = keep_alive.build_keep_alive1_packet(
        salt=salt, password=password, auth_info=auth_info, include_trailing_zeros=True
    )

    assert len(packet) == 42  # 1(Code) + 16(MD5) + 3(Pad) + 16(Auth) + 2(Time) + 4(Pad)
    assert packet.startswith(constants.KEEP_ALIVE_CLIENT_CODE)  # b'\xff'

    # 验证 Auth Info 位置
    assert packet[20:36] == auth_info

    # 验证时间戳 (2字节，网络序)
    ts_bytes = packet[36:38]
    ts_val = struct.unpack("!H", ts_bytes)[0]
    assert abs(ts_val - (int(time.time()) % 0xFFFF)) <= 1  # 允许1秒误差

    # 验证结尾
    assert packet.endswith(constants.KEEP_ALIVE_EMPTY_BYTES_4)


def test_build_keep_alive1_packet_no_trailing_zeros(salt, password, auth_info):
    """
    测试不带末尾 4 字节 00 填充的构建。
    """
    packet = keep_alive.build_keep_alive1_packet(
        salt=salt,
        password=password,
        auth_info=auth_info,
        include_trailing_zeros=False,  # <-- 测试这个分支
    )
    assert len(packet) == 38
    assert not packet.endswith(constants.KEEP_ALIVE_EMPTY_BYTES_4)


@pytest.mark.parametrize(
    "salt, password, auth_info, description",
    [
        (b"", "pass", b"\xaa" * 16, "Salt 为空"),
        (b"\x12\x34", "pass", b"\xaa" * 16, "Salt 长度无效"),
        (b"\x12\x34\x56\x78", "", b"\xaa" * 16, "Password 为空"),
        (b"\x12\x34\x56\x78", "pass", b"", "Auth Info 为空"),
        (b"\x12\x34\x56\x78", "pass", b"\xaa" * 10, "Auth Info 长度无效"),
    ],
)
def test_build_keep_alive1_packet_invalid_inputs(
    salt, password, auth_info, description
):
    """
    测试 KA1 构建时的无效输入（应返回 None）。
    """
    packet = keep_alive.build_keep_alive1_packet(salt, password, auth_info)
    assert packet is None, description


@pytest.mark.parametrize(
    "response_data, expected_result",
    [
        (b"\x07\x00\x28\x00...", True),
        (b"\x04\x00...", False),
        (b"", False),
        (None, False),
    ],
)
def test_parse_keep_alive1_response(response_data, expected_result):
    """
    测试 KA1 响应的解析。
    """
    assert keep_alive.parse_keep_alive1_response(response_data) == expected_result


# --- Keep Alive 2 (07 包) ---


@pytest.mark.parametrize(
    "packet_type, is_first_packet, expected_version, expected_specific_part",
    [
        # 1. Type 1, 首次包
        (
            1,
            True,
            constants.KA2_FIRST_PACKET_VERSION,  # b'\x0f\x27'
            constants.KA2_TYPE1_SPECIFIC_PART,  # b'\x00' * 16
        ),
        # 2. Type 1, 非首次包
        (
            1,
            False,
            constants.KEEP_ALIVE_VERSION,  # b'\xdc\x02'
            constants.KA2_TYPE1_SPECIFIC_PART,  # b'\x00' * 16
        ),
        # 3. Type 3, 非首次包 (Type 3 永远不应该是首次包)
        (
            3,
            False,
            constants.KEEP_ALIVE_VERSION,  # b'\xdc\x02'
            constants.KA2_TYPE3_CRC_DEFAULT
            + b"\xc0\xa8\x01\x0a"
            + constants.KA2_TYPE3_PADDING_END,  # 4(CRC) + 4(IP) + 8(Pad)
        ),
    ],
)
def test_build_keep_alive2_packet(
    packet_type,
    is_first_packet,
    expected_version,
    expected_specific_part,
    host_ip_bytes,
    keep_alive_version,
):
    """
    测试 Keep Alive 2 (07) 包的构建。
    """
    packet_number = 42
    tail = b"\x11\x22\x33\x44"

    packet = keep_alive.build_keep_alive2_packet(
        packet_number=packet_number,
        tail=tail,
        packet_type=packet_type,
        host_ip_bytes=host_ip_bytes,
        keep_alive_version=keep_alive_version,
        is_first_packet=is_first_packet,
    )

    assert packet is not None
    assert len(packet) == 40

    # 验证 Code 和 Number
    assert packet.startswith(
        constants.MISC_CODE + bytes([packet_number])
    )  # b'\x07\x2a'

    # 验证固定头部
    assert packet[2:5] == constants.KA2_HEADER_PREFIX  # b'\x28\x00\x0b'

    # 验证 Type
    assert packet[5:6] == bytes([packet_type])

    # 验证 Version
    assert packet[6:8] == expected_version

    # 验证 Tail
    assert packet[16:20] == tail

    # 验证类型特定部分 (最后 16 字节)
    assert packet[24:] == expected_specific_part


@pytest.mark.parametrize(
    "packet_number, tail, packet_type, description",
    [
        (-1, b"\x00" * 4, 1, "Packet Number < 0"),
        (256, b"\x00" * 4, 1, "Packet Number > 255"),
        (42, b"\x00" * 3, 1, "Tail 长度无效"),
        (42, None, 1, "Tail 为 None"),
        (42, b"\x00" * 4, 2, "Packet Type 无效"),
    ],
)
def test_build_keep_alive2_packet_invalid_inputs(
    packet_number, tail, packet_type, description, host_ip_bytes, keep_alive_version
):
    """
    测试 KA2 构建时的无效输入（应返回 None）。
    """
    packet = keep_alive.build_keep_alive2_packet(
        packet_number=packet_number,
        tail=tail,
        packet_type=packet_type,
        host_ip_bytes=host_ip_bytes,
        keep_alive_version=keep_alive_version,
        is_first_packet=False,
    )
    assert packet is None, description


@pytest.mark.parametrize(
    "response_data, expected_tail",
    [
        # 1. 成功
        (
            b"\x07" + b"\x00" * 15 + b"\xde\xad\xbe\xef" + b"\x00" * 20,
            b"\xde\xad\xbe\xef",
        ),
        # 2. 失败 (Code 错误)
        (b"\x04" + b"\x00" * 15 + b"\xde\xad\xbe\xef" + b"\x00" * 20, None),
        # 3. 失败 (包太短)
        (b"\x07" + b"\x00" * 18, None),  # 总共 19 字节
        # 4. 失败 (空数据)
        (b"", None),
        # 5. 失败 (None)
        (None, None),
    ],
)
def test_parse_keep_alive2_response(response_data, expected_tail):
    """
    测试 KA2 响应的解析（提取 Tail）。
    """
    assert keep_alive.parse_keep_alive2_response(response_data) == expected_tail
