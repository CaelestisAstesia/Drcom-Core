# tests/protocols/test_challenge.py

import pytest

from drcom_core.protocols import challenge, constants


def test_build_challenge_request():
    """
    测试 Challenge 请求包的构建 (Code 0x01)。
    """
    packet = challenge.build_challenge_request()

    # 1. 验证总长度
    assert len(packet) == 20

    # 2. 验证固定头部
    assert packet.startswith(constants.CHALLENGE_REQ_CODE)  # b'\x01\x02'

    # 3. 验证固定尾部
    assert packet.endswith(
        constants.CHALLENGE_REQ_SUFFIX
        + (b"\x00" * constants.CHALLENGE_REQ_PADDING_LENGTH)
    )  # b'\x09' + b'\x00' * 15

    # 4. 验证随机数部分 (偏移量 2-3)
    assert len(packet[2:4]) == 2
    # (我们不能断言它的具体值，只能断言它的位置和长度)


@pytest.mark.parametrize(
    "response_data, expected_salt, description",
    [
        # 1. 成功案例：一个最小有效包
        (
            b"\x02\x01\xab\xcd\x1a\x2b\x3c\x4d" + b"\x00" * 12,
            b"\x1a\x2b\x3c\x4d",
            "成功：最小有效响应包",
        ),
        # 2. 失败：Code 错误 (收到 0x03)
        (
            b"\x03\x01\xab\xcd\x1a\x2b\x3c\x4d" + b"\x00" * 12,
            None,
            "失败：Code 错误",
        ),
        # 3. 失败：包太短 (无法提取 Salt)
        (
            b"\x02\x01\xab\xcd\x1a\x2b\x3c",  # 只有 7 字节
            None,
            "失败：包太短",
        ),
        # 4. 失败：空数据
        (
            b"",
            None,
            "失败：空数据",
        ),
        # 5. 失败：None
        (
            None,
            None,
            "失败：None 输入",
        ),
    ],
)
def test_parse_challenge_response(response_data, expected_salt, description):
    """
    测试 Challenge 响应包的解析 (Code 0x02)。
    """
    assert challenge.parse_challenge_response(response_data) == expected_salt, (
        description
    )
