# tests/test_protocol/test_challenge.py

import random
import socket
import struct
import time
from unittest.mock import MagicMock  # 用于创建模拟对象

import pytest

# 导入需要测试的模块和常量
from src.drcom_protocol import challenge, constants

# 测试 receive_challenge_response


def test_receive_challenge_response_success():
    """测试成功接收并解析 Challenge 响应"""
    # 1. 准备一个模拟的 socket 对象
    mock_socket = MagicMock(spec=socket.socket)  # spec 确保 mock 对象有 socket 的方法

    # 2. 准备一个模拟的成功响应数据包
    #    结构: 02 + 01 + timestamp(2B) + salt(4B) + ...
    test_salt = b"\x11\x22\x33\x44"
    mock_response_data = (
        constants.CHALLENGE_RESP_CODE  # b'\x02'
        + b"\x01\xab\xcd"  # 其他字节
        + test_salt
        + b"\x00" * 20  # 任意后续字节
    )
    mock_server_address = ("1.2.3.4", 61440)

    # 3. 配置 mock_socket.recvfrom 的行为：
    #    当它被调用时，返回我们准备好的模拟数据和地址
    mock_socket.recvfrom.return_value = (mock_response_data, mock_server_address)

    # 4. 调用被测试函数
    salt, address = challenge.receive_challenge_response(mock_socket)

    # 5. 断言结果是否符合预期
    mock_socket.recvfrom.assert_called_once_with(
        1024
    )  # 验证 recvfrom 被调用且缓冲区大小正确
    assert salt == test_salt
    assert address == mock_server_address


def test_receive_challenge_response_wrong_code():
    """测试收到的响应包 Code 不正确"""
    mock_socket = MagicMock(spec=socket.socket)
    # 响应 Code 是 0x01 而不是预期的 0x02
    mock_response_data = (
        constants.CHALLENGE_REQ_CODE
        + b"\x01\xab\xcd"
        + b"\x11\x22\x33\x44"
        + b"\x00" * 20
    )
    mock_server_address = ("1.2.3.4", 61440)
    mock_socket.recvfrom.return_value = (mock_response_data, mock_server_address)

    salt, address = challenge.receive_challenge_response(mock_socket)

    assert salt is None  # 预期 salt 为 None
    assert address == mock_server_address  # 地址仍然会被返回


def test_receive_challenge_response_too_short():
    """测试收到的响应包长度不足以提取 Salt"""
    mock_socket = MagicMock(spec=socket.socket)
    # 响应包总长度只有 7 字节，小于 SALT_END_INDEX (8)
    mock_response_data = constants.CHALLENGE_RESP_CODE + b"\x01\xab\xcd\x11\x22\x33"
    mock_server_address = ("1.2.3.4", 61440)
    mock_socket.recvfrom.return_value = (mock_response_data, mock_server_address)

    salt, address = challenge.receive_challenge_response(mock_socket)

    assert salt is None
    assert address == mock_server_address


def test_receive_challenge_response_socket_timeout():
    """测试 socket.recvfrom 抛出超时异常"""
    mock_socket = MagicMock(spec=socket.socket)
    # 配置 recvfrom 在被调用时抛出 socket.timeout 异常
    mock_socket.recvfrom.side_effect = socket.timeout("timed out")

    # 使用 pytest.raises 来断言特定的异常是否被抛出
    with pytest.raises(socket.timeout):
        challenge.receive_challenge_response(mock_socket)


def test_receive_challenge_response_socket_error():
    """测试 socket.recvfrom 抛出其他 Socket 错误"""
    mock_socket = MagicMock(spec=socket.socket)
    mock_socket.recvfrom.side_effect = socket.error("Some socket error")

    with pytest.raises(socket.error):
        challenge.receive_challenge_response(mock_socket)


def test_send_challenge_request_packet_structure():
    """测试构建的 Challenge 请求包结构是否正确"""
    mock_socket = MagicMock(spec=socket.socket)  # 模拟 socket 用于函数调用
    server_addr = "1.2.3.4"
    port = 61440

    with pytest.MonkeyPatch.context() as mp:
        # 固定 time.time 和 random.randint 的返回值，得到固定的 random_bytes
        mp.setattr(time, "time", lambda: 1678886400.0)  # 固定时间戳
        mp.setattr(random, "randint", lambda a, b: 0xAA)  # 固定随机偏移
        expected_random_bytes = struct.pack("<H", int(1678886400.0 + 0xAA) % 0xFFFF)

        # 调用函数
        sent_packet = challenge.send_challenge_request(mock_socket, server_addr, port)

        # 断言包结构
        assert sent_packet is not None
        assert (
            len(sent_packet) == 2 + 2 + 1 + constants.CHALLENGE_REQ_PADDING_LENGTH
        )  # 总长度
        assert sent_packet.startswith(constants.CHALLENGE_REQ_CODE)  # 检查 Code
        assert (
            sent_packet[2:4] == expected_random_bytes
        )  # 检查随机部分 (需要 mock 才能精确)
        assert sent_packet[4:5] == constants.CHALLENGE_REQ_SUFFIX  # 检查后缀
        assert (
            sent_packet[5:] == b"\x00" * constants.CHALLENGE_REQ_PADDING_LENGTH
        )  # 检查填充

        # 验证 sendto 是否以正确的参数被调用
        mock_socket.sendto.assert_called_once_with(sent_packet, (server_addr, port))
