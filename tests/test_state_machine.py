# tests/test_state_machine.py
"""
测试 Dr.COM D 版协议的心跳状态机流转。
重点验证:
1. 初始化阶段 (Init): 3 步握手是否正确执行，_ka2_initialized 标志位是否翻转。
2. 循环阶段 (Loop): 2 步保活是否正确更新 Tail。
"""

from unittest.mock import MagicMock

import pytest

from drcom_core.protocols import constants
from drcom_core.protocols.version_520d import D_Protocol
from drcom_core.state import CoreStatus, DrcomState


@pytest.fixture
def proto(valid_config):
    """创建一个带有 Mock 网络客户端的协议实例"""
    state = DrcomState()
    # 预设登录成功所需的基础状态
    state.status = CoreStatus.LOGGED_IN
    state.salt = b"\x11\x22\x33\x44"
    state.auth_info = b"A" * 16

    net_client = MagicMock()
    return D_Protocol(valid_config, state, net_client)


def _make_ka_resp(tail: bytes = b"\x00" * 4) -> bytes:
    """辅助函数：构造一个带 Tail 的通用 Keep-Alive 响应包"""
    # 结构: Code(0x07) + Padding(15) + Tail(4) + Padding(...)
    # Tail 位于 index 16:20
    return constants.KEEP_ALIVE_RESP_CODE + b"\x00" * 15 + tail + b"\x00" * 10


def test_keep_alive_initialization_flow(proto):
    """
    测试 KA2 的初始化流程 (Init Sequence)。
    期望: 执行 KA1 -> Init Step 1 -> Init Step 2 -> Init Step 3
    结果: state._ka2_initialized 变为 True，Tail 更新为最后一次收到的值。
    """
    # 准备 Mock 响应数据
    # 1. KA1 响应 (0x07 开头即可)
    resp_ka1 = constants.KEEP_ALIVE_RESP_CODE + b"\x00" * 20

    # 2. KA2 Init Step 1 响应 (服务器只回 ACK，Tail 无意义)
    resp_step1 = _make_ka_resp(tail=b"\x00\x00\x00\x00")

    # 3. KA2 Init Step 2 响应 (服务器返回 Tail A)
    tail_a = b"\xaa\xaa\xaa\xaa"
    resp_step2 = _make_ka_resp(tail=tail_a)

    # 4. KA2 Init Step 3 响应 (服务器返回 Tail B)
    tail_b = b"\xbb\xbb\xbb\xbb"
    resp_step3 = _make_ka_resp(tail=tail_b)

    # 设置 Mock side_effect
    # receive 返回 (data, address)
    proto.net_client.receive.side_effect = [
        (resp_ka1, ("server", 0)),
        (resp_step1, ("server", 0)),
        (resp_step2, ("server", 0)),
        (resp_step3, ("server", 0)),
    ]

    # --- 执行 ---
    success = proto.keep_alive()

    # --- 验证 ---
    assert success is True
    # 状态标志位应翻转
    assert proto.state._ka2_initialized is True
    # 最终 Tail 应为 Tail B
    assert proto.state.keep_alive_tail == tail_b
    # 验证发包次数 (KA1 + 3个 KA2)
    assert proto.net_client.send.call_count == 4


def test_keep_alive_loop_flow(proto):
    """
    测试 KA2 的稳定循环流程 (Loop Sequence)。
    前提: state._ka2_initialized = True
    期望: 执行 KA1 -> Loop Step 1 -> Loop Step 2
    """
    # 手动设置已初始化状态
    proto.state._ka2_initialized = True
    proto.state.keep_alive_tail = b"\xbb\xbb\xbb\xbb"  # 上次留下的 Tail

    # 准备 Mock 响应
    resp_ka1 = constants.KEEP_ALIVE_RESP_CODE

    # Loop Step 1 响应 (返回 Tail C)
    tail_c = b"\xcc\xcc\xcc\xcc"
    resp_loop1 = _make_ka_resp(tail=tail_c)

    # Loop Step 2 响应 (返回 Tail D)
    tail_d = b"\xdd\xdd\xdd\xdd"
    resp_loop2 = _make_ka_resp(tail=tail_d)

    proto.net_client.receive.side_effect = [
        (resp_ka1, ("server", 0)),
        (resp_loop1, ("server", 0)),
        (resp_loop2, ("server", 0)),
    ]

    # --- 执行 ---
    success = proto.keep_alive()

    # --- 验证 ---
    assert success is True
    # 状态应保持为已初始化
    assert proto.state._ka2_initialized is True
    # Tail 更新为 Tail D
    assert proto.state.keep_alive_tail == tail_d
    # 验证发包次数 (KA1 + 2个 KA2)
    assert proto.net_client.send.call_count == 3
