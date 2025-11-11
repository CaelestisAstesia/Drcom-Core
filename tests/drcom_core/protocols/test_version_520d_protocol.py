# tests/drcom_core/protocols/test_version_520d_protocol.py
"""
对 D_Protocol (version_520d.py) 策略进行集成/流程测试。

这些测试不关心数据包的具体字节内容（这由 login/challenge 等的单元测试保证），
而是关心 D_Protocol 是否能正确编排流程（如重试、状态管理、错误处理）。

核心测试方法是模拟 (Mock) NetworkClient。
"""

import hashlib
import socket
from unittest.mock import MagicMock

import pytest

# 导入我们需要测试和模拟的类
from drcom_core.config import DrcomConfig, load_config_from_dict
from drcom_core.network import NetworkClient
from drcom_core.protocols import constants
from drcom_core.protocols.version_520d import D_Protocol
from drcom_core.state import DrcomState

# --- Fixtures (测试环境搭建) ---


@pytest.fixture
def minimal_config() -> DrcomConfig:
    """提供一个基础的、可用的配置对象"""
    return load_config_from_dict(
        {
            "USERNAME": "testuser",
            "PASSWORD": "testpass",
            "SERVER_IP": "1.2.3.4",
            "HOST_IP": "10.0.0.1",
            "MAC": "001122334455",
            "AUTH_VERSION": "2c00",
            "KEEP_ALIVE_VERSION": "dc02",
        }
    )


@pytest.fixture
def initial_state() -> DrcomState:
    """在每个测试用例运行前，提供一个干净的、初始化的状态对象"""
    return DrcomState()


@pytest.fixture
def mock_net_client(mocker, minimal_config) -> MagicMock:
    """
    (核心) 模拟 NetworkClient。
    我们使用 spec=True 来确保我们只模拟 NetworkClient 真实存在的方法。
    """
    # 创建一个 NetworkClient 的模拟对象
    mock = mocker.MagicMock(spec=NetworkClient)

    # D_Protocol 会访问 net_client.config.server_address 来验证响应包
    # 我们需要确保模拟对象上也有这个配置
    mock.config = minimal_config
    return mock


@pytest.fixture
def protocol_sut(minimal_config, initial_state, mock_net_client) -> D_Protocol:
    """
    (核心) 提供我们的“被测系统”(Subject Under Test, SUT)。
    它被注入了真实的 config、真实 state 和 *模拟的 net_client*。
    """
    return D_Protocol(minimal_config, initial_state, mock_net_client)


# --- 测试 Login (登录) 流程 ---


def test_login_happy_path(
    protocol_sut: D_Protocol, mock_net_client: MagicMock, initial_state: DrcomState
):
    """
    测试 D_Protocol.login() 在网络响应正常时的“快乐路径”
    """
    # 1. 准备 (Arrange)
    # 模拟 Challenge 响应 (b'\x02...')，包含 Salt b'TEST'
    challenge_response_pkt = (
        b"\x02\x01\x00\x00" + b"TEST" + b"\x00" * 12,
        ("1.2.3.4", 61440),  # 模拟来源地址
    )

    # 模拟 Login 成功响应 (b'\x04...')，包含 AuthInfo b'AUTHINFO12345678'
    login_response_pkt = (
        b"\x04" + b"\x00" * 22 + b"AUTHINFO12345678",
        ("1.2.3.4", 61440),
    )

    # 使用 .side_effect 让 mock 每次调用时按顺序返回不同的值
    mock_net_client.receive.side_effect = [challenge_response_pkt, login_response_pkt]

    # 2. 执行 (Act)
    success = protocol_sut.login()

    # 3. 断言 (Assert)
    assert success is True
    assert initial_state.login_success is True
    assert initial_state.salt == b"TEST"
    assert initial_state.auth_info == b"AUTHINFO12345678"

    # 验证网络调用次数
    assert mock_net_client.send.call_count == 2
    assert mock_net_client.receive.call_count == 2


def test_login_challenge_fails_timeout(
    protocol_sut: D_Protocol, mock_net_client: MagicMock, initial_state: DrcomState
):
    """
    测试 D_Protocol.login() 在 _challenge() 阶段因网络超时而失败
    """
    # 1. 准备 (Arrange)
    # 模拟 net_client.receive() 总是抛出 socket.timeout 异常
    mock_net_client.receive.side_effect = socket.timeout

    # 2. 执行 (Act)
    success = protocol_sut.login()

    # 3. 断言 (Assert)
    assert success is False
    assert initial_state.login_success is False
    assert initial_state.salt == b""  # Salt 未被设置

    # 验证 Challenge 的重试机制是否按预期工作
    assert mock_net_client.send.call_count == constants.MAX_RETRIES_CHALLENGE
    assert mock_net_client.receive.call_count == constants.MAX_RETRIES_CHALLENGE


def test_login_wrong_password(
    protocol_sut: D_Protocol, mock_net_client: MagicMock, initial_state: DrcomState
):
    """
    测试 D_Protocol.login() 在 _login() 阶段因密码错误 (0x05, 0x03) 而失败
    """
    # 1. 准备 (Arrange)
    challenge_response_pkt = (
        b"\x02\x01\x00\x00" + b"SALT" + b"\x00" * 12,
        ("1.2.3.4", 61440),
    )

    # 模拟 Login 失败响应 (b'\x05...')，错误码在索引 4 处，为 0x03 (密码错误)
    login_fail_pkt = (
        b"\x05\x00\x00\x00" + bytes([constants.ERROR_CODE_WRONG_PASS]) + b"\x00" * 30,
        ("1.2.3.4", 61440),
    )

    mock_net_client.receive.side_effect = [challenge_response_pkt, login_fail_pkt]

    # 2. 执行 (Act)
    success = protocol_sut.login()

    # 3. 断言 (Assert)
    assert success is False
    assert initial_state.login_success is False
    assert initial_state.salt == b"SALT"  # Challenge 成功了
    assert initial_state.auth_info == b""  # 但 Auth Info 未设置

    # 关键：验证它没有重试登录 (因为 0x03 是 NO_RETRY_ERROR_CODES)
    # 总共调用了 2 次 receive (1次Challenge, 1次Login)
    assert mock_net_client.send.call_count == 2
    assert mock_net_client.receive.call_count == 2


def test_login_retryable_error(
    protocol_sut: D_Protocol, mock_net_client: MagicMock, initial_state: DrcomState
):
    """
    测试 D_Protocol.login() 在 _login() 阶段遇到可重试错误 (如 0x02 服务器繁忙)
    """
    # 1. 准备 (Arrange)
    challenge_response_pkt = (
        b"\x02\x01\x00\x00" + b"SALT" + b"\x00" * 12,
        ("1.2.3.4", 61440),
    )
    # 模拟 Login 失败响应 (0x02 服务器繁忙)
    login_fail_pkt_busy = (
        b"\x05\x00\x00\x00" + bytes([constants.ERROR_CODE_SERVER_BUSY]) + b"\x00" * 30,
        ("1.2.3.4", 61440),
    )
    # 模拟 Login 成功响应
    login_success_pkt = (
        b"\x04" + b"\x00" * 22 + b"AUTHINFO12345678",
        ("1.2.3.4", 61440),
    )

    # 剧本：1. Challenge 成功 -> 2. Login 繁忙 -> 3. Login 成功
    mock_net_client.receive.side_effect = [
        challenge_response_pkt,
        login_fail_pkt_busy,
        login_success_pkt,
    ]

    # 2. 执行 (Act)
    success = protocol_sut.login()

    # 3. 断言 (Assert)
    assert success is True  # 最终成功了
    assert initial_state.login_success is True
    assert initial_state.auth_info == b"AUTHINFO12345678"

    # 验证网络调用：1次Challenge Send/Recv + 2次Login Send/Recv
    assert mock_net_client.send.call_count == 3
    assert mock_net_client.receive.call_count == 3


# --- 测试 Keep Alive (心跳) 流程 ---


@pytest.fixture
def logged_in_state(initial_state: DrcomState) -> DrcomState:
    """提供一个已登录成功、但KA2未初始化的状态"""
    initial_state.login_success = True
    initial_state.salt = b"SALT"
    initial_state.auth_info = b"AUTHINFO12345678"
    initial_state._ka2_initialized = False
    initial_state.keep_alive_serial_num = 0
    return initial_state


def test_keep_alive_initial_sequence(
    protocol_sut: D_Protocol, mock_net_client: MagicMock, logged_in_state: DrcomState
):
    """
    测试 D_Protocol.keep_alive() 首次运行时的三步握手初始化
    """
    # 1. 准备 (Arrange)
    # keep_alive() 首次运行会调用 4 次 receive:
    # 1. KA1 (FF) 响应
    # 2. KA2 Init Seq 1 响应
    # 3. KA2 Init Seq 2 响应 (会提取 Tail 1)
    # 4. KA2 Init Seq 3 响应 (会提取 Tail 2)
    mock_net_client.receive.side_effect = [
        (b"\x07\x00...", ("1.2.3.4", 61440)),  # KA1 Resp
        (b"\x07\x00...", ("1.2.3.4", 61440)),  # KA2 Seq 1 Resp
        (
            b"\x07" + b"\x00" * 15 + b"TAI1",
            ("1.2.3.4", 61440),
        ),  # KA2 Seq 2 Resp (Tail 在 [16:20])
        (b"\x07" + b"\x00" * 15 + b"TAI2", ("1.2.3.4", 61440)),  # KA2 Seq 3 Resp
    ]

    # 2. 执行 (Act)
    success = protocol_sut.keep_alive()

    # 3. 断言 (Assert)
    assert success is True
    assert logged_in_state._ka2_initialized is True  # 状态被标记为已初始化
    assert logged_in_state.keep_alive_tail == b"TAI2"  # 状态存储了最后的心跳尾巴
    assert logged_in_state.keep_alive_serial_num == 3  # 序列号增加了 3 次 (0, 1, 2)
    assert mock_net_client.send.call_count == 4  # 4次发送 (KA1, KA2-1, KA2-2, KA2-3)


def test_keep_alive_loop_sequence(
    protocol_sut: D_Protocol, mock_net_client: MagicMock, logged_in_state: DrcomState
):
    """
    测试 D_Protocol.keep_alive() 在 KA2 已初始化后的“循环序列”
    """
    # 1. 准备 (Arrange)
    # 关键：设置状态为“已初始化”
    logged_in_state._ka2_initialized = True
    logged_in_state.keep_alive_tail = b"PREV"  # 上一次的 Tail
    logged_in_state.keep_alive_serial_num = 3  # 上一次的序列号

    # KA 循环序列只调用 3 次 receive:
    # 1. KA1 (FF) 响应
    # 2. KA2 Loop Seq 1 响应 (会提取 Tail A)
    # 3. KA2 Loop Seq 2 响应 (会提取 Tail B)
    mock_net_client.receive.side_effect = [
        (b"\x07\x00...", ("1.2.3.4", 61440)),  # KA1 Resp
        (b"\x07" + b"\x00" * 15 + b"TAIA", ("1.2.3.4", 61440)),  # KA2 Loop 1 Resp
        (b"\x07" + b"\x00" * 15 + b"TAIB", ("1.2.3.4", 61440)),  # KA2 Loop 2 Resp
    ]

    # 2. 执行 (Act)
    success = protocol_sut.keep_alive()

    # 3. 断言 (Assert)
    assert success is True
    assert logged_in_state._ka2_initialized is True  # 保持 True
    assert logged_in_state.keep_alive_tail == b"TAIB"  # 状态更新为最后的 Tail
    assert logged_in_state.keep_alive_serial_num == 5  # 序列号增加了 2 次 (3, 4)
    assert mock_net_client.send.call_count == 3  # 3次发送 (KA1, KA2-Loop1, KA2-Loop2)


def test_keep_alive_ka1_fails(
    protocol_sut: D_Protocol, mock_net_client: MagicMock, logged_in_state: DrcomState
):
    """
    测试 D_Protocol.keep_alive() 在 KA1 (FF包) 阶段超时
    """
    # 1. 准备 (Arrange)
    mock_net_client.receive.side_effect = socket.timeout

    # 2. 执行 (Act)
    success = protocol_sut.keep_alive()

    # 3. 断言 (Assert)
    assert success is False
    assert mock_net_client.send.call_count == 1  # 只发送了 KA1
    assert mock_net_client.receive.call_count == 1


def test_keep_alive_ka2_fails(
    protocol_sut: D_Protocol, mock_net_client: MagicMock, logged_in_state: DrcomState
):
    """
    测试 D_Protocol.keep_alive() 在 KA2 序列中途超时
    """
    # 1. 准备 (Arrange)
    # 剧本：KA1 成功，KA2 Seq 1 失败
    mock_net_client.receive.side_effect = [
        (b"\x07\x00...", ("1.2.3.4", 61440)),  # KA1 Resp
        socket.timeout,  # KA2 Seq 1 Resp (Timeout)
    ]

    # 2. 执行 (Act)
    success = protocol_sut.keep_alive()

    # 3. 断言 (Assert)
    assert success is False
    assert mock_net_client.send.call_count == 2  # 1. KA1, 2. KA2 Seq 1
    assert mock_net_client.receive.call_count == 2


# --- 测试 Logout (登出) 流程 ---


def test_logout_normal_no_response(
    protocol_sut: D_Protocol,
    mock_net_client: MagicMock,
    logged_in_state: DrcomState,  # logged_in_state 会被修改
    mocker,
):
    """
    测试 D_Protocol.logout() 正常执行 (登出前 Challenge 成功，发送登出包后超时)
    """
    # 1. 准备 (Arrange)
    spy_send = mocker.spy(protocol_sut.net_client, "send")

    # 登出前，AuthInfo 是这个值
    auth_info_before_logout = logged_in_state.auth_info
    assert auth_info_before_logout == b"AUTHINFO12345678"

    mock_net_client.receive.side_effect = [
        (
            b"\x02\x01\x00\x00" + b"NEWS" + b"\x00" * 16,  # 使用 4 字节 Salt
            ("1.2.3.4", 61440),
        ),
        socket.timeout,
    ]

    # 2. 执行 (Act)
    protocol_sut.logout()

    # 3. 断言 (Assert)
    # 状态被重置
    assert logged_in_state.login_success is False
    assert logged_in_state.auth_info == b""
    assert logged_in_state.salt == b""

    # 检查网络调用
    assert spy_send.call_count == 2
    assert mock_net_client.receive.call_count == 2

    # (高级) 检查第二次（最后一次）send 调用
    sent_logout_packet = spy_send.call_args_list[1][0][0]

    # 重新计算理论上的 MD5 (使用 4 字节 Salt)
    expected_md5a = hashlib.md5(
        constants.MD5_SALT_PREFIX + b"NEWS" + b"testpass"
    ).digest()

    assert sent_logout_packet.startswith(constants.LOGOUT_REQ_CODE)
    assert expected_md5a in sent_logout_packet

    # 检查*登出前*的 AuthInfo 是否被正确打包
    assert auth_info_before_logout in sent_logout_packet


def test_logout_challenge_fails_fallback(
    protocol_sut: D_Protocol,
    mock_net_client: MagicMock,
    logged_in_state: DrcomState,
    mocker,
):
    """
    测试 D_Protocol.logout() 在登出 Challenge 失败时，回退使用旧 Salt
    """
    # 1. 准备 (Arrange)
    spy_send = mocker.spy(protocol_sut.net_client, "send")

    # 剧本： 1. Logout Challenge 超时 -> 2. Logout Packet (0x06) 响应超时
    mock_net_client.receive.side_effect = [
        socket.timeout,  # Logout Challenge Resp (Timeout)
        socket.timeout,  # Logout 0x06 packet Resp (Timeout)
    ]

    # 2. 执行 (Act)
    protocol_sut.logout()

    # 3. 断言 (Assert)
    # 状态被重置
    assert logged_in_state.login_success is False
    assert logged_in_state.auth_info == b""

    # 检查网络调用
    assert spy_send.call_count == 2
    assert mock_net_client.receive.call_count == 2

    # (高级) 检查第二次（最后一次）send 调用是否包含了用 *旧 Salt* 计算的 MD5
    sent_logout_packet = spy_send.call_args_list[1][0][0]

    # 重新计算一下理论上的 MD5 (使用 Fixture 里的 'OLDSALT')
    expected_md5a = hashlib.md5(
        constants.MD5_SALT_PREFIX + b"SALT" + b"testpass"
    ).digest()

    assert sent_logout_packet.startswith(constants.LOGOUT_REQ_CODE)
    assert expected_md5a in sent_logout_packet
    assert b"AUTHINFO12345678" in sent_logout_packet
