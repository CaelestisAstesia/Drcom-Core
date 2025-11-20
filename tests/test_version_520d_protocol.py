# tests/test_version_520d_protocol.py
from unittest.mock import MagicMock

import pytest

from drcom_core.exceptions import AuthError, NetworkError
from drcom_core.protocols.version_520d import D_Protocol
from drcom_core.state import CoreStatus, DrcomState


@pytest.fixture
def protocol_instance(valid_config):
    state = DrcomState()
    net_client = MagicMock()
    return D_Protocol(valid_config, state, net_client)


def test_login_flow_success(protocol_instance):
    """测试完整的登录成功流程"""
    # Mock Challenge Response (Salt)
    salt = b"\x11\x22\x33\x44"
    challenge_resp = b"\x02\x01\x00\x00" + salt + b"\x00" * 20

    # Mock Login Response (Auth Info)
    auth_info = b"A" * 16
    login_resp = b"\x04" + b"\x00" * 22 + auth_info + b"\x00" * 10
    # Login response returns (data, (ip, port))
    login_net_ret = (login_resp, (protocol_instance.config.server_address, 61440))

    # 设置 Mock 行为: 1. Challenge, 2. Login
    protocol_instance.net_client.receive.side_effect = [
        (challenge_resp, ("ip", 0)),
        login_net_ret,
    ]

    success = protocol_instance.login()

    assert success is True
    assert protocol_instance.state.status == CoreStatus.LOGGED_IN
    assert protocol_instance.state.salt == salt
    assert protocol_instance.state.auth_info == auth_info


def test_login_fail_auth_error(protocol_instance):
    """测试登录失败 (密码错误)，应抛出 AuthError"""
    salt = b"\x11\x22\x33\x44"
    challenge_resp = b"\x02\x01\x00\x00" + salt + b"\x00" * 20

    # 构造 0x05 错误包
    fail_resp = b"\x05\x00\x00\x00\x03"  # 0x03 = Wrong Pass
    fail_net_ret = (fail_resp, (protocol_instance.config.server_address, 61440))

    protocol_instance.net_client.receive.side_effect = [
        (challenge_resp, ("ip", 0)),
        fail_net_ret,
    ]

    with pytest.raises(AuthError) as exc:
        protocol_instance.login()

    assert exc.value.error_code == 0x03

    # [修正] AuthError 是直接抛出的，不会进入异常捕获块设置 ERROR
    # 状态应停留在开始时设置的 CONNECTING
    assert protocol_instance.state.status == CoreStatus.CONNECTING


def test_challenge_retry(protocol_instance):
    """测试 Challenge 重试机制"""
    # 前几次抛出 NetworkError，最后一次成功
    salt = b"\x11\x22\x33\x44"
    success_resp = b"\x02\x01\x00\x00" + salt + b"\x00" * 20

    protocol_instance.net_client.receive.side_effect = [
        NetworkError("Timeout"),
        NetworkError("Timeout"),
        (success_resp, ("ip", 0)),
    ]

    # 我们只测试 _challenge 方法
    assert protocol_instance._challenge() is True
    assert protocol_instance.state.salt == salt
