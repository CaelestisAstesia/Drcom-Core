# tests/test_strategy_flow.py
"""
测试 D 版协议策略的流程控制 (Flow Control)。
覆盖 src/drcom_core/protocols/d_series/strategy.py
"""

from unittest.mock import MagicMock

import pytest

from drcom_core.exceptions import AuthError, AuthErrorCode
from drcom_core.protocols.d_series import constants, strategy
from drcom_core.state import CoreStatus, DrcomState


@pytest.fixture
def strategy_instance(valid_config):
    """返回一个配置好的 Strategy 实例，NetClient 已 Mock"""
    state = DrcomState()
    net = MagicMock()
    # 默认 receive 返回空数据防止 NoneType 错误，具体 case 具体 override
    net.receive.return_value = (b"", ("127.0.0.1", 0))

    proto = strategy.Protocol520D(valid_config, state, net)
    return proto, net, state


# --- Login Flow ---


def test_login_success_flow(strategy_instance):
    """测试完整的登录成功路径"""
    proto, net, state = strategy_instance

    # 1. 模拟 Challenge 响应 (0x02 + Padding(3) + Salt(4))
    # [Fix] Padding 修正为 3 字节，对齐 SALT_OFFSET_START = 4
    salt = b"\x11\x22\x33\x44"
    resp_chal = constants.Code.CHALLENGE_RESP + b"\x00\x00\x00" + salt + b"\x00" * 20

    # 2. 模拟 Login 响应 (0x04 + AuthInfo)
    auth_info = b"A" * 16
    resp_login = (
        bytes([constants.Code.LOGIN_RESP_SUCC])
        + b"\x00" * 22
        + auth_info
        + b"\x00" * 20
    )

    # 设置 Mock 序列
    # receive 返回 (data, address)
    net.receive.side_effect = [
        (resp_chal, ("server", 0)),
        (resp_login, (proto.config.server_address, 61440)),
    ]

    # 执行
    assert proto.login() is True

    # 验证状态
    assert state.status == CoreStatus.LOGGED_IN
    assert state.salt == salt
    assert state.auth_info == auth_info

    # 验证发送调用
    assert net.send.call_count == 2  # 1 Challenge + 1 Login


def test_login_server_busy_retry(strategy_instance):
    """测试服务器繁忙 (0x02) 时的重试逻辑"""
    proto, net, state = strategy_instance

    # 1. Challenge 成功 (3字节 Padding)
    resp_chal = (
        constants.Code.CHALLENGE_RESP + b"\x00\x00\x00" + b"\x00" * 4 + b"\x00" * 20
    )

    # 2. Login 第一次返回 Busy (0x02 in ErrorCode index)
    # Login Fail Code (0x05) ... ErrorCode (0x02)
    resp_busy = (
        bytes([constants.Code.LOGIN_RESP_FAIL])
        + b"\x00" * 3
        + bytes([AuthErrorCode.SERVER_BUSY])
        + b"\x00" * 10
    )

    # 3. Login 第二次成功
    resp_succ = (
        bytes([constants.Code.LOGIN_RESP_SUCC])
        + b"\x00" * 22
        + b"A" * 16
        + b"\x00" * 10
    )

    net.receive.side_effect = [
        (resp_chal, ("server", 0)),
        (resp_busy, (proto.config.server_address, 0)),
        (resp_succ, (proto.config.server_address, 0)),
    ]

    assert proto.login() is True
    # Login 包应该发了两次
    assert net.send.call_count == 3  # 1 Chal + 2 Login


def test_login_auth_fail(strategy_instance):
    """测试密码错误 (0x03) 直接抛出 AuthError"""
    proto, net, state = strategy_instance

    # [Fix] Padding 修正为 3 字节
    resp_chal = (
        constants.Code.CHALLENGE_RESP + b"\x00\x00\x00" + b"\x00" * 4 + b"\x00" * 20
    )
    resp_fail = (
        bytes([constants.Code.LOGIN_RESP_FAIL])
        + b"\x00" * 3
        + bytes([AuthErrorCode.WRONG_PASSWORD])
        + b"\x00" * 10
    )

    net.receive.side_effect = [
        (resp_chal, ("server", 0)),
        (resp_fail, (proto.config.server_address, 0)),
    ]

    with pytest.raises(AuthError) as exc:
        proto.login()

    # [Fix] AuthError 现在会优先使用 AuthErrorCode 的中文描述
    # 0x03 对应的描述是 "账号或密码错误"
    assert "账号或密码错误" in str(exc.value)


# --- Keep Alive Flow ---


def test_keep_alive_ka1_fail(strategy_instance):
    """测试 KA1 失败应返回 False (而不是抛出异常)"""
    proto, net, state = strategy_instance
    state.salt = b"\x00" * 4
    state.auth_info = b"\x00" * 16

    # 返回错误的 Code (例如 0x00)，导致 parse_keep_alive1_response 返回 False
    net.receive.return_value = (b"\x00" * 20, ("server", 0))

    # [Fix] keep_alive 内部捕获了 ProtocolError 并返回 False
    # 所以这里不应该用 pytest.raises
    assert proto.keep_alive() is False
    assert (
        state.status == CoreStatus.HEARTBEAT
    )  # 初始设为 Heartbeat，失败后由 loop 处理，或者在这里断言是否变为 ERROR?
    # 查看 strategy 源码，失败仅 log warning，并未修改 state 为 error (交给外层重试)
    # 所以这里只需要断言返回 False
