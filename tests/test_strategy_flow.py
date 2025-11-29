# tests/test_strategy_flow.py
"""
测试 D 版协议策略的流程控制 (Flow Control) [Asyncio Edition]。
覆盖 src/drcom_core/protocols/d_series/strategy.py
"""

from unittest.mock import AsyncMock, MagicMock

import pytest

from drcom_core.exceptions import AuthError, AuthErrorCode
from drcom_core.protocols.d_series import constants, strategy
from drcom_core.state import CoreStatus, DrcomState

# 必须安装 pytest-asyncio
# pip install pytest-asyncio


@pytest.fixture
def strategy_instance(valid_config):
    """返回一个配置好的 Strategy 实例，NetClient 已 Mock 为异步"""
    state = DrcomState()
    net = MagicMock()

    # [Fix] 关键：网络发送和接收必须是 AsyncMock
    net.send = AsyncMock()
    net.receive = AsyncMock()

    # 默认 receive 返回空数据
    net.receive.return_value = (b"", ("127.0.0.1", 0))

    proto = strategy.Protocol520D(valid_config, state, net)
    return proto, net, state


# --- Login Flow ---


@pytest.mark.asyncio  # [Fix] 标记为异步测试
async def test_login_success_flow(strategy_instance):
    """测试完整的登录成功路径"""
    proto, net, state = strategy_instance

    # 1. 模拟 Challenge 响应
    salt = b"\x11\x22\x33\x44"
    resp_chal = constants.Code.CHALLENGE_RESP + b"\x00\x00\x00" + salt + b"\x00" * 20

    # 2. 模拟 Login 响应
    auth_info = b"A" * 16
    resp_login = (
        bytes([constants.Code.LOGIN_RESP_SUCC])
        + b"\x00" * 22
        + auth_info
        + b"\x00" * 20
    )

    # 设置 Mock 序列
    net.receive.side_effect = [
        (resp_chal, ("server", 0)),
        (resp_login, (proto.config.server_address, 61440)),
    ]

    # [Fix] 使用 await 调用
    assert await proto.login() is True

    # 验证状态
    assert state.status == CoreStatus.LOGGED_IN
    assert state.salt == salt
    assert state.auth_info == auth_info
    assert net.send.call_count == 2


@pytest.mark.asyncio
async def test_login_server_busy_retry(strategy_instance):
    """测试服务器繁忙 (0x02) 时的重试逻辑"""
    proto, net, state = strategy_instance

    resp_chal = (
        constants.Code.CHALLENGE_RESP + b"\x00\x00\x00" + b"\x00" * 4 + b"\x00" * 20
    )

    # Busy 响应
    resp_busy = (
        bytes([constants.Code.LOGIN_RESP_FAIL])
        + b"\x00" * 3
        + bytes([AuthErrorCode.SERVER_BUSY])
        + b"\x00" * 10
    )
    # Success 响应
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

    assert await proto.login() is True
    assert net.send.call_count == 3


@pytest.mark.asyncio
async def test_login_auth_fail(strategy_instance):
    """测试密码错误 (0x03) 直接抛出 AuthError"""
    proto, net, state = strategy_instance

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
        await proto.login()

    assert "账号或密码错误" in str(exc.value)


@pytest.mark.asyncio
async def test_keep_alive_ka1_fail(strategy_instance):
    """测试 KA1 失败应返回 False"""
    proto, net, state = strategy_instance
    state.salt = b"\x00" * 4
    state.auth_info = b"\x00" * 16

    net.receive.return_value = (b"\x00" * 20, ("server", 0))

    assert await proto.keep_alive() is False
