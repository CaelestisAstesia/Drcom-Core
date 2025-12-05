# Mirror tests for src/drcom_core/protocols/d_series/strategy.py
from unittest.mock import AsyncMock, MagicMock

import pytest

from drcom_core.exceptions import AuthError, AuthErrorCode
from drcom_core.protocols.d_series import constants, strategy
from drcom_core.state import CoreStatus, DrcomState


@pytest.fixture
def strategy_instance(valid_config):
    state = DrcomState()
    net = MagicMock()
    net.send = AsyncMock()
    net.receive = AsyncMock()
    net.receive.return_value = (b"", ("127.0.0.1", 0))
    proto = strategy.Protocol520D(valid_config, state, net)
    return proto, net, state


@pytest.mark.asyncio
async def test_login_success_flow(strategy_instance):
    proto, net, state = strategy_instance

    salt = b"\x11\x22\x33\x44"
    resp_chal = constants.Code.CHALLENGE_RESP + b"\x00\x00\x00" + salt + b"\x00" * 20

    auth_info = b"A" * 16
    resp_login = bytes([constants.Code.LOGIN_RESP_SUCC]) + b"\x00" * 22 + auth_info + b"\x00" * 20

    net.receive.side_effect = [
        (resp_chal, ("server", 0)),
        (resp_login, (proto.config.server_address, 61440)),
    ]

    assert await proto.login() is True
    assert state.status == CoreStatus.LOGGED_IN
    assert state.salt == salt
    assert state.auth_info == auth_info
    assert net.send.call_count == 2


@pytest.mark.asyncio
async def test_login_server_busy_retry(strategy_instance):
    proto, net, state = strategy_instance

    resp_chal = constants.Code.CHALLENGE_RESP + b"\x00\x00\x00" + b"\x00" * 4 + b"\x00" * 20

    resp_busy = bytes([constants.Code.LOGIN_RESP_FAIL]) + b"\x00" * 3 + bytes([AuthErrorCode.SERVER_BUSY]) + b"\x00" * 10
    resp_succ = bytes([constants.Code.LOGIN_RESP_SUCC]) + b"\x00" * 22 + b"A" * 16 + b"\x00" * 10

    net.receive.side_effect = [
        (resp_chal, ("server", 0)),
        (resp_busy, (proto.config.server_address, 0)),
        (resp_succ, (proto.config.server_address, 0)),
    ]

    assert await proto.login() is True
    assert net.send.call_count == 3


@pytest.mark.asyncio
async def test_login_auth_fail(strategy_instance):
    proto, net, state = strategy_instance

    resp_chal = constants.Code.CHALLENGE_RESP + b"\x00\x00\x00" + b"\x00" * 4 + b"\x00" * 20
    resp_fail = bytes([constants.Code.LOGIN_RESP_FAIL]) + b"\x00" * 3 + bytes([AuthErrorCode.WRONG_PASSWORD]) + b"\x00" * 10

    net.receive.side_effect = [
        (resp_chal, ("server", 0)),
        (resp_fail, (proto.config.server_address, 0)),
    ]

    with pytest.raises(AuthError) as exc:
        await proto.login()

    assert "账号或密码错误" in str(exc.value)


@pytest.mark.asyncio
async def test_keep_alive_ka1_fail(strategy_instance):
    proto, net, state = strategy_instance
    state.salt = b"\x00" * 4
    state.auth_info = b"\x00" * 16

    net.receive.return_value = (b"\x00" * 20, ("server", 0))

    assert await proto.keep_alive() is False


def _ka2_resp(tail: bytes) -> bytes:
    return constants.Code.MISC + b"\x00" * 15 + tail + b"\x00" * 10


@pytest.mark.asyncio
async def test_keep_alive_init_sequence(valid_config):
    state = DrcomState()
    state.salt = b"\x01\x02\x03\x04"
    state.auth_info = b"A" * 16

    net = MagicMock()
    net.send = AsyncMock()
    net.receive = AsyncMock()

    net.receive.side_effect = [
        (_ka2_resp(b"\xaa\xaa\xaa\xaa"), ("srv", 0)),
        (_ka2_resp(b"\xbb\xbb\xbb\xbb"), ("srv", 0)),
        (_ka2_resp(b"\xcc\xcc\xcc\xcc"), ("srv", 0)),
        (_ka2_resp(b"\xdd\xdd\xdd\xdd"), ("srv", 0)),
    ]

    proto = strategy.Protocol520D(valid_config, state, net)
    ok = await proto.keep_alive()

    assert ok is True
    assert state._ka2_initialized is True
    assert state.keep_alive_tail == b"\xdd\xdd\xdd\xdd"
    assert net.send.call_count == 4


@pytest.mark.asyncio
async def test_keep_alive_loop_sequence(valid_config):
    state = DrcomState()
    state.salt = b"\x00" * 4
    state.auth_info = b"T" * 16
    state._ka2_initialized = True

    net = MagicMock()
    net.send = AsyncMock()
    net.receive = AsyncMock()

    net.receive.side_effect = [
        (_ka2_resp(b"\x11\x22\x33\x44"), ("srv", 0)),
        (_ka2_resp(b"\x55\x66\x77\x88"), ("srv", 0)),
        (_ka2_resp(b"\x99\xaa\xbb\xcc"), ("srv", 0)),
    ]

    proto = strategy.Protocol520D(valid_config, state, net)
    ok = await proto.keep_alive()

    assert ok is True
    assert state._ka2_initialized is True
    assert state.keep_alive_tail == b"\x99\xaa\xbb\xcc"
    assert net.send.call_count == 3
