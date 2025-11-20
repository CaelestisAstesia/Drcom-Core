# tests/test_core.py
from unittest.mock import patch

import pytest

from drcom_core import CoreStatus, DrcomCore


@pytest.fixture
def mock_deps():
    with (
        patch("drcom_core.core.NetworkClient") as nc,
        patch("drcom_core.core.D_Protocol") as proto,
    ):
        yield nc, proto


def test_core_login_delegation(valid_config, mock_deps):
    """测试 Core.login 只是委托给 Protocol"""
    _, mock_proto_cls = mock_deps
    # 让 protocol.login 返回 True
    mock_proto_cls.return_value.login.return_value = True

    core = DrcomCore(valid_config)
    assert core.login() is True
    assert core.state.status == CoreStatus.LOGGED_IN


def test_heartbeat_thread(valid_config, mock_deps):
    """测试心跳线程启动和停止"""
    core = DrcomCore(valid_config)
    core.state.status = CoreStatus.LOGGED_IN  # 只有登录后才能启动

    core.start_heartbeat()
    assert core._heartbeat_thread.is_alive()

    core.stop()
    assert not core._heartbeat_thread.is_alive()
    assert core.state.status == CoreStatus.OFFLINE
