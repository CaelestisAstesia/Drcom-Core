# tests/test_core.py
from unittest.mock import MagicMock, patch

import pytest

from drcom_core.core import CoreStatus, DrcomCore
from drcom_core.exceptions import AuthError


@pytest.fixture
def mock_protocol_class():
    """Mock D_Protocol 类"""
    with patch("drcom_core.core.D_Protocol") as mock:
        yield mock


@pytest.fixture
def core_instance(valid_config, mock_protocol_class):
    """返回一个注入了 Mock 协议的 Core 实例"""
    with patch("drcom_core.core.NetworkClient"):
        return DrcomCore(valid_config)


def test_login_success_flow(core_instance):
    """测试登录成功流程"""
    core_instance.protocol.login.return_value = True

    result = core_instance.login()

    assert result is True
    assert core_instance.state.status == CoreStatus.LOGGED_IN


def test_login_fail_auth_error(core_instance):
    """测试认证被拒绝 (如密码错误)"""
    # 模拟 protocol.login() 抛出 AuthError
    core_instance.protocol.login.side_effect = AuthError("密码错误", 0x03)

    # 修正：现在 core.login 会重新抛出 AuthError，所以必须捕获它
    with pytest.raises(AuthError):
        core_instance.login()

    assert core_instance.state.status == CoreStatus.OFFLINE
    assert "密码错误" in core_instance.state.last_error


def test_heartbeat_thread_lifecycle(core_instance):
    """测试心跳线程的启动与停止"""
    core_instance.state.status = CoreStatus.LOGGED_IN

    core_instance.start_heartbeat()
    assert core_instance._heartbeat_thread.is_alive()

    core_instance.stop()
    assert not core_instance._heartbeat_thread.is_alive()
    assert core_instance.state.status == CoreStatus.OFFLINE


def test_status_callback(valid_config):
    """测试状态回调是否被触发"""
    callback_mock = MagicMock()

    with (
        patch("drcom_core.core.NetworkClient"),
        patch("drcom_core.core.D_Protocol") as mock_proto,
    ):
        mock_proto.return_value.login.return_value = True

        core = DrcomCore(valid_config, status_callback=callback_mock)
        core.login()

        assert callback_mock.call_count >= 2
        assert callback_mock.call_args[0][0] == CoreStatus.LOGGED_IN
