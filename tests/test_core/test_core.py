# tests/test_core/test_core.py

import socket
from unittest.mock import MagicMock, patch

import pytest

# 导入我们要测试的类
from src.drcom_core.core import DrcomCore

# 导入协议模块，以便在 mock 时引用它们
#


@pytest.fixture
def minimal_config():
    """
    提供一个最小化的配置字典，以满足 DrcomCore 新的 __init__ 要求。
    """
    return {
        "SERVER_IP": "1.2.3.4",
        "USERNAME": "testuser",
        "PASSWORD": "testpassword",
        "HOST_IP": "10.1.1.1",
        "MAC": "001122334455",
        "DRCOM_PORT": 61440,
        "BIND_IP": "0.0.0.0",
        # 其他配置（如 AUTH_VERSION 等）会使用 core.py 里的默认值
    }


@pytest.fixture
def mocked_core(minimal_config):
    """
    提供一个 DrcomCore 实例，其 __init__ 已被正确调用，
    但网络套接字已被模拟。
    """

    # 1. 我们 patch _init_socket，因为它会尝试绑定一个真实的网络端口
    with patch.object(DrcomCore, "_init_socket", return_value=None):
        # 2. 我们 *正常* 创建 DrcomCore 实例，并传入“依赖注入”的配置
        core = DrcomCore(config=minimal_config)

        # 3. 因为 _init_socket 被"跳过"了，
        #    self.core_socket 还是 None。
        #    我们必须手动给它分配一个 MagicMock 对象，
        #    以便后续的 .login() 等方法可以使用 .core_socket.sendto()。
        core.core_socket = MagicMock(spec=socket.socket)

        yield core  # 使用 yield 将 core 实例提供给测试函数


# 位于 src/tests/test_core/test_core.py


def test_login_success(mocked_core: DrcomCore):
    """
    测试 core.login() 成功时的情况。
    """
    # 模拟内部方法
    # 模拟 _perform_challenge 成功
    mocked_core._perform_challenge = MagicMock(return_value=True)

    # 【关键修正】
    # 我们需要模拟 _perform_login() 的“副作用”(Side Effect)
    # 即它在返回 True 之前，会设置 self.login_success = True
    def mock_login_side_effect(*args, **kwargs):
        mocked_core.login_success = True  # 模拟这个副作用
        mocked_core.auth_info = b"mocked_auth_info"  # 顺便模拟 auth_info
        return True  # 返回 True

    # 将 mock 的 side_effect 指向我们刚创建的辅助函数
    mocked_core._perform_login = MagicMock(side_effect=mock_login_side_effect)

    # 调用公开 API
    result = mocked_core.login()

    # 断言
    assert result is True
    assert mocked_core.login_success is True
    mocked_core._perform_challenge.assert_called_once()  # 确认 challenge 被调用了
    mocked_core._perform_login.assert_called_once()  # 确认 login 被调用了


def test_login_fail_at_challenge(mocked_core: DrcomCore):
    """
    测试 core.login() 在 challenge 阶段失败时的情况。
    """
    # 模拟 _perform_challenge 失败
    mocked_core._perform_challenge = MagicMock(return_value=False)
    mocked_core._perform_login = MagicMock()  # 创建一个 mock 以便检查

    result = mocked_core.login()

    assert result is False
    assert mocked_core.login_success is False
    mocked_core._perform_challenge.assert_called_once()  # challenge 被调用了
    mocked_core._perform_login.assert_not_called()  # 但 login *不应该* 被调用


def test_login_fail_at_login(mocked_core: DrcomCore):
    """
    测试 core.login() 在 login 阶段失败时的情况。
    """
    mocked_core._perform_challenge = MagicMock(return_value=True)
    mocked_core._perform_login = MagicMock(return_value=False)  # 模拟 login 失败

    result = mocked_core.login()

    assert result is False
    assert mocked_core.login_success is False
    mocked_core._perform_challenge.assert_called_once()  # challenge 被调用
    mocked_core._perform_login.assert_called_once()  # login 也被调用（但失败了）


def test_login_already_logined(mocked_core: DrcomCore):
    """
    测试在已登录状态下调用 core.login()。
    """
    mocked_core.login_success = True  # 假设已登录
    mocked_core._perform_challenge = MagicMock()
    mocked_core._perform_login = MagicMock()

    result = mocked_core.login()

    assert result is True  # 依然返回成功
    assert mocked_core.login_success is True
    mocked_core._perform_challenge.assert_not_called()  # 不应该再次调用 challenge
    mocked_core._perform_login.assert_not_called()  # 也不应该再次调用 login
