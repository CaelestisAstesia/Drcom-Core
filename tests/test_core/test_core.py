# src/tests/test_core/test_core.py

from unittest.mock import MagicMock, patch

import pytest

from src.drcom_core.core import DrcomCore


# 这里，我们用它来创建一个干净的 DrcomCore 实例，并模拟掉它加载配置和初始化网络。
@pytest.fixture
def mocked_core():
    """
    提供一个 DrcomCore 实例，其 _load_config 和 _init_socket 已被模拟。
    """
    # 使用 patch.object 来模拟特定对象的方法
    with patch.object(DrcomCore, "_load_config", return_value=None):
        with patch.object(DrcomCore, "_init_socket", return_value=None):
            core = DrcomCore()
            # 我们可以手动设置一些测试所需的属性
            core.login_success = False
            yield core  # 'yield' 关键字将 core 实例提供给测试函数


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
