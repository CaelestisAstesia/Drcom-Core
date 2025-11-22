# tests/test_error_mapping.py
"""
测试登录失败时的错误码解析与中文映射。
确保每个 AuthErrorCode 都能向用户展示正确的中文提示。
"""

import pytest

from drcom_core.exceptions import AuthErrorCode
from drcom_core.protocols import constants, login

# 构造测试数据集: (枚举成员, 期望包含的中文片段)
TEST_CASES = [
    (AuthErrorCode.IN_USE, "账号在线"),
    (AuthErrorCode.WRONG_PASSWORD, "密码错误"),
    (AuthErrorCode.INSUFFICIENT_FUNDS, "余额不足"),
    (AuthErrorCode.FROZEN, "冻结"),
    (AuthErrorCode.WRONG_MAC, "MAC地址不匹配"),
    (AuthErrorCode.WRONG_IP, "IP地址不匹配"),
    (AuthErrorCode.WRONG_VERSION, "版本不匹配"),
    (AuthErrorCode.SERVER_BUSY, "服务器繁忙"),
    # 测试一个未知的错误码
    (99, "N/A"),  # 假设 99 未定义，应显示 Code: 0x63
]


@pytest.mark.parametrize("error_code_val, expected_msg", TEST_CASES)
def test_login_error_message_mapping(error_code_val, expected_msg):
    """
    参数化测试: 构造 0x05 失败包，验证 parse_login_response 返回的消息。
    """

    code_int = (
        error_code_val.value if hasattr(error_code_val, "value") else error_code_val
    )

    resp = (
        bytes([constants.LOGIN_RESP_FAIL_CODE])
        + b"\x00" * 3
        + bytes([code_int])
        + b"\x00" * 10
    )

    success, _, received_code, msg = login.parse_login_response(
        resp, "1.1.1.1", "1.1.1.1"
    )

    assert success is False
    assert received_code == code_int

    # 验证消息中包含预期的中文关键词
    # 对于未知错误码 99，msg 可能不包含中文描述，只包含 Code
    if isinstance(error_code_val, AuthErrorCode):
        assert expected_msg in msg, f"错误码 {error_code_val} 的中文映射不正确"
