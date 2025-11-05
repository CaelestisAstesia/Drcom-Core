# src/tests/test_protocol/test_login.py

from src.drcom_protocol import constants, login

# --- 测试 parse_login_response ---


def test_parse_login_response_success():
    """
    测试解析“登录成功” (0x04) 的响应包
    """
    # 这是一个模拟的登录成功包 (Code 0x04)
    # 我们需要的“tail”在第 23 到 39 字节
    mock_auth_info = b"\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff\x00"
    mock_response_data = (
        b"\x04"  # 成功代码
        + b"\x00" * 22  # 填充
        + mock_auth_info
        + b"\x00" * 10  # 剩余部分
    )
    expected_server_ip = "1.2.3.4"

    # 调用被测试函数
    is_success, auth_info, err_code, msg = login.parse_login_response(
        mock_response_data, expected_server_ip, "1.2.3.4"
    )

    # 断言 (Assert)：检查结果是否和预期一致
    assert is_success is True
    assert auth_info == mock_auth_info
    assert err_code is None
    assert "登录成功" in msg


def test_parse_login_response_fail_wrong_pass():
    """
    测试解析“登录失败 - 密码错误” (0x05, 错误码 0x03) 的响应包
    """
    # 这是一个模拟的登录失败包 (Code 0x05, 错误码 0x03)
    mock_response_data = (
        b"\x05"  # 失败代码
        + b"\x00\x00\x00"
        + b"\x03"  # 错误码在第4字节
        + b"\x00" * 10
    )
    expected_server_ip = "1.2.3.4"

    is_success, auth_info, err_code, msg = login.parse_login_response(
        mock_response_data, expected_server_ip, "1.2.3.4"
    )

    assert is_success is False
    assert auth_info is None
    assert err_code == constants.ERROR_CODE_WRONG_PASS  # 检查是否为密码错误
    assert "账号或密码错误" in msg


def test_parse_login_response_fail_in_use():
    """
    测试解析“登录失败 - 账号已在用” (0x05, 错误码 0x01)
    """
    mock_response_data = (
        b"\x05" + b"\x00\x00\x00" + b"\x01"  # 错误码 0x01
    )
    expected_server_ip = "1.2.3.4"

    is_success, auth_info, err_code, msg = login.parse_login_response(
        mock_response_data, expected_server_ip, "1.2.3.4"
    )

    assert is_success is False
    assert auth_info is None
    assert err_code == constants.ERROR_CODE_IN_USE
    assert "正在使用中" in msg


def test_parse_login_response_wrong_source_ip():
    """
    测试响应包来自错误的 IP 地址
    """
    mock_response_data = b"\x04" + b"\x00" * 50
    expected_server_ip = "1.2.3.4"
    wrong_server_ip = "5.6.7.8"

    is_success, auth_info, err_code, msg = login.parse_login_response(
        mock_response_data, expected_server_ip, wrong_server_ip
    )

    assert is_success is False
    assert "来源不匹配" in msg
