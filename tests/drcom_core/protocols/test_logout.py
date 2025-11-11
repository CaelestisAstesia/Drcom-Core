# tests/protocols/test_logout.py

import pytest

from drcom_core.protocols import constants, logout


def test_build_logout_packet(
    username, password, salt, mac_address, auth_info, control_check_status, adapter_num
):
    """
    测试登出包的构建 (Code 0x06)。
    """
    packet = logout.build_logout_packet(
        username=username,
        password=password,
        salt=salt,
        mac=mac_address,
        auth_info=auth_info,
        control_check_status=control_check_status,
        adapter_num=adapter_num,
    )

    # 验证 Code 和 Type
    assert packet.startswith(
        constants.LOGOUT_REQ_CODE + constants.LOGOUT_TYPE
    )  # b'\x06\x01'

    # 验证用户名位置
    assert packet[20:56].startswith(username.encode("utf-8", "ignore"))

    # 验证 Auth Info (Tail) 位置
    assert packet[64:80] == auth_info


@pytest.mark.parametrize(
    "invalid_param, value, expected_exception",
    [
        ("salt", b"\x12\x34", ValueError),  # Salt 长度错误
        ("salt", b"", ValueError),  # Salt 为空
        ("auth_info", b"\xaa" * 10, ValueError),  # Auth Info 长度错误
        ("auth_info", b"", ValueError),  # Auth Info 为空
    ],
)
def test_build_logout_packet_invalid_inputs(
    invalid_param,
    value,
    expected_exception,
    # 传入有效的 fixtures
    username,
    password,
    salt,
    mac_address,
    auth_info,
    control_check_status,
    adapter_num,
):
    """
    测试登出包构建时的无效参数是否能正确抛出异常。
    """
    params = {
        "username": username,
        "password": password,
        "salt": salt,
        "mac": mac_address,
        "auth_info": auth_info,
        "control_check_status": control_check_status,
        "adapter_num": adapter_num,
    }

    # 覆盖掉无效的参数
    params[invalid_param] = value

    # 断言预期的异常被抛出
    with pytest.raises(expected_exception):
        logout.build_logout_packet(**params)


@pytest.mark.parametrize(
    "response_data, expected_ip, received_ip, expected_result, description",
    [
        # 1. 成功 (无响应)
        (
            None,
            "1.1.1.1",
            None,
            (True, "未收到响应 (正常情况)"),
            "成功 (无响应)",
        ),
        # 2. 成功 (0x04)
        (
            b"\x04" + b"\x00" * 20,
            "1.1.1.1",
            "1.1.1.1",
            (True, "服务器确认登出成功"),
            "成功 (0x04)",
        ),
        # 3. 失败 (IP 不匹配)
        (
            b"\x04" + b"\x00" * 20,
            "1.1.1.1",
            "2.2.2.2",
            (False, "收到来源不匹配的登出响应 (来自: 2.2.2.2)"),
            "失败 (IP 不匹配)",
        ),
        # 4. 失败 (非预期 Code)
        (
            b"\x05" + b"\x00" * 20,
            "1.1.1.1",
            "1.1.1.1",
            (False, "收到来自服务器的非预期登出响应代码: 0x5"),
            "失败 (非预期 Code)",
        ),
        # 5. 失败 (收到响应但 IP 丢失)
        (
            b"\x04" + b"\x00" * 20,
            "1.1.1.1",
            None,
            (False, "收到登出响应但缺少来源 IP"),
            "失败 (IP 丢失)",
        ),
    ],
)
def test_parse_logout_response(
    response_data, expected_ip, received_ip, expected_result, description
):
    """
    测试登出响应的解析。
    """
    result = logout.parse_logout_response(response_data, expected_ip, received_ip)
    assert result == expected_result, description
