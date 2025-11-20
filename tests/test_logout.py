# tests/test_logout.py
import pytest

from drcom_core.protocols import constants, logout


def test_build_logout_packet(valid_config):
    """测试构建登出包"""
    salt = b"\x11\x22\x33\x44"
    auth_info = b"A" * 16

    pkt = logout.build_logout_packet(
        username=valid_config.username,
        password=valid_config.password,
        salt=salt,
        mac=valid_config.mac_address,
        auth_info=auth_info,
        control_check_status=valid_config.control_check_status,
        adapter_num=valid_config.adapter_num,
    )
    # 简单验证包头 (0x06)
    assert pkt.startswith(constants.LOGOUT_REQ_CODE)


@pytest.mark.parametrize(
    "response_data, expected_ip, received_ip, expected_result_bool, expected_msg_part",
    [
        # 1. 成功 (无响应, Timeout)
        (None, "1.1.1.1", None, True, "未收到响应"),
        # 2. 成功 (0x04)
        (b"\x04", "1.1.1.1", "1.1.1.1", True, "0x04"),
        # 3. 失败 (IP 不匹配)
        # [修正] 匹配实际的错误消息格式 "来源 IP 不匹配"
        (b"\x04", "1.1.1.1", "2.2.2.2", False, "来源 IP 不匹配"),
        # 4. 失败 (非预期 Code)
        (b"\x05", "1.1.1.1", "1.1.1.1", False, "非预期登出响应代码"),
    ],
)
def test_parse_logout_response(
    response_data, expected_ip, received_ip, expected_result_bool, expected_msg_part
):
    """测试登出响应解析"""
    success, msg = logout.parse_logout_response(response_data, expected_ip, received_ip)
    assert success is expected_result_bool
    assert expected_msg_part in msg
