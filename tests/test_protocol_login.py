# tests/test_protocol_login.py
from drcom_core.protocols import constants, login


def test_build_login_packet_structure(valid_config):
    """测试登录包构建成功"""
    salt = b"\x11\x22\x33\x44"

    pkt = login.build_login_packet(
        username=valid_config.username,
        password=valid_config.password,
        salt=salt,
        mac_address=valid_config.mac_address,
        host_ip_bytes=valid_config.host_ip_bytes,
        primary_dns_bytes=valid_config.primary_dns_bytes,
        dhcp_server_bytes=valid_config.dhcp_address_bytes,
        host_name=valid_config.host_name,
        host_os=valid_config.host_os,
        os_info_bytes=valid_config.os_info_bytes,  # [新参数]
        adapter_num=valid_config.adapter_num,
        ipdog=valid_config.ipdog,
        auth_version=valid_config.auth_version,
        control_check_status=valid_config.control_check_status,
        ror_status=valid_config.ror_status,
    )

    # 验证包头
    assert pkt.startswith(constants.LOGIN_REQ_CODE)
    # 验证长度 (简单检查是否包含填充)
    assert len(pkt) > 300
    # 验证 OS Info 是否正确插入
    assert valid_config.os_info_bytes in pkt


def test_magic_tail_randomness(valid_config):
    """验证 Magic Tail 是随机的 (反指纹)"""
    salt = b"\x00\x00\x00\x00"
    # 固定所有参数
    args = {
        "username": valid_config.username,
        "password": valid_config.password,
        "salt": salt,
        "mac_address": valid_config.mac_address,
        "host_ip_bytes": valid_config.host_ip_bytes,
        "primary_dns_bytes": valid_config.primary_dns_bytes,
        "dhcp_server_bytes": valid_config.dhcp_address_bytes,
        "host_name": valid_config.host_name,
        "host_os": valid_config.host_os,
        "os_info_bytes": valid_config.os_info_bytes,
        "adapter_num": valid_config.adapter_num,
        "ipdog": valid_config.ipdog,
        "auth_version": valid_config.auth_version,
        "control_check_status": valid_config.control_check_status,
        "ror_status": False,
    }

    pkt1 = login.build_login_packet(**args)
    pkt2 = login.build_login_packet(**args)

    # 1. 两个包必须不同 (因为尾部随机)
    assert pkt1 != pkt2
    # 2. 包长度必须相同
    assert len(pkt1) == len(pkt2)
    # 3. 除去最后2字节，前面的内容必须相同
    assert pkt1[:-2] == pkt2[:-2]


def test_parse_login_success():
    """测试解析成功响应 (0x04)"""
    # 构造一个合法的 0x04 包, Auth Info 位于 23:39 (16字节)
    mock_auth_info = b"A" * 16
    resp = (
        bytes([constants.LOGIN_RESP_SUCCESS_CODE])  # 0x04
        + b"\x00" * 22
        + mock_auth_info
        + b"\x00" * 10
    )

    success, auth_info, err, msg = login.parse_login_response(
        resp, "1.1.1.1", "1.1.1.1"
    )
    assert success is True
    assert auth_info == mock_auth_info
    assert "成功" in msg
