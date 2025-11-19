# tests/test_protocol_login.py
from drcom_core.protocols import constants, login


def test_login_packet_structure(valid_config):
    """测试登录包的基本结构和长度"""
    # 获取一个固定的 salt
    salt = b"\x11\x22\x33\x44"

    packet = login.build_login_packet(
        username=valid_config.username,
        password=valid_config.password,
        salt=salt,
        mac_address=valid_config.mac_address,
        host_ip_bytes=valid_config.host_ip_bytes,
        primary_dns_bytes=valid_config.primary_dns_bytes,
        dhcp_server_bytes=valid_config.dhcp_address_bytes,
        host_name=valid_config.host_name,
        host_os=valid_config.host_os,
        adapter_num=valid_config.adapter_num,
        ipdog=valid_config.ipdog,
        auth_version=valid_config.auth_version,
        control_check_status=valid_config.control_check_status,
        magic_tail=False,  # 先测试固定尾部
    )

    # 1. 验证包头 (Code 03 01)
    assert packet.startswith(constants.LOGIN_REQ_CODE)

    # 2. 验证尾部 (固定尾部 e9 13)
    assert packet.endswith(constants.LOGIN_PACKET_ENDING)


def test_magic_tail(valid_config):
    """测试 Magic Tail 是否生成随机尾部"""
    salt = b"\x11\x22\x33\x44"

    # 构建两个启用 Magic Tail 的包
    packet1 = login.build_login_packet(
        username=valid_config.username,
        password=valid_config.password,
        salt=salt,
        mac_address=valid_config.mac_address,
        host_ip_bytes=valid_config.host_ip_bytes,
        primary_dns_bytes=valid_config.primary_dns_bytes,
        dhcp_server_bytes=valid_config.dhcp_address_bytes,
        host_name=valid_config.host_name,
        host_os=valid_config.host_os,
        adapter_num=valid_config.adapter_num,
        ipdog=valid_config.ipdog,
        auth_version=valid_config.auth_version,
        control_check_status=valid_config.control_check_status,
        magic_tail=True,  # 启用！
    )

    packet2 = login.build_login_packet(
        username=valid_config.username,
        password=valid_config.password,
        salt=salt,
        mac_address=valid_config.mac_address,
        host_ip_bytes=valid_config.host_ip_bytes,
        primary_dns_bytes=valid_config.primary_dns_bytes,
        dhcp_server_bytes=valid_config.dhcp_address_bytes,
        host_name=valid_config.host_name,
        host_os=valid_config.host_os,
        adapter_num=valid_config.adapter_num,
        ipdog=valid_config.ipdog,
        auth_version=valid_config.auth_version,
        control_check_status=valid_config.control_check_status,
        magic_tail=True,  # 启用！
    )

    # 验证包长度应该相同
    assert len(packet1) == len(packet2)

    # 验证包内容（尾部）应该不同
    # 注意：极小概率下随机数可能碰撞，但在测试中通常忽略不计
    assert packet1 != packet2

    # 验证都不是固定的 e9 13
    assert not packet1.endswith(constants.LOGIN_PACKET_ENDING)
