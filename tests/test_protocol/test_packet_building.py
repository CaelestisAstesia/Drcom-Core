# src/tests/test_protocol/test_packet_building.py

import hashlib
import socket
import struct
import time
from unittest.mock import patch

from src.drcom_protocol import constants, keep_alive, login

# 这些数据将用于生成我们的标准包，
TEST_USERNAME = "test_user"
TEST_PASSWORD = "test_password"
TEST_SALT = b"\x1a\x2b\x3c\x4d"
TEST_MAC_INT = 0xAABBCCDDEEFF
TEST_HOST_IP = "10.10.10.10"
TEST_HOST_NAME = "MyPC"
TEST_HOST_OS = "Windows 10"
TEST_PRIMARY_DNS = "114.114.114.114"
TEST_DHCP_SERVER = "10.10.10.1"


# 你可以根据你的抓包修改这些值
TEST_CONTROL_CHECK_STATUS = b"\x20"
TEST_ADAPTER_NUM = b"\x01"
TEST_IPDOG = b"\x01"
TEST_AUTH_VERSION = b"\x0a\x00"  # 比如吉大的是 0a00
TEST_ROR_STATUS = False


def test_build_login_packet_structure():
    """
    测试 build_login_packet 生成的数据包结构是否正确。
    我们不比较整个包（因为 hash 依赖库实现），
    而是逐字段(slice-based)断言，验证结构和非哈希字段。
    """

    # --- 1. 准备 (Arrange) ---
    # 准备好所有输入

    # --- 2. 执行 (Act) ---
    # 调用我们的函数
    packet = login.build_login_packet(
        username=TEST_USERNAME,
        password=TEST_PASSWORD,
        salt=TEST_SALT,
        mac_address=TEST_MAC_INT,
        host_ip=TEST_HOST_IP,
        host_name=TEST_HOST_NAME,
        host_os=TEST_HOST_OS,
        primary_dns=TEST_PRIMARY_DNS,
        dhcp_server=TEST_DHCP_SERVER,
        control_check_status=TEST_CONTROL_CHECK_STATUS,
        adapter_num=TEST_ADAPTER_NUM,
        ipdog=TEST_IPDOG,
        auth_version=TEST_AUTH_VERSION,
        ror_status=TEST_ROR_STATUS,
    )

    # --- 3. 断言 (Assert) ---
    # 逐个字段检查包的结构

    # 头部 (0-3)
    assert packet[0:2] == constants.LOGIN_REQ_CODE
    assert packet[2:3] == b"\x00"
    assert packet[3:4] == bytes(
        [len(TEST_USERNAME) + constants.LOGIN_PACKET_LENGTH_OFFSET]
    )

    # MD5_A (4-19)
    md5a_data = constants.MD5_SALT_PREFIX + TEST_SALT + TEST_PASSWORD.encode()
    expected_md5a = hashlib.md5(md5a_data).digest()
    assert packet[4:20] == expected_md5a

    # 用户名 (20-55)
    assert packet[20:56] == TEST_USERNAME.encode().ljust(
        constants.USERNAME_PADDING_LENGTH, b"\x00"
    )

    # Control/Adapter (56-57)
    assert packet[56:57] == TEST_CONTROL_CHECK_STATUS
    assert packet[57:58] == TEST_ADAPTER_NUM

    # MAC 异或 (58-63)
    # (这个断言可以验证我们的异或逻辑)
    md5_part_int = int.from_bytes(expected_md5a[:6], "big")
    xor_result = md5_part_int ^ TEST_MAC_INT
    expected_xor_bytes = xor_result.to_bytes(6, "big", signed=False)
    assert packet[58:64] == expected_xor_bytes

    # MD5_B (64-79)
    md5b_data = (
        constants.MD5B_SALT_PREFIX
        + TEST_PASSWORD.encode()
        + TEST_SALT
        + constants.MD5B_SALT_SUFFIX
    )
    expected_md5b = hashlib.md5(md5b_data).digest()
    assert packet[64:80] == expected_md5b

    # IP 地址 (80-96)
    assert packet[80:81] == b"\x01"  # 1 个 IP
    assert packet[81:85] == socket.inet_aton(TEST_HOST_IP)
    assert packet[85:97] == b"\x00" * constants.IP_ADDR_PADDING_LENGTH

    # ... 我们可以继续断言后面的 Checksum1, HostName, DNS 等字段 ...
    # Checksum1 (MD5C) (97-104)
    # IPDOG (105)
    assert packet[105:106] == TEST_IPDOG

    # Auth Version (310-311, 假设在 Host OS 之后)
    # 我们需要精确定位 Auth Version 的偏移量
    # 偏移量 = 110(HostName起) + 32(HostName) + 4(DNS) + 4(DHCP) + 4(SecDNS) + 8(WINS) + 20(OSInfo) + 32(HostOS) + 96(OSPad) = 310
    assert packet[310:312] == TEST_AUTH_VERSION

    # ... 更多字段 ...

    print("\n[DEBUG] Login Packet Build Test Passed (Partial assertions)")


def test_build_keep_alive1_packet_structure():
    """
    测试 build_keep_alive1_packet 的结构
    """

    # --- 1. 准备 (Arrange) ---
    TEST_AUTH_INFO = b"\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff\x00"

    # 我们需要模拟 time.time() 来获取一个固定的时间戳
    with patch.object(time, "time", return_value=1234567890.0):
        expected_timestamp = struct.pack("!H", int(1234567890.0) % 0xFFFF)

        # --- 2. 执行 (Act) ---
        packet = keep_alive.build_keep_alive1_packet(
            salt=TEST_SALT,
            password=TEST_PASSWORD,
            auth_info=TEST_AUTH_INFO,
            include_trailing_zeros=True,
        )

    # --- 3. 断言 (Assert) ---
    assert packet is not None
    assert packet.startswith(constants.KEEP_ALIVE_CLIENT_CODE)

    # 验证 MD5
    md5_data = constants.MD5_SALT_PREFIX + TEST_SALT + TEST_PASSWORD.encode()
    expected_md5 = hashlib.md5(md5_data).digest()
    assert packet[1:17] == expected_md5

    # 验证 00 填充
    assert packet[17:20] == constants.KEEP_ALIVE_EMPTY_BYTES_3

    # 验证 Auth Info (Tail)
    assert packet[20:36] == TEST_AUTH_INFO

    # 验证时间戳
    assert packet[36:38] == expected_timestamp

    # 验证末尾填充
    assert packet[38:42] == constants.KEEP_ALIVE_EMPTY_BYTES_4
