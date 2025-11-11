# tests/protocols/test_login.py

import pytest

from drcom_core.protocols import constants, login

try:
    print("\n[DEBUG] Pytest 正在从以下路径导入 'login' 模块:")
    print(f"    {login.__file__}\n")
except Exception as e:
    print(f"\n[DEBUG] 无法打印 login.__file__: {e}\n")
# --- 测试内部辅助函数 _calculate_checksum ---


def test_calculate_checksum_deterministic():
    """
    测试 Checksum2 算法是否是确定性的。
    我们使用一组已知数据和后缀，验证其是否能生成一个固定的 checksum。
    """
    # 1. 准备输入数据
    # 模拟的包数据（任意选择，但必须固定）
    mock_packet_data = (
        b"\x03\x01\x00\x28" + b"\xab" * 16 + b"testuser".ljust(36, b"\x00")
    )
    # 模拟的 MAC
    mac_bytes = b"\x11\x22\x33\x44\x55\x66"

    # 完整的 Checksum 输入
    checksum_input = mock_packet_data + constants.CHECKSUM2_SUFFIX + mac_bytes

    # 2. 执行算法
    checksum_result = login._calculate_checksum(checksum_input)

    # 3. 验证
    # (这个期望值是通过在已知代码上运行一次 `_calculate_checksum` 得出的)
    # 它的作用是确保算法逻辑在未来不会被意外更改。
    expected_checksum_bytes = b"\x60\x79\xdb\x20"

    assert checksum_result == expected_checksum_bytes
    assert len(checksum_result) == 4


# --- 测试 build_login_packet ---


def test_build_login_packet_happy_path(
    username,
    password,
    salt,
    mac_address,
    mac_bytes,
    host_ip_bytes,
    host_name,
    host_os,
    primary_dns_bytes,
    dhcp_server_bytes,
    control_check_status,
    adapter_num,
    ipdog,
    auth_version,
):
    """
    测试登录包构建（成功路径，非 ROR）。
    """
    packet = login.build_login_packet(
        username=username,
        password=password,
        salt=salt,
        mac_address=mac_address,
        host_ip_bytes=host_ip_bytes,
        host_name=host_name,
        host_os=host_os,
        primary_dns_bytes=primary_dns_bytes,
        dhcp_server_bytes=dhcp_server_bytes,
        control_check_status=control_check_status,
        adapter_num=adapter_num,
        ipdog=ipdog,
        auth_version=auth_version,
        ror_status=False,
    )

    # 验证包头
    assert packet.startswith(constants.LOGIN_REQ_CODE)  # b'\x03\x01'

    # 验证包长度 (8 (username) + 20) = 28 (0x1c)
    expected_len_byte = bytes([len(username) + constants.LOGIN_PACKET_LENGTH_OFFSET])
    assert packet[3:4] == expected_len_byte

    # 验证用户名位置
    assert packet[20:56].startswith(username.encode("utf-8", "ignore"))

    # 验证 Host IP 位置
    assert packet[81:85] == host_ip_bytes

    # 验证 Host Name 位置
    assert packet[110:142].startswith(host_name.encode("utf-8", "ignore"))

    # 验证 Auth Version 位置
    assert packet[310:312] == auth_version

    actual_mac_slice = packet[320:326]
    expected_mac = mac_bytes
    # 验证 AuthExtData 结构中的 MAC 地址 (包的末尾附近)
    # (312 (Code) + 313 (Len) + 314-317 (CRC) + 318-319 (Option) + 320-325 (MAC))
    # 调试输出：
    if actual_mac_slice != expected_mac:
        print(f"\n--- DEBUG: 完整数据包 (Actual) ---\n{packet.hex()}\n")

        # 我们可以进一步验证其他字段
        # 比如 mac xor md5a (偏移量 58-63)
        actual_xor_slice = packet[58:64]
        print(f"--- DEBUG: 实际的 XOR   (packet[58:64]): {actual_xor_slice.hex()}")

        # 打印出 `md5a` 的相关切片，看看哪个对上了
        from hashlib import md5

        md5a = md5(b"\x03\x01" + salt + password.encode("utf-8", "ignore")).digest()
        print(f"--- DEBUG: 期望的 MD5A[0:6]: {md5a[:6].hex()}")
        print(f"--- DEBUG: 期望的 MD5A[3:9]: {md5a[3:9].hex()}")

        print(f"--- DEBUG: 期望的 MAC (mac_bytes): {expected_mac.hex()}")
        print(f"--- DEBUG: 实际的 MAC (packet[320:326]): {actual_mac_slice.hex()}")

    assert packet[320:326] == mac_bytes

    # 验证结尾 (非 ROR)
    assert packet.endswith(constants.LOGIN_PACKET_ENDING)
    # 验证总长度
    assert len(packet) == 330  # (325 + 2 + 1 + 2 = 330)


def test_build_login_packet_ror_status(
    username,
    password,
    salt,
    mac_address,
    mac_bytes,
    host_ip_bytes,
    host_name,
    host_os,
    primary_dns_bytes,
    dhcp_server_bytes,
    control_check_status,
    adapter_num,
    ipdog,
    auth_version,
):
    """
    测试 ROR=True 分支，它会跳过 AutoLogout 和 BroadcastMode 字节。
    """
    packet = login.build_login_packet(
        username=username,
        password=password,
        salt=salt,
        mac_address=mac_address,
        host_ip_bytes=host_ip_bytes,
        host_name=host_name,
        host_os=host_os,
        primary_dns_bytes=primary_dns_bytes,
        dhcp_server_bytes=dhcp_server_bytes,
        control_check_status=control_check_status,
        adapter_num=adapter_num,
        ipdog=ipdog,
        auth_version=auth_version,
        ror_status=True,  # <-- 测试这个分支
    )

    # 验证总长度 (ROR 模式下少了 2 字节)
    assert len(packet) == 328
    # 验证结尾 (ROR)
    assert packet[326:328] == constants.LOGIN_PACKET_ENDING
    assert packet.endswith(constants.LOGIN_PACKET_ENDING)


@pytest.mark.parametrize(
    "invalid_param, value, expected_exception",
    [
        ("salt", b"\x12\x34", ValueError),  # Salt 长度错误
        ("salt", b"", ValueError),  # Salt 为空
        ("username", "", ValueError),  # 用户名为空
        ("password", "", ValueError),  # 密码为空
        ("host_ip_bytes", b"\x01\x02\x03", ValueError),  # IP 长度错误
        ("mac_address", 2**48 + 1, ValueError),  # MAC 整数过大 (溢出6字节)
    ],
)
def test_build_login_packet_invalid_inputs(
    invalid_param,
    value,
    expected_exception,
    # 传入所有有效的 fixtures
    username,
    password,
    salt,
    mac_address,
    host_ip_bytes,
    host_name,
    host_os,
    primary_dns_bytes,
    dhcp_server_bytes,
    control_check_status,
    adapter_num,
    ipdog,
    auth_version,
):
    """
    测试登录包构建时的无效参数是否能正确抛出异常。
    """
    # 准备参数字典
    params = {
        "username": username,
        "password": password,
        "salt": salt,
        "mac_address": mac_address,
        "host_ip_bytes": host_ip_bytes,
        "host_name": host_name,
        "host_os": host_os,
        "primary_dns_bytes": primary_dns_bytes,
        "dhcp_server_bytes": dhcp_server_bytes,
        "control_check_status": control_check_status,
        "adapter_num": adapter_num,
        "ipdog": ipdog,
        "auth_version": auth_version,
        "ror_status": False,
    }

    # 覆盖掉无效的参数
    params[invalid_param] = value

    # 断言预期的异常被抛出
    with pytest.raises(expected_exception):
        login.build_login_packet(**params)


# --- 测试 parse_login_response ---


@pytest.mark.parametrize(
    "response_data, expected_ip, received_ip, expected_result, description",
    [
        # 1. 成功 (0x04)
        (
            b"\x04"
            + b"\x00" * 22
            + b"\xaa" * 16
            + b"\x00" * 10,  # 模拟的 Auth Info 在 23-38
            "1.1.1.1",
            "1.1.1.1",
            (True, b"\xaa" * 16, None, "登录成功"),
            "成功 (0x04)",
        ),
        # 2. 失败 (0x04 但包太短)
        (
            b"\x04" + b"\x00" * 22,  # 总共 23 字节，无法提取 Auth Info
            "1.1.1.1",
            "1.1.1.1",
            (False, None, None, "登录成功响应包过短 (长度 23)，无法提取 Auth Info。"),
            "失败 (0x04 包太短)",
        ),
        # 3. 失败 (0x05 - 密码错误)
        (
            b"\x05\x00\x00\x00\x03" + b"\x00" * 10,  # 错误码 0x03 在偏移量 4
            "1.1.1.1",
            "1.1.1.1",
            (False, None, 0x03, "登录失败 (错误码: 0x3) - 账号或密码错误"),
            "失败 (0x05 密码错误)",
        ),
        # 4. 失败 (0x05 - 账号在用)
        (
            b"\x05\x00\x00\x00\x01" + b"\x00" * 10,  # 错误码 0x01
            "1.1.1.1",
            "1.1.1.1",
            (
                False,
                None,
                0x01,
                "登录失败 (错误码: 0x1) - 账号正在使用中或认证 MAC/IP 不匹配",
            ),
            "失败 (0x05 账号在用)",
        ),
        # 5. 失败 (0x05 - 未知错误码)
        (
            b"\x05\x00\x00\x00\xff" + b"\x00" * 10,  # 错误码 0xFF
            "1.1.1.1",
            "1.1.1.1",
            (False, None, 0xFF, "登录失败 (错误码: 0xff) - 未知错误"),
            "失败 (0x05 未知错误码)",
        ),
        # 6. 失败 (IP 不匹配)
        (
            b"\x04" + b"\x00" * 50,
            "1.1.1.1",
            "2.2.2.2",  # IP 不匹配
            (False, None, None, "收到无效响应或来源不匹配 (来自: 2.2.2.2)"),
            "失败 (IP 不匹配)",
        ),
        # 7. 失败 (未知 Code)
        (
            b"\xaa" + b"\x00" * 50,  # 未知 Code
            "1.1.1.1",
            "1.1.1.1",
            (False, None, None, "收到未知的登录响应代码: 0xaa"),
            "失败 (未知 Code)",
        ),
    ],
)
def test_parse_login_response(
    response_data, expected_ip, received_ip, expected_result, description
):
    """
    测试登录响应的解析。
    """
    result = login.parse_login_response(response_data, expected_ip, received_ip)
    assert result == expected_result, description
