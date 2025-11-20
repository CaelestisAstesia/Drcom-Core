# src/drcom_core/protocols/login.py
"""
处理 Dr.COM D 版登录认证 (Code 0x03) 请求包的构建与解析。
"""

import hashlib
import logging
import random
import struct

from . import constants

logger = logging.getLogger(__name__)


def _calculate_checksum(data: bytes) -> bytes:
    ret = constants.CHECKSUM2_INIT_VALUE
    padded_data = data + b"\x00" * (-(len(data)) % 4)

    for i in range(0, len(padded_data), 4):
        chunk = padded_data[i : i + 4]
        val = struct.unpack("<I", chunk)[0]
        ret ^= val

    ret = (constants.CHECKSUM2_MULTIPLIER * ret) & 0xFFFFFFFF
    return struct.pack("<I", ret)


def build_login_packet(
    username: str,
    password: str,
    salt: bytes,
    mac_address: int,
    # --- 网络配置 ---
    host_ip_bytes: bytes,
    primary_dns_bytes: bytes,
    dhcp_server_bytes: bytes,
    # --- 身份标识 ---
    host_name: str,
    host_os: str,
    os_info_bytes: bytes,
    adapter_num: bytes,
    ipdog: bytes,
    auth_version: bytes,
    control_check_status: bytes,
    # --- 策略开关 ---
    ror_status: bool,
) -> bytes:
    """
    构建 Dr.COM D 版登录请求包。
    """
    usr_bytes = username.encode("utf-8", "ignore")
    pwd_bytes = password.encode("utf-8", "ignore")
    hostname_bytes = host_name.encode("utf-8", "ignore")
    hostos_bytes = host_os.encode("utf-8", "ignore")

    data = b""

    packet_len = len(usr_bytes) + constants.LOGIN_PACKET_LENGTH_OFFSET
    header = constants.LOGIN_REQ_CODE + b"\x00" + bytes([packet_len])
    data += header

    md5a_data = constants.MD5_SALT_PREFIX + salt + pwd_bytes
    md5a = hashlib.md5(md5a_data).digest()
    data += md5a

    data += usr_bytes.ljust(constants.USERNAME_PADDING_LENGTH, b"\x00")
    data += control_check_status
    data += adapter_num

    mac_xor_key = int.from_bytes(md5a[:6], byteorder="big")
    xor_result = mac_xor_key ^ mac_address
    data += xor_result.to_bytes(6, byteorder="big")

    md5b_input = (
        constants.MD5B_SALT_PREFIX + pwd_bytes + salt + constants.MD5B_SALT_SUFFIX
    )
    md5b = hashlib.md5(md5b_input).digest()
    data += md5b

    data += b"\x01"
    data += host_ip_bytes
    data += b"\x00" * constants.IP_ADDR_PADDING_LENGTH

    md5c_input = data + constants.MD5C_SUFFIX
    md5c = hashlib.md5(md5c_input).digest()[: constants.CHECKSUM1_LENGTH]
    data += md5c

    data += ipdog
    data += constants.IPDOG_SEPARATOR

    data += hostname_bytes.ljust(constants.HOSTNAME_PADDING_LENGTH, b"\x00")
    data += primary_dns_bytes
    data += dhcp_server_bytes
    data += constants.SECONDARY_DNS_PADDING
    data += constants.WINS_SERVER_PADDING

    data += os_info_bytes

    data += hostos_bytes.ljust(constants.HOSTOS_PADDING_LENGTH, b"\x00")
    data += b"\x00" * constants.HOSTOS_PADDING_SUFFIX_LENGTH
    data += auth_version

    if ror_status:
        logger.warning("ROR 模式已启用但尚未实现。")

    mac_bytes = mac_address.to_bytes(6, byteorder="big")
    checksum2_input = data + constants.CHECKSUM2_SUFFIX + mac_bytes
    checksum2 = _calculate_checksum(checksum2_input)

    data += constants.AUTH_EXT_DATA_CODE
    data += constants.AUTH_EXT_DATA_LEN
    data += checksum2
    data += constants.AUTH_EXT_DATA_OPTION
    data += mac_bytes

    if not ror_status:
        data += constants.AUTO_LOGOUT_PADDING
        data += constants.BROADCAST_MODE_PADDING

    rand_tail = random.randbytes(2)
    data += rand_tail

    return data


def parse_login_response(
    response_data: bytes, expected_server_ip: str, received_from_ip: str
) -> tuple[bool, bytes | None, int | None, str]:
    """
    解析登录响应。
    Returns: (Success, AuthInfo, ErrorCode, Message)
    """
    if not response_data:
        return False, None, None, "未收到数据"

    if received_from_ip != expected_server_ip:
        return (
            False,
            None,
            None,
            f"来源 IP 不匹配 (期望 {expected_server_ip}, 实际 {received_from_ip})",
        )

    code = response_data[0]

    if code == constants.LOGIN_RESP_SUCCESS_CODE:
        if len(response_data) < constants.AUTH_INFO_END_INDEX:
            return False, None, None, "响应包长度不足"

        auth_info = response_data[
            constants.AUTH_INFO_START_INDEX : constants.AUTH_INFO_END_INDEX
        ]
        return True, auth_info, None, "登录成功"

    elif code == constants.LOGIN_RESP_FAIL_CODE:
        error_code = None
        if len(response_data) > constants.ERROR_CODE_INDEX:
            error_code = response_data[constants.ERROR_CODE_INDEX]

        err_msg = "未知错误"
        # 简单的映射，实际生产可以做成字典
        if error_code == constants.ERROR_CODE_IN_USE:
            err_msg = "账号在线或MAC绑定错误"
        elif error_code == constants.ERROR_CODE_WRONG_PASS:
            err_msg = "密码错误"
        elif error_code == constants.ERROR_CODE_INSUFFICIENT:
            err_msg = "余额不足或欠费"
        elif error_code == constants.ERROR_CODE_WRONG_MAC:
            err_msg = "MAC地址不匹配"
        elif error_code == constants.ERROR_CODE_WRONG_IP:
            err_msg = "IP地址不匹配"
        elif error_code == constants.ERROR_CODE_WRONG_VERSION:
            err_msg = "客户端版本不匹配"
        elif error_code == constants.ERROR_CODE_FROZEN:
            err_msg = "账号被冻结"

        return (
            False,
            None,
            error_code,
            f"登录失败: {err_msg} (Code: {hex(error_code) if error_code else 'N/A'})",
        )

    else:
        return False, None, None, f"未知的响应代码: {hex(code)}"
