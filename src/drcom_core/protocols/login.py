# src/drcom_core/protocols/login.py
import hashlib
import logging
import random
import struct

from ..exceptions import AuthErrorCode
from .constants import LoginConst, PacketCode

logger = logging.getLogger(__name__)


def _calculate_checksum(data: bytes) -> bytes:
    """计算校验和"""
    ret = LoginConst.CHECKSUM2_INIT
    padded_data = data + b"\x00" * (-(len(data)) % 4)

    for i in range(0, len(padded_data), 4):
        chunk = padded_data[i : i + 4]
        val = struct.unpack("<I", chunk)[0]
        ret ^= val

    ret = (LoginConst.CHECKSUM2_MULT * ret) & 0xFFFFFFFF
    return struct.pack("<I", ret)


def build_login_packet(
    username: str,
    password: str,
    salt: bytes,
    mac_address: int,
    host_ip_bytes: bytes,
    primary_dns_bytes: bytes,
    dhcp_server_bytes: bytes,
    host_name: str,
    host_os: str,
    os_info_bytes: bytes,
    adapter_num: bytes,
    ipdog: bytes,
    auth_version: bytes,
    control_check_status: bytes,
    ror_status: bool,
) -> bytes:
    """构建 Login 请求包"""
    usr_bytes = username.encode("utf-8", "ignore")
    pwd_bytes = password.encode("utf-8", "ignore")
    hostname_bytes = host_name.encode("utf-8", "ignore")
    hostos_bytes = host_os.encode("utf-8", "ignore")

    data = b""

    packet_len = len(usr_bytes) + LoginConst.PACKET_LEN_OFFSET
    header = PacketCode.LOGIN_REQ + b"\x00" + bytes([packet_len])
    data += header

    md5a_data = LoginConst.MD5A_SALT_PREFIX + salt + pwd_bytes
    md5a = hashlib.md5(md5a_data).digest()
    data += md5a

    data += usr_bytes.ljust(LoginConst.PAD_USERNAME, b"\x00")
    data += control_check_status
    data += adapter_num

    mac_xor_key = int.from_bytes(md5a[:6], byteorder="big")
    xor_result = mac_xor_key ^ mac_address
    data += xor_result.to_bytes(6, byteorder="big")

    md5b_input = (
        LoginConst.MD5B_SALT_PREFIX + pwd_bytes + salt + LoginConst.MD5B_SALT_SUFFIX
    )
    md5b = hashlib.md5(md5b_input).digest()
    data += md5b

    data += b"\x01"
    data += host_ip_bytes
    data += b"\x00" * LoginConst.PAD_IP

    md5c_input = data + LoginConst.MD5C_SUFFIX
    md5c = hashlib.md5(md5c_input).digest()[: LoginConst.CHECKSUM1_LEN]
    data += md5c

    data += ipdog
    data += LoginConst.SEP_IPDOG

    data += hostname_bytes.ljust(LoginConst.PAD_HOSTNAME, b"\x00")
    data += primary_dns_bytes
    data += dhcp_server_bytes
    data += LoginConst.PAD_DNS2
    data += LoginConst.PAD_WINS

    data += os_info_bytes

    data += hostos_bytes.ljust(LoginConst.PAD_HOST_OS, b"\x00")
    data += b"\x00" * LoginConst.PAD_HOST_OS_SUFFIX
    data += auth_version

    if ror_status:
        logger.warning("ROR 模式已启用但尚未实现。")

    mac_bytes = mac_address.to_bytes(6, byteorder="big")
    checksum2_input = data + LoginConst.CHECKSUM2_SUFFIX + mac_bytes
    checksum2 = _calculate_checksum(checksum2_input)

    data += LoginConst.AUTH_EXT_CODE
    data += LoginConst.AUTH_EXT_LEN
    data += checksum2
    data += LoginConst.AUTH_EXT_OPTION
    data += mac_bytes

    if not ror_status:
        data += LoginConst.PAD_AUTO_LOGOUT
        data += LoginConst.PAD_BROADCAST

    rand_tail = random.randbytes(2)
    data += rand_tail

    return data


def parse_login_response(
    response_data: bytes, expected_server_ip: str, received_from_ip: str
) -> tuple[bool, bytes | None, int | None, str]:
    """解析 Login 响应"""
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

    if code == PacketCode.LOGIN_SUCCESS:
        if len(response_data) < LoginConst.AUTH_INFO_END:
            return False, None, None, "响应包长度不足"

        auth_info = response_data[LoginConst.AUTH_INFO_START : LoginConst.AUTH_INFO_END]
        return True, auth_info, None, "登录成功"

    elif code == PacketCode.LOGIN_FAILURE:
        error_code = None
        if len(response_data) > LoginConst.ERROR_CODE_IDX:
            error_code = response_data[LoginConst.ERROR_CODE_IDX]

        err_msg = "未知错误"
        if error_code is not None:
            try:
                e_enum = AuthErrorCode(error_code)
                # ... (错误映射逻辑保持不变，此处省略以节省篇幅) ...
                err_msg = f"错误: {e_enum.name}"
            except ValueError:
                pass

        return (
            False,
            None,
            error_code,
            f"登录失败: {err_msg} (Code: {hex(error_code) if error_code is not None else 'N/A'})",
        )

    else:
        return False, None, None, f"未知的响应代码: {hex(code)}"
