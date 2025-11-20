# src/drcom_core/protocols/logout.py
"""
处理 Dr.COM D 版登出 (Code 0x06) 请求包的构建以及响应的解析。
遵循“信任边界”原则。
"""

import hashlib
import logging
from typing import Optional, Tuple

from . import constants

logger = logging.getLogger(__name__)


def build_logout_packet(
    username: str,
    password: str,
    salt: bytes,
    mac: int,
    auth_info: bytes,
    control_check_status: bytes,
    adapter_num: bytes,
) -> bytes:
    """
    构建 Dr.COM D 版登出请求包 (Code 0x06)。
    """
    # 1. 编码
    username_bytes = username.encode("utf-8", "ignore")
    password_bytes = password.encode("utf-8", "ignore")

    packet = b""

    # 2. 包头
    pkt_len = len(username_bytes) + constants.LOGIN_PACKET_LENGTH_OFFSET
    header = (
        constants.LOGOUT_REQ_CODE + constants.LOGOUT_TYPE + b"\x00" + bytes([pkt_len])
    )
    packet += header

    # 3. MD5_A (基于新 Salt)
    md5a_data = constants.MD5_SALT_PREFIX + salt + password_bytes
    md5a = hashlib.md5(md5a_data).digest()
    packet += md5a

    # 4. 用户名
    packet += username_bytes.ljust(constants.USERNAME_PADDING_LENGTH, b"\x00")

    # 5. ControlStatus & AdapterNum
    packet += control_check_status
    packet += adapter_num

    # 6. MAC 地址异或
    # 注意：MD5A 长度必定足够 (16 bytes)，无需 try-except
    mac_xor_md5_part = md5a[: constants.MAC_XOR_PADDING_LENGTH]
    md5_part_int = int.from_bytes(mac_xor_md5_part, byteorder="big")
    xor_result = md5_part_int ^ mac
    xor_bytes = xor_result.to_bytes(constants.MAC_XOR_PADDING_LENGTH, byteorder="big")
    packet += xor_bytes

    # 7. Auth Info (Tail)
    packet += auth_info

    return packet


def parse_logout_response(
    response_data: Optional[bytes],
    expected_server_ip: str,
    received_from_ip: Optional[str],
) -> Tuple[bool, str]:
    """
    解析登出响应。
    """
    # 情况 1: 未收到响应 (Timeout) -> 视为成功
    if not response_data:
        return True, "未收到响应 (尝试登出成功)"

    # 情况 2: IP 不匹配
    if not received_from_ip or received_from_ip != expected_server_ip:
        return False, f"来源 IP 不匹配 ({received_from_ip})"

    # 情况 3: 检查 Code
    if response_data[0] == constants.SUCCESS_RESP_CODE:
        return True, "服务器确认登出成功 (0x04)"
    else:
        return False, f"非预期登出响应代码: {hex(response_data[0])}"
