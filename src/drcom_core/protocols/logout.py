# src/drcom_core/protocols/logout.py
import hashlib
import logging
from typing import Optional, Tuple

from .constants import LoginConst, LogoutConst, PacketCode, PacketType

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
    """构建 Logout 包。"""
    username_bytes = username.encode("utf-8", "ignore")
    password_bytes = password.encode("utf-8", "ignore")

    packet = b""

    pkt_len = len(username_bytes) + LoginConst.PACKET_LEN_OFFSET
    header = PacketCode.LOGOUT_REQ + PacketType.LOGOUT + b"\x00" + bytes([pkt_len])
    packet += header

    md5a_data = LoginConst.MD5A_SALT_PREFIX + salt + password_bytes
    md5a = hashlib.md5(md5a_data).digest()
    packet += md5a

    packet += username_bytes.ljust(LoginConst.PAD_USERNAME, b"\x00")
    packet += control_check_status
    packet += adapter_num

    mac_xor_md5_part = md5a[: LoginConst.PAD_MAC_XOR]
    md5_part_int = int.from_bytes(mac_xor_md5_part, byteorder="big")
    xor_result = md5_part_int ^ mac
    xor_bytes = xor_result.to_bytes(LoginConst.PAD_MAC_XOR, byteorder="big")
    packet += xor_bytes

    packet += auth_info
    return packet


def parse_logout_response(
    response_data: Optional[bytes],
    expected_server_ip: str,
    received_from_ip: Optional[str],
) -> Tuple[bool, str]:
    """解析 Logout 响应包。"""
    if not response_data:
        return True, "未收到响应 (尝试登出成功)"

    if not received_from_ip or received_from_ip != expected_server_ip:
        return False, f"来源 IP 不匹配 ({received_from_ip})"

    if response_data[0] == LogoutConst.SUCCESS_CODE:
        return True, "服务器确认登出成功 (0x04)"
    else:
        return False, f"非预期登出响应代码: {hex(response_data[0])}"
