# src/drcom_core/protocols/keep_alive.py
import hashlib
import logging
import struct
import time
from typing import Optional

from .constants import KeepAliveConst, LoginConst, PacketCode

logger = logging.getLogger(__name__)


def build_keep_alive1_packet(
    salt: bytes,
    password: str,
    auth_info: bytes,
    include_trailing_zeros: bool = True,
) -> bytes:
    """构建 Keep Alive 1 (FF 包)。"""
    password_bytes = password.encode("utf-8", "ignore")

    md5_data = LoginConst.MD5A_SALT_PREFIX + salt + password_bytes
    md5_hash = hashlib.md5(md5_data).digest()

    timestamp_packed = struct.pack("!H", int(time.time()) % 0xFFFF)

    packet = (
        PacketCode.KA_CLIENT_HEARTBEAT
        + md5_hash
        + KeepAliveConst.EMPTY_3
        + auth_info
        + timestamp_packed
    )

    if include_trailing_zeros:
        packet += KeepAliveConst.EMPTY_4

    return packet


def parse_keep_alive1_response(data: bytes) -> bool:
    """解析 Keep Alive 1 (FF 包)。"""
    if not data:
        return False
    return data.startswith(KeepAliveConst.RESP_CODE)


def build_keep_alive2_packet(
    packet_number: int,
    tail: bytes,
    packet_type: int,
    host_ip_bytes: bytes,
    keep_alive_version: bytes,
    is_first_packet: bool = False,
) -> bytes:
    """构建 Keep Alive 2 (07 包)。"""
    data = PacketCode.KA_MISC
    data += bytes([packet_number])
    data += KeepAliveConst.KA2_HEADER_PREFIX
    data += bytes([packet_type])

    if is_first_packet:
        data += KeepAliveConst.KA2_FIRST_VER
    else:
        data += keep_alive_version

    data += KeepAliveConst.KA2_FIXED1
    data += KeepAliveConst.KA2_FIXED1_PAD
    data += tail
    data += KeepAliveConst.KA2_TAIL_PAD

    if packet_type == 3:
        specific_part = (
            KeepAliveConst.KA2_T3_CRC_DEFAULT
            + host_ip_bytes
            + KeepAliveConst.KA2_T3_PAD_END
        )
    else:
        specific_part = KeepAliveConst.KA2_T1_SPECIFIC

    data += specific_part
    return data


def parse_keep_alive2_response(data: bytes) -> Optional[bytes]:
    """解析 Keep Alive 2 (07 包)。"""
    if not data:
        return None
    if not data.startswith(KeepAliveConst.RESP_CODE):
        return None
    if len(data) < 20:
        return None
    return data[16:20]
