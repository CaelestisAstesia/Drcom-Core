# src/drcom_core/protocols/keep_alive.py
"""
处理 Dr.COM D 版心跳维持 (Keep Alive) 包的构建与解析。
遵循“信任边界”原则：不再执行防御性参数校验。
"""

import hashlib
import logging
import struct
import time
from typing import Optional

from . import constants

logger = logging.getLogger(__name__)


# Keep Alive 1 (FF 包)
# ---------------------------------------------------


def build_keep_alive1_packet(
    salt: bytes,
    password: str,
    auth_info: bytes,
    include_trailing_zeros: bool = True,
) -> bytes:
    """
    构建 Keep Alive 1 (FF 包)。
    """
    # 直接编码，信任 config 中的 password 是 str
    password_bytes = password.encode("utf-8", "ignore")

    # 1. 计算 MD5 (0301 + salt + password)
    md5_data = constants.MD5_SALT_PREFIX + salt + password_bytes
    md5_hash = hashlib.md5(md5_data).digest()

    # 2. 时间戳
    timestamp_packed = struct.pack("!H", int(time.time()) % 0xFFFF)

    # 3. 组装
    packet = (
        constants.KEEP_ALIVE_CLIENT_CODE
        + md5_hash
        + constants.KEEP_ALIVE_EMPTY_BYTES_3
        + auth_info
        + timestamp_packed
    )

    if include_trailing_zeros:
        packet += constants.KEEP_ALIVE_EMPTY_BYTES_4

    return packet


def parse_keep_alive1_response(data: bytes) -> bool:
    """
    解析 Keep Alive 1 响应。
    """
    if not data:
        return False
    return data.startswith(constants.KEEP_ALIVE_RESP_CODE)


# Keep Alive 2 (07 包序列)
# ---------------------------------------------------


def build_keep_alive2_packet(
    packet_number: int,
    tail: bytes,
    packet_type: int,
    host_ip_bytes: bytes,
    keep_alive_version: bytes,
    is_first_packet: bool = False,
) -> bytes:
    """
    构建 Keep Alive 2 (07 包)。
    """
    # 头部
    data = constants.MISC_CODE  # b"\x07"
    data += bytes([packet_number])
    data += constants.KA2_HEADER_PREFIX
    data += bytes([packet_type])

    # Version
    if is_first_packet:
        data += constants.KA2_FIRST_PACKET_VERSION
    else:
        data += keep_alive_version

    data += constants.KA2_FIXED_PART1
    data += constants.KA2_FIXED_PART1_PADDING
    data += tail
    data += constants.KA2_TAIL_PADDING

    # 类型特定部分
    if packet_type == 3:
        specific_part = (
            constants.KA2_TYPE3_CRC_DEFAULT
            + host_ip_bytes
            + constants.KA2_TYPE3_PADDING_END
        )
    else:
        specific_part = constants.KA2_TYPE1_SPECIFIC_PART

    data += specific_part
    return data


def parse_keep_alive2_response(data: bytes) -> Optional[bytes]:
    """
    解析 Keep Alive 2 响应，提取 Tail。
    """
    if not data:
        return None

    # 1. 检查 Code
    if not data.startswith(constants.KEEP_ALIVE_RESP_CODE):
        return None

    # 2. 提取 Tail (16:20)
    # 这里做一下长度检查防止 crash 是合理的，因为网络数据不可信
    if len(data) < 20:
        return None

    return data[16:20]
