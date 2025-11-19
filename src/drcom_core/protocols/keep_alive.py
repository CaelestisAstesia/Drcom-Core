# src/drcom_core/protocols/keep_alive.py
"""
处理 Dr.COM D 版心跳维持 (Keep Alive) 包的构建与解析。
"""

import hashlib
import logging
import struct
import time
from typing import Optional

from ..exceptions import ProtocolError
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
    # 参数校验
    if not salt or len(salt) != 4:
        raise ProtocolError("构建 FF 包失败: Salt 无效。")
    if not auth_info or len(auth_info) != constants.AUTH_INFO_LENGTH:
        raise ProtocolError("构建 FF 包失败: Auth Info 长度错误 (需要16字节)。")

    try:
        password_bytes = password.encode("utf-8", "ignore")

        # 1. 计算 MD5 部分
        md5_data = constants.MD5_SALT_PREFIX + salt + password_bytes
        md5_hash = hashlib.md5(md5_data).digest()

        # 2. 获取时间戳
        timestamp_packed = struct.pack("!H", int(time.time()) % 0xFFFF)

        # 3. 组装数据包
        packet = (
            constants.KEEP_ALIVE_CLIENT_CODE  # \xff
            + md5_hash
            + constants.KEEP_ALIVE_EMPTY_BYTES_3
            + auth_info
            + timestamp_packed
        )

        if include_trailing_zeros:
            packet += constants.KEEP_ALIVE_EMPTY_BYTES_4

        return packet

    except Exception as e:
        raise ProtocolError(f"构建 Keep Alive 1 包时出错: {e}") from e


def parse_keep_alive1_response(data: bytes) -> bool:
    """
    解析 Keep Alive 1 (FF 包) 的响应。
    """
    if not data:
        logger.warning("KA1 响应为空。")
        return False

    if data.startswith(constants.KEEP_ALIVE_RESP_CODE):  # 0x07
        return True
    else:
        logger.warning(f"KA1 收到非预期的响应代码: {data[:1].hex()}。")
        return False


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
    if not (0 <= packet_number <= 255):
        raise ProtocolError(f"KA2 packet_number 无效: {packet_number}")
    if len(tail) != 4:
        raise ProtocolError(f"KA2 tail 长度无效: {len(tail)}")
    if packet_type not in [1, 3]:
        raise ProtocolError(f"KA2 packet_type 无效: {packet_type}")

    try:
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
            if len(host_ip_bytes) != 4:
                raise ProtocolError("Host IP 长度错误")

            specific_part = (
                constants.KA2_TYPE3_CRC_DEFAULT
                + host_ip_bytes
                + constants.KA2_TYPE3_PADDING_END
            )
        else:
            specific_part = constants.KA2_TYPE1_SPECIFIC_PART

        data += specific_part
        return data

    except Exception as e:
        raise ProtocolError(f"构建 KA2 包时出错: {e}") from e


def parse_keep_alive2_response(data: bytes) -> Optional[bytes]:
    """
    解析 Keep Alive 2 (07 包) 的响应，提取 Tail。
    """
    if not data:
        return None

    # 1. 检查 Code
    if not data.startswith(constants.KEEP_ALIVE_RESP_CODE):
        logger.warning(f"KA2 收到非预期响应代码: {data[:1].hex()}。")
        return None

    # 2. 提取 Tail
    tail_start = 16
    tail_end = 20
    if len(data) < tail_end:
        logger.warning(f"KA2 响应过短 (len={len(data)})，无法提取 Tail。")
        return None

    new_tail = data[tail_start:tail_end]
    return new_tail
