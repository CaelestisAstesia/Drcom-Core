# /src/drcom_protocol/keep_alive.py
"""
处理 Dr.COM D 版心跳维持 (Keep Alive) 包的构建与解析。
包括 Keep Alive 1 (FF 包) 和 Keep Alive 2 (07 包序列)。
"""

import hashlib
import logging
import socket
import struct
import time
from typing import Optional

# 从常量模块导入所有需要的常量
from .constants import (
    AUTH_INFO_LENGTH,
    KA2_FIRST_PACKET_VERSION,
    KA2_FIXED_PART1,
    KA2_FIXED_PART1_PADDING,
    KA2_HEADER_PREFIX,
    KA2_TAIL_PADDING,
    KA2_TYPE1_SPECIFIC_PART,
    KA2_TYPE3_CRC_DEFAULT,
    KA2_TYPE3_PADDING_END,
    KEEP_ALIVE_CLIENT_CODE,
    KEEP_ALIVE_EMPTY_BYTES_3,
    KEEP_ALIVE_EMPTY_BYTES_4,
    KEEP_ALIVE_RESP_CODE,
    KEEP_ALIVE_VERSION,  # Keep Alive 2 的版本号
    MD5_SALT_PREFIX,
    MISC_CODE,
)

logger = logging.getLogger(__name__)

# Keep Alive 1 (FF 包)


def build_keep_alive1_packet(
    salt: bytes,
    password: str,
    auth_info: bytes,  # Tail from login response
    include_trailing_zeros: bool = True,  # 控制是否添加末尾 4 字节 00
) -> Optional[bytes]:
    """
    构建 Keep Alive 1 (FF 包 / 心跳包 1)。

    结构: FF + MD5(0301+salt+pwd) + 00*3 + auth_info(tail) + timestamp(!H) [+ 00*4]

    Args:
        salt: 当前有效的 4 字节 Challenge Salt。
        password: 用户密码。
        auth_info: 登录成功时获取的 16 字节认证信息 (Tail)。
        include_trailing_zeros: 是否在包末尾添加 4 个零字节。

    Returns:
        Optional[bytes]: 构建好的 FF 心跳包，如果参数无效则返回 None。
    """
    logger.debug("构建 Keep Alive 1 (FF) 包...")
    # 参数校验
    if not salt or len(salt) != 4:
        logger.error("构建 FF 包失败: Salt 无效。")
        return None
    if not password:
        logger.error("构建 FF 包失败: 密码为空。")
        return None
    if not auth_info or len(auth_info) != AUTH_INFO_LENGTH:
        logger.error(
            f"构建 FF 包失败: Auth Info (Tail) 无效或长度不为 {AUTH_INFO_LENGTH}。"
        )
        return None

    try:
        password_bytes = password.encode("utf-8", "ignore")

        # 1. 计算 MD5 部分
        md5_data = MD5_SALT_PREFIX + salt + password_bytes  # 使用导入的常量
        md5_hash = hashlib.md5(md5_data).digest()

        # 2. 获取时间戳 (2字节网络序)
        timestamp_packed = struct.pack("!H", int(time.time()) % 0xFFFF)

        # 3. 组装数据包
        packet = (
            KEEP_ALIVE_CLIENT_CODE  # 使用导入的常量
            + md5_hash
            + KEEP_ALIVE_EMPTY_BYTES_3  # 使用导入的常量
            + auth_info
            + timestamp_packed
        )

        # 4. (可选) 添加末尾填充
        if include_trailing_zeros:
            packet += KEEP_ALIVE_EMPTY_BYTES_4  # 使用导入的常量

        logger.debug(
            f"构建的 Keep Alive 1 包 ({'带' if include_trailing_zeros else '不带'}末尾填充): {packet.hex()}"
        )
        return packet

    except Exception as e:
        logger.error(f"构建 Keep Alive 1 包时出错: {e}", exc_info=True)
        return None


def parse_keep_alive1_response(data: bytes) -> bool:
    """
    解析 Keep Alive 1 (FF 包) 的响应。
    主要检查响应代码是否为 0x07。

    Args:
        data: 收到的响应字节串。

    Returns:
        bool: 如果响应代码是 0x07 则返回 True，否则 False。
    """
    if not data:
        logger.warning("解析 Keep Alive 1 响应：收到空数据。")
        return False

    if data.startswith(KEEP_ALIVE_RESP_CODE):  # 使用导入的常量
        logger.debug(f"Keep Alive 1 响应代码正确 ({KEEP_ALIVE_RESP_CODE.hex()})。")
        return True
    else:
        logger.warning(f"Keep Alive 1 收到非预期的响应代码: {data[:1].hex()}。")
        return False


# Keep Alive 2 (07 包序列)


def build_keep_alive2_packet(
    packet_number: int,
    tail: bytes,  # 来自上一个响应包 data[16:20]
    packet_type: int,  # 通常是 1 或 3
    host_ip: str,
    # keep_alive_version: bytes, # 不再作为参数传入，直接使用常量
    is_first_packet: bool = False,
) -> Optional[bytes]:
    """
    构建 Dr.COM 的 Keep Alive 2 (07 包) 心跳包。
    基于 latest-wired-python3.py 的实现逻辑。

    结构: 07 + number + 28000b + type + version + 2f12 + 00*6 + tail + 00*4 + specific_part

    Args:
        packet_number: 包序号 (0-255)。
        tail: 4 字节的 tail 值 (bytes 类型)，来自上一个 **响应包** 的 data[16:20]。
        packet_type: 包类型，通常是 1 或 3。
        host_ip: 当前客户端的 IP 地址字符串。
        is_first_packet: 是否是整个 keep_alive2 序列中的第一个包。默认为 False。

    Returns:
        Optional[bytes]: 构建成功的心跳包，如果参数无效则返回 None。
    """
    logger.debug(
        f"构建 Keep Alive 2 (07) 包: Number={packet_number}, Type={packet_type}, First={is_first_packet}"
    )
    # 参数校验 (移除 keep_alive_version 检查)
    if not isinstance(packet_number, int) or not (0 <= packet_number <= 255):
        logger.error(f"构建 KA2 包失败: packet_number ({packet_number}) 无效。")
        return None
    if not isinstance(tail, bytes) or len(tail) != 4:
        logger.error(
            f"构建 KA2 包失败: tail 无效或长度不为 4 (实际: {len(tail) if isinstance(tail, bytes) else type(tail)})。"
        )
        return None
    if packet_type not in [1, 3]:
        logger.error(f"构建 KA2 包失败: packet_type ({packet_type}) 无效。")
        return None

    # 构建数据包头部和公共部分
    try:
        data = MISC_CODE  # b"\x07"
        data += bytes([packet_number])
        data += KA2_HEADER_PREFIX
        data += bytes([packet_type])

        # Version 字段
        if is_first_packet:
            data += KA2_FIRST_PACKET_VERSION
        else:
            data += KEEP_ALIVE_VERSION  # 使用常量

        data += KA2_FIXED_PART1
        data += KA2_FIXED_PART1_PADDING
        data += tail  # 使用传入的 tail
        data += KA2_TAIL_PADDING

    except Exception as e:
        logger.error(f"构建 KA2 包公共部分时出错: {e}", exc_info=True)
        return None

    # 构建类型特定部分 (specific_part) - 16字节
    try:
        if packet_type == 3:
            # Type 3: CRC(0) + Host IP + Padding(8)
            host_ip_bytes = socket.inet_aton(host_ip)
            specific_part = (
                KA2_TYPE3_CRC_DEFAULT + host_ip_bytes + KA2_TYPE3_PADDING_END
            )
        else:  # packet_type == 1
            # Type 1: Padding(16)
            specific_part = KA2_TYPE1_SPECIFIC_PART

        data += specific_part

    except socket.error:
        logger.error(f"构建 KA2 包失败：转换 host_ip '{host_ip}' 失败。")
        return None
    except Exception as e:
        logger.error(f"构建 KA2 包类型特定部分时出错: {e}", exc_info=True)
        return None

    logger.debug(f"构建的 Keep Alive 2 包: {data.hex()}")
    return data


def parse_keep_alive2_response(data: bytes) -> Optional[bytes]:
    """
    解析 Keep Alive 2 (07 包) 的响应。
    主要目的是提取新的 tail 值 (data[16:20])。

    Args:
        data: 收到的响应字节串。

    Returns:
        Optional[bytes]: 如果成功提取到 4 字节的 tail 则返回它，否则返回 None。
    """
    if not data:
        logger.warning("解析 Keep Alive 2 响应：收到空数据。")
        return None

    # 1. 检查响应 Code 是否为 0x07
    if not data.startswith(KEEP_ALIVE_RESP_CODE):  # b'\x07'
        logger.warning(f"Keep Alive 2 收到非预期的响应代码: {data[:1].hex()}。")
        return None

    # 2. 检查长度是否足够提取 tail (需要至少 20 字节)
    tail_start_index = 16  # Tail 开始索引
    tail_end_index = tail_start_index + 4  # Tail 结束索引
    if len(data) < tail_end_index:
        logger.warning(f"Keep Alive 2 响应包过短 (长度 {len(data)})，无法提取 Tail。")
        return None

    # 3. 提取 tail
    new_tail = data[tail_start_index:tail_end_index]
    logger.debug(f"从 Keep Alive 2 响应中提取到新的 Tail: {new_tail.hex()}")
    return new_tail
