# src/drcom_core/drcom_protocol/challenge.py
"""
处理 Dr.COM 认证过程中的 Challenge 请求与响应 (Code 0x01, 0x02)。
本模块只负责包的构建和解析。
"""

import logging
import random
import struct
import time
from typing import Optional

from . import constants

logger = logging.getLogger(__name__)


def build_challenge_request() -> bytes:
    """
    构建 Challenge 请求包 (Code 0x01)。

    Returns:
        bytes: 构建完成的 Challenge 请求包。
    """
    logger.debug("构建 Challenge 请求包...")
    try:
        # 1. 生成随机数种子
        random_seed: float = time.time() + random.randint(0xF, 0xFF)
        # 2. 打包为 2 字节小端序 (<H)
        random_bytes: bytes = struct.pack("<H", int(random_seed) % 0xFFFF)

        # 3. 构建 Challenge 请求包
        challenge_packet: bytes = (
            constants.CHALLENGE_REQ_CODE  # b'\x01\x02'
            + random_bytes  # 2 bytes
            + constants.CHALLENGE_REQ_SUFFIX  # b'\x09'
            + b"\x00" * constants.CHALLENGE_REQ_PADDING_LENGTH  # 15 bytes
        )
        logger.debug(f"构建的 Challenge 请求包: {challenge_packet.hex()}")
        return challenge_packet

    except Exception as e:
        logger.error(f"构建 Challenge 请求时发生意外错误: {e}", exc_info=True)
        # 在这种简单构建中很难出错，但以防万一
        raise ValueError("构建 Challenge 包失败") from e


def parse_challenge_response(data: bytes) -> Optional[bytes]:
    """
    解析来自 Dr.COM 服务器的 Challenge 响应包 (Code 0x02)。

    Args:
        data: 从网络接收到的原始响应字节串。

    Returns:
        Optional[bytes]: 成功解析则为 4 字节的 salt，否则为 None。
    """
    logger.debug("解析 Challenge 响应...")

    # 1. 验证响应代码
    if not data.startswith(constants.CHALLENGE_RESP_CODE):  # b'\x02'
        logger.warning(
            f"收到的响应包 Code 不正确 "
            f"(期望: {constants.CHALLENGE_RESP_CODE.hex()}，"
            f"实际: {data[:1].hex()})。"
        )
        return None

    # 2. 验证响应包长度是否足够提取 salt
    if len(data) < constants.SALT_END_INDEX:
        logger.warning(
            f"收到的 Challenge 响应包过短 (长度 {len(data)})，无法提取 Salt "
            f"(需要至少 {constants.SALT_END_INDEX} 字节)。"
        )
        return None

    # 3. 提取 Salt
    salt = data[constants.SALT_START_INDEX : constants.SALT_END_INDEX]
    logger.debug(f"成功从响应中提取 Salt: {salt.hex()}")
    return salt
