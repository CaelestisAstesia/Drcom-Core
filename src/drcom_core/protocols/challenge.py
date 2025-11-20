# src/drcom_core/protocols/challenge.py
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
    """
    # 1. 生成随机数种子
    random_seed: float = time.time() + random.randint(0xF, 0xFF)
    # 2. 打包为 2 字节小端序 (<H)
    random_bytes: bytes = struct.pack("<H", int(random_seed) % 0xFFFF)

    # 3. 构建 Challenge 请求包
    challenge_packet: bytes = (
        constants.CHALLENGE_REQ_CODE
        + random_bytes
        + constants.CHALLENGE_REQ_SUFFIX
        + b"\x00" * constants.CHALLENGE_REQ_PADDING_LENGTH
    )
    return challenge_packet


def parse_challenge_response(data: bytes) -> Optional[bytes]:
    """
    解析 Challenge 响应包。

    这是数据进入系统的"关口"，必须在此处检查数据的合法性。
    一旦此函数成功返回 bytes，上层逻辑应视为该数据已通过验证 (Trusted)。
    """
    if not data:
        return None

    # 1. 协议代码检查
    if not data.startswith(constants.CHALLENGE_RESP_CODE):
        logger.debug(f"Challenge 响应 Code 不匹配: {data[:1].hex()}")
        return None

    # 2. 长度检查 (确保有足够的字节提取 Salt)
    if len(data) < constants.SALT_END_INDEX:
        logger.debug("Challenge 响应长度不足，无法提取 Salt。")
        return None

    # 3. 提取 Salt
    # 此时提取出的 4 字节数据即为清洗后的可信数据
    salt = data[constants.SALT_START_INDEX : constants.SALT_END_INDEX]
    return salt
