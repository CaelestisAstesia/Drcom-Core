# src/drcom_core/protocols/challenge.py
import logging
import random
import struct
import time
from typing import Optional

from .constants import ChallengeConst, PacketCode

logger = logging.getLogger(__name__)


def build_challenge_request() -> bytes:
    """构建 Challenge 请求包 (Code 0x01)。"""
    random_seed: float = time.time() + random.randint(0xF, 0xFF)
    random_bytes: bytes = struct.pack("<H", int(random_seed) % 0xFFFF)

    challenge_packet: bytes = (
        PacketCode.CHALLENGE_REQ
        + random_bytes
        + ChallengeConst.REQ_SUFFIX
        + b"\x00" * ChallengeConst.REQ_PADDING_LEN
    )
    return challenge_packet


def parse_challenge_response(data: bytes) -> Optional[bytes]:
    """解析 Challenge 响应包。"""
    if not data:
        return None

    if not data.startswith(PacketCode.CHALLENGE_RESP):
        logger.debug(f"Challenge 响应 Code 不匹配: {data[:1].hex()}")
        return None

    if len(data) < ChallengeConst.SALT_END:
        logger.debug("Challenge 响应长度不足，无法提取 Salt。")
        return None

    salt = data[ChallengeConst.SALT_START : ChallengeConst.SALT_END]
    return salt
