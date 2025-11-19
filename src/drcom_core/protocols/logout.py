# src/drcom_core/protocols/logout.py
"""
处理 Dr.COM D 版登出 (Code 0x06) 请求包的构建以及响应的解析。
本模块只负责包的构建和解析，不执行网络 I/O。
"""

import hashlib
import logging
from typing import Optional, Tuple

from ..exceptions import ProtocolError
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
    logger.debug("开始构建登出数据包...")

    # 参数校验
    if not auth_info or len(auth_info) != constants.AUTH_INFO_LENGTH:
        raise ProtocolError(
            f"无效的 Auth Info (Tail)，长度应为 {constants.AUTH_INFO_LENGTH}。"
        )
    if not salt or len(salt) != 4:
        raise ProtocolError("无效的 Salt，长度应为 4。")

    # 编码转换
    try:
        username_bytes = username.encode("utf-8", "ignore")
        password_bytes = password.encode("utf-8", "ignore")
    except Exception as e:
        raise ProtocolError(f"用户名或密码编码失败: {e}") from e

    packet = b""

    # 1. 包头和长度
    pkt_len = len(username_bytes) + constants.LOGIN_PACKET_LENGTH_OFFSET
    header = (
        constants.LOGOUT_REQ_CODE + constants.LOGOUT_TYPE + b"\x00" + bytes([pkt_len])
    )
    packet += header

    # 2. MD5_A (基于新 Salt)
    md5a_data = constants.MD5_SALT_PREFIX + salt + password_bytes
    md5a = hashlib.md5(md5a_data).digest()
    packet += md5a

    # 3. 用户名
    packet += username_bytes.ljust(constants.USERNAME_PADDING_LENGTH, b"\x00")

    # 4. ControlStatus & AdapterNum
    packet += control_check_status
    packet += adapter_num

    # 5. MAC 地址异或
    mac_xor_md5_part = md5a[: constants.MAC_XOR_PADDING_LENGTH]
    try:
        md5_part_int = int.from_bytes(mac_xor_md5_part, byteorder="big")
        xor_result = md5_part_int ^ mac
        xor_bytes = xor_result.to_bytes(
            constants.MAC_XOR_PADDING_LENGTH, byteorder="big"
        )
        packet += xor_bytes
    except Exception as e:
        logger.error(f"MAC 地址异或计算失败: {e}", exc_info=True)
        # 为了尝试登出，这里做降级处理：填充0
        packet += b"\x00" * constants.MAC_XOR_PADDING_LENGTH

    # 6. Auth Info (Tail)
    packet += auth_info

    return packet


def parse_logout_response(
    response_data: Optional[bytes],
    expected_server_ip: str,
    received_from_ip: Optional[str],
) -> Tuple[bool, str]:
    """
    解析 Dr.COM 服务器返回的登出响应包。
    """
    # 情况 1: 未收到响应
    if not response_data:
        return True, "未收到响应 (正常情况，视为尝试登出成功)"

    # 情况 2: 收到响应，但来源 IP 不对
    if not received_from_ip or received_from_ip != expected_server_ip:
        msg = f"收到来源不匹配的登出响应 (来自: {received_from_ip})"
        logger.warning(msg)
        return False, msg

    # 情况 3: 收到来自正确服务器的响应
    response_code = response_data[0]
    if response_code == constants.SUCCESS_RESP_CODE:  # 0x04
        return True, "服务器确认登出成功 (0x04)"
    else:
        msg = f"收到来自服务器的非预期登出响应代码: {hex(response_code)}"
        logger.warning(msg)
        return False, msg
