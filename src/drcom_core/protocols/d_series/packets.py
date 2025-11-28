# src/drcom_core/protocols/d_series/packets.py
"""
Dr.COM D系列协议封包构建器 (Packet Builders)

负责将 Python 数据结构转换为符合协议规范的二进制字节流 (bytes)。
本模块是无状态的 (Stateless)，不持有任何配置或会话信息。
"""

import random
import struct
import time
from typing import Optional

# 引用通用算法库
from ... import utils

# 引用本族常量
from . import constants

# =========================================================================
# Challenge (0x01)
# =========================================================================


def build_challenge_request(padding: bytes = b"\x00" * 15) -> bytes:
    """
    构建 Challenge 请求包 (0x01)。
    """
    t = time.time() + random.randint(0xF, 0xFF)
    seed = struct.pack("<H", int(t) % 0xFFFF)
    return constants.Code.CHALLENGE_REQ + seed + b"\x09" + padding


def parse_challenge_response(data: bytes) -> Optional[bytes]:
    """
    解析 Challenge 响应包 (0x02)，提取 Salt。
    """
    if not data or not data.startswith(constants.Code.CHALLENGE_RESP):
        return None
    if len(data) < constants.SALT_OFFSET_END:
        return None
    return data[constants.SALT_OFFSET_START : constants.SALT_OFFSET_END]


# =========================================================================
# Login (0x03)
# =========================================================================


def build_login_packet(
    username: str,
    password: str,
    salt: bytes,
    mac_address: int,
    host_ip_bytes: bytes,
    primary_dns_bytes: bytes,
    dhcp_server_bytes: bytes,
    secondary_dns_bytes: bytes,
    host_name: str,
    host_os: str,
    os_info_bytes: bytes,
    control_check_status: bytes,
    adapter_num: bytes,
    ipdog: bytes,
    auth_version: bytes,
    padding_after_ipdog: bytes,
    padding_after_dhcp: bytes,
    padding_auth_ext: bytes,
    ror_enabled: bool = False,
) -> bytes:
    """构建 5.2.0(D) 标准登录数据包。"""
    usr_bytes = username.encode("gbk", "ignore")
    pwd_bytes = password.encode("gbk", "ignore")
    hostname_bytes = host_name.encode("gbk", "ignore")
    hostos_bytes = host_os.encode("gbk", "ignore")
    mac_bytes = mac_address.to_bytes(6, byteorder="big")

    pkt = bytearray()

    # 1. Header
    pkt_len = 20 + len(usr_bytes)
    pkt.extend(constants.Code.LOGIN_REQ)
    pkt.append(0x00)
    pkt.append(pkt_len)

    # 2. MD5_A
    md5a = utils.md5_bytes(constants.MD5_SALT_PREFIX + salt + pwd_bytes)
    pkt.extend(md5a)

    # 3. Identity
    pkt.extend(usr_bytes.ljust(constants.USERNAME_MAX_LEN, b"\x00"))
    pkt.extend(control_check_status)
    pkt.extend(adapter_num)

    # 4. MAC XOR
    xor_key = int.from_bytes(md5a[:6], byteorder="big")
    mac_xor = mac_address ^ xor_key
    pkt.extend(mac_xor.to_bytes(constants.LOGIN_MAC_XOR_LEN, byteorder="big"))

    # 5. MD5_B
    md5b_data = (
        constants.MD5B_SALT_PREFIX + pwd_bytes + salt + constants.MD5B_SALT_SUFFIX
    )
    pkt.extend(utils.md5_bytes(md5b_data))

    # 6. IP List & MD5_C
    ip_section = bytearray()
    ip_section.append(0x01)  # IP Count
    ip_section.extend(host_ip_bytes)
    ip_section.extend(b"\x00" * 12)
    pkt.extend(ip_section)

    md5c = utils.md5_bytes(ip_section + constants.MD5C_SUFFIX)[
        : constants.LOGIN_MD5C_LEN
    ]
    pkt.extend(md5c)

    # 7. IPDOG
    pkt.extend(ipdog)
    pkt.extend(padding_after_ipdog)

    # 8. Host Info
    pkt.extend(hostname_bytes.ljust(constants.HOSTNAME_MAX_LEN, b"\x00"))
    pkt.extend(primary_dns_bytes)
    pkt.extend(dhcp_server_bytes)
    pkt.extend(secondary_dns_bytes)
    pkt.extend(padding_after_dhcp)

    # 9. OS Info
    pkt.extend(os_info_bytes)
    pkt.extend(hostos_bytes.ljust(constants.HOST_OS_MAX_LEN, b"\x00"))
    pkt.extend(b"\x00" * constants.HOST_OS_SUFFIX_LEN)

    # 10. Version
    pkt.extend(auth_version)

    # 11. Checksum
    checksum_input = pkt + constants.CHECKSUM_SUFFIX + mac_bytes
    checksum_val = utils.checksum_d_series(checksum_input)

    # 12. Auth Ext
    pkt.extend(constants.AUTH_EXT_CODE)
    pkt.extend(constants.AUTH_EXT_LEN)
    pkt.extend(checksum_val)
    pkt.extend(constants.AUTH_EXT_OPTION)
    pkt.extend(mac_bytes)

    # 13. Padding & Tail
    pkt.extend(padding_auth_ext)
    pkt.extend(random.randbytes(2))

    return bytes(pkt)


def parse_login_response(data: bytes) -> tuple[bool, bytes | None, int | None]:
    """解析登录响应 (0x04/0x05)"""
    if not data:
        return False, None, None

    code = data[0]
    if code == constants.Code.LOGIN_RESP_SUCC:
        if len(data) >= constants.AUTH_INFO_END:
            return True, data[constants.AUTH_INFO_START : constants.AUTH_INFO_END], None
    elif code == constants.Code.LOGIN_RESP_FAIL:
        err = (
            data[constants.ERROR_CODE_INDEX]
            if len(data) > constants.ERROR_CODE_INDEX
            else 0
        )
        return False, None, err

    return False, None, None


# =========================================================================
# Keep Alive 1 (0xFF)
# =========================================================================


def build_keep_alive1_packet(
    salt: bytes,
    password: str,
    auth_info: bytes,
    include_trailing_zeros: bool = True,
) -> bytes:
    """
    构建 Keep Alive 1 (0xFF) 数据包。
    """
    pwd_bytes = password.encode("gbk", "ignore")

    # MD5(0x03 0x01 + Salt + Pwd)
    md5_hash = utils.md5_bytes(constants.MD5_SALT_PREFIX + salt + pwd_bytes)

    # 随机时间戳 (2字节)
    timestamp = struct.pack("!H", int(time.time()) % 0xFFFF)

    pkt = bytearray()
    pkt.extend(constants.Code.KEEP_ALIVE_1)
    pkt.extend(md5_hash)
    pkt.extend(b"\x00\x00\x00")  # Padding
    pkt.extend(auth_info)
    pkt.extend(timestamp)

    if include_trailing_zeros:
        pkt.extend(b"\x00" * 4)

    return bytes(pkt)


def parse_keep_alive1_response(data: bytes) -> bool:
    """验证 KA1 响应 (应为 0x07 开头)"""
    return bool(data and data.startswith(constants.Code.MISC))


# =========================================================================
# Keep Alive 2 (0x07)
# =========================================================================


def build_keep_alive2_packet(
    packet_number: int,
    tail: bytes,
    packet_type: int,
    host_ip_bytes: bytes,
    keep_alive_version: bytes,
    is_first_packet: bool = False,
    keep_alive2_flag: bytes = b"\xdc",  # P版/变种 Flag
) -> bytes:
    """
    构建 Keep Alive 2 (0x07) 数据包。
    """
    pkt = bytearray()

    # Header: 07 + Num + 28 00 0B + Type
    pkt.extend(constants.Code.MISC)
    pkt.append(packet_number)
    pkt.extend(constants.KA2_HEADER_PREFIX)
    pkt.append(packet_type)

    # Version / Flag
    if is_first_packet:
        pkt.extend(b"\x0f\x27")  # Init Magic
    else:
        pkt.extend(keep_alive_version)

    # Fixed Part: 2f 12 + 00*6
    pkt.extend(constants.KA2_FIXED_PART1)
    pkt.extend(b"\x00" * 6)

    # Tail
    pkt.extend(tail)
    pkt.extend(b"\x00" * 4)  # Padding after tail

    # Specific Part
    if packet_type == 3:
        # Type 3: CRC(00*4) + IP + Padding(00*8)
        pkt.extend(b"\x00" * 4)
        pkt.extend(host_ip_bytes)
        pkt.extend(b"\x00" * 8)
    else:
        # Type 1: Padding(00*16)
        pkt.extend(b"\x00" * 16)

    return bytes(pkt)


def parse_keep_alive2_response(data: bytes) -> Optional[bytes]:
    """提取 KA2 响应中的 Tail (16:20)"""
    if not data or not data.startswith(constants.Code.MISC):
        return None
    if len(data) < 20:
        return None
    return data[16:20]


# =========================================================================
# Logout (0x06)
# =========================================================================


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
    构建注销 (0x06) 数据包。
    """
    usr_bytes = username.encode("gbk", "ignore")
    pwd_bytes = password.encode("gbk", "ignore")

    pkt = bytearray()

    # Header
    pkt_len = 20 + len(usr_bytes)
    pkt.extend(constants.Code.LOGOUT_REQ)
    pkt.extend(constants.Code.LOGOUT_TYPE)
    pkt.append(0x00)
    pkt.append(pkt_len)

    # MD5 (03 01 + Salt + Pwd)
    md5a = utils.md5_bytes(constants.MD5_SALT_PREFIX + salt + pwd_bytes)
    pkt.extend(md5a)

    # Identity
    pkt.extend(usr_bytes.ljust(constants.USERNAME_MAX_LEN, b"\x00"))
    pkt.extend(control_check_status)
    pkt.extend(adapter_num)

    # MAC XOR
    xor_key = int.from_bytes(md5a[:6], byteorder="big")
    mac_xor = mac ^ xor_key
    pkt.extend(mac_xor.to_bytes(constants.LOGIN_MAC_XOR_LEN, byteorder="big"))

    # Auth Info
    pkt.extend(auth_info)

    return bytes(pkt)
