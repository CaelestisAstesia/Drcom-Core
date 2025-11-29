# src/drcom_core/protocols/d_series/packets.py
"""
Dr.COM D系列协议封包构建器 (Packet Builders)

负责将 Python 数据结构转换为符合协议规范的二进制字节流 (bytes)。
本模块是无状态的 (Stateless)，不持有任何配置或会话信息。
"""

import secrets
import struct
import time
from typing import Optional

# 引用通用算法库
from ... import utils

# 引用配置结构体(类型提示)
from ...config import DrcomConfig

# 引用本族常量
from . import constants

# =========================================================================
# Challenge (0x01)
# =========================================================================


def build_challenge_request(padding: bytes = b"\x00" * 15) -> bytes:
    """
    构建 Challenge 请求包 (0x01)。

    向服务器申请 Salt (盐值) 的第一步交互。包内包含一个随机生成的 Seed。

    Args:
        padding (bytes, optional): 填充数据，通常为 15 字节的 0x00。默认为 b"\x00" * 15。

    Returns:
        bytes: 构建好的 0x01 请求包。
    """
    # 生成随机 Seed：使用当前时间戳 + 随机数，取模 0xFFFF
    rand_val = 0xF + secrets.randbelow(0xFF - 0xF + 1)
    t = time.time() + rand_val
    seed = struct.pack("<H", int(t) % 0xFFFF)

    # 结构: Code(0x0102) + Seed(2B) + Magic(0x09) + Padding(15B)
    return constants.Code.CHALLENGE_REQ + seed + b"\x09" + padding


def parse_challenge_response(data: bytes) -> Optional[bytes]:
    """
    解析 Challenge 响应包 (0x02)，提取 Salt。

    Args:
        data (bytes): 接收到的原始 UDP 数据包。

    Returns:
        Optional[bytes]: 成功提取则返回 4 字节 Salt，否则返回 None。
    """
    # 1. 基础校验：非空且 Code 必须为 0x02
    if not data or not data.startswith(constants.Code.CHALLENGE_RESP):
        return None

    # 2. 长度校验：确保数据足够长，包含了 Salt 字段
    if len(data) < constants.SALT_OFFSET_END:
        return None

    # 3. 提取 Salt：位于偏移量 [4:8]
    return data[constants.SALT_OFFSET_START : constants.SALT_OFFSET_END]


# =========================================================================
# Login (0x03)
# =========================================================================


def build_login_packet(config: DrcomConfig, salt: bytes) -> bytes:
    """
    构建 5.2.0(D) 标准登录数据包 (Login Request)。

    这是整个协议中最复杂的包，包含多段 MD5 校验和 CRC 校验。

    Args:
        config (DrcomConfig): 配置对象，包含所有必要的登录参数。包含以下：
            username (str): 用户名。
            password (str): 密码。
            salt (bytes): Challenge 阶段获取的 4 字节盐值。
            mac_address (int): 本机 MAC 地址 (整数形式)。
            host_ip_bytes (bytes): 本机 IP 地址 (4字节)。
            primary_dns_bytes (bytes): 主 DNS (4字节)。
            dhcp_server_bytes (bytes): DHCP 服务器地址 (4字节)。
            secondary_dns_bytes (bytes): 次 DNS (4字节)。
            host_name (str): 主机名。
            host_os (str): 操作系统名称。
            os_info_bytes (bytes): 操作系统详细信息指纹 (Hex)。
            control_check_status (bytes): 客户端校验控制位。
            adapter_num (bytes): 网卡数量/序号。
            ipdog (bytes): IPDog 开关位。
            auth_version (bytes): 协议版本号 (如 \x2c\x00)。
            padding_after_ipdog (bytes): IPDog 后的填充位。
            padding_after_dhcp (bytes): DHCP 信息后的填充位。
            padding_auth_ext (bytes): 扩展认证区的填充位。
            ror_enabled (bool, optional): 是否启用 ROR 算法 (预留，当前未使用)。

    Returns:
        bytes: 构建好的登录数据包。
    """
    # 从 config 提取必要参数
    username = config.username
    password = config.password
    mac_address = config.mac_address

    # 编码转换
    usr_bytes = username.encode("gbk", "ignore")
    pwd_bytes = password.encode("gbk", "ignore")
    hostname_bytes = config.host_name.encode("gbk", "ignore")
    hostos_bytes = config.host_os.encode("gbk", "ignore")
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
    pkt.extend(config.control_check_status)
    pkt.extend(config.adapter_num)

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
    ip_section.append(0x01)
    ip_section.extend(config.host_ip_bytes)
    ip_section.extend(b"\x00" * 12)
    pkt.extend(ip_section)

    md5c = utils.md5_bytes(ip_section + constants.MD5C_SUFFIX)[
        : constants.LOGIN_MD5C_LEN
    ]
    pkt.extend(md5c)

    # 7. IPDOG
    pkt.extend(config.ipdog)
    pkt.extend(config.padding_after_ipdog)

    # 8. Host Info
    pkt.extend(hostname_bytes.ljust(constants.HOSTNAME_MAX_LEN, b"\x00"))
    pkt.extend(config.primary_dns_bytes)
    pkt.extend(config.dhcp_address_bytes)
    pkt.extend(config.secondary_dns_bytes)
    pkt.extend(config.padding_after_dhcp)

    # 9. OS Info
    pkt.extend(config.os_info_bytes)
    pkt.extend(hostos_bytes.ljust(constants.HOST_OS_MAX_LEN, b"\x00"))
    pkt.extend(b"\x00" * constants.HOST_OS_SUFFIX_LEN)

    # 10. Version
    pkt.extend(config.auth_version)

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
    pkt.extend(config.padding_auth_ext)
    # [修改] 使用 secrets 生成随机尾部
    pkt.extend(secrets.token_bytes(2))

    return bytes(pkt)


def parse_login_response(data: bytes) -> tuple[bool, bytes | None, int | None]:
    """
    解析登录响应数据包 (0x04/0x05)。

    Args:
        data (bytes): 接收到的 UDP 数据。

    Returns:
        tuple[bool, bytes | None, int | None]:
            - success (bool): 登录是否成功。
            - auth_info (bytes | None): 成功时返回 16 字节 Auth Info (用于心跳)，失败为 None。
            - error_code (int | None): 失败时返回错误码 (如 0x03 密码错误)，成功为 None。
    """
    if not data:
        return False, None, None

    code = data[0]
    # Case 1: 登录成功 (0x04)
    if code == constants.Code.LOGIN_RESP_SUCC:
        if len(data) >= constants.AUTH_INFO_END:
            # 提取 Auth Info，通常位于 [23:39]
            return True, data[constants.AUTH_INFO_START : constants.AUTH_INFO_END], None

    # Case 2: 登录失败 (0x05)
    elif code == constants.Code.LOGIN_RESP_FAIL:
        # 提取错误码，通常位于 index 4
        err = (
            data[constants.ERROR_CODE_INDEX]
            if len(data) > constants.ERROR_CODE_INDEX
            else 0
        )
        return False, None, err

    # Case 3: 未知响应
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

    这是登录成功后的第一个心跳包，用于验证 Session 有效性。

    Args:
        salt (bytes): 之前获取的 Salt。
        password (str): 密码。
        auth_info (bytes): 登录响应中获取的 16 字节 Auth Info。
        include_trailing_zeros (bool, optional): 是否在末尾包含 4 字节的 0x00 填充。默认为 True。

    Returns:
        bytes: 构建好的 0xFF 心跳包。
    """
    pwd_bytes = password.encode("gbk", "ignore")

    # MD5(0x03 0x01 + Salt + Pwd)
    md5_hash = utils.md5_bytes(constants.MD5_SALT_PREFIX + salt + pwd_bytes)

    # 随机时间戳 (2字节，Big Endian)
    timestamp = struct.pack("!H", int(time.time()) % 0xFFFF)

    pkt = bytearray()
    # Header: 0xFF
    pkt.extend(constants.Code.KEEP_ALIVE_1)
    pkt.extend(md5_hash)
    pkt.extend(b"\x00\x00\x00")  # Padding
    pkt.extend(auth_info)
    pkt.extend(timestamp)

    if include_trailing_zeros:
        pkt.extend(b"\x00" * 4)

    return bytes(pkt)


def parse_keep_alive1_response(data: bytes) -> bool:
    """
    验证 KA1 响应。

    期望收到以 0x07 (Code.MISC) 开头的包。

    Args:
        data (bytes): 接收到的数据。

    Returns:
        bool: 是否为有效的 KA1 响应。
    """
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

    用于维持在线状态，包含序列号 (Sequence Number) 和 尾部签名 (Tail)。

    Args:
        packet_number (int): 当前心跳序列号 (0-255 循环)。
        tail (bytes): 上一次心跳响应中提取的 4 字节 Tail。
        packet_type (int): 包类型。1=基础保活, 3=包含IP信息。
        host_ip_bytes (bytes): 本机 IP。
        keep_alive_version (bytes): 心跳版本号 (如 \xdc\x02)。
        is_first_packet (bool, optional): 是否为初始化阶段的首包 (使用特殊 Magic)。
        keep_alive2_flag (bytes, optional): P版或变种协议的 Flag 标志位。

    Returns:
        bytes: 构建好的 0x07 心跳包。
    """
    pkt = bytearray()

    # Header: 07 + Num + 28 00 0B + Type
    pkt.extend(constants.Code.MISC)
    pkt.append(packet_number)
    pkt.extend(constants.KA2_HEADER_PREFIX)
    pkt.append(packet_type)

    # Version / Flag 字段
    if is_first_packet:
        pkt.extend(b"\x0f\x27")  # Init Magic (初始化魔法数)
    else:
        pkt.extend(keep_alive_version)

    # Fixed Part: 2f 12 + 00*6
    pkt.extend(constants.KA2_FIXED_PART1)
    pkt.extend(b"\x00" * 6)

    # Tail (循环更新的签名)
    pkt.extend(tail)
    pkt.extend(b"\x00" * 4)  # Padding after tail

    # Specific Part (根据类型区分)
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
    """
    解析 KA2 响应，提取下一次心跳所需的 Tail。

    Args:
        data (bytes): 接收到的数据。

    Returns:
        Optional[bytes]: 成功则返回 4 字节 Tail (偏移量 16:20)，否则返回 None。
    """
    if not data or not data.startswith(constants.Code.MISC):
        return None
    if len(data) < 20:
        return None
    # Tail 位于 16:20
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

    Args:
        username (str): 用户名。
        password (str): 密码。
        salt (bytes): 申请到的新 Salt (通常注销前需重新 Challenge)。
        mac (int): MAC 地址 (整数)。
        auth_info (bytes): 登录时的 Auth Info。
        control_check_status (bytes): 控制位。
        adapter_num (bytes): 网卡序号。

    Returns:
        bytes: 构建好的注销包。
    """
    usr_bytes = username.encode("gbk", "ignore")
    pwd_bytes = password.encode("gbk", "ignore")

    pkt = bytearray()

    # Header
    # 结构: Code(0x06) + Type(0x01) + 0x00 + Length
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
