# File: src/drcom_core/protocols/d_series/packets.py
"""
Dr.COM D系列协议封包构建器 (Packet Builders)

负责将 Python 数据结构转换为符合协议规范的二进制字节流 (bytes)。
本模块是无状态的 (Stateless)，不持有任何配置或会话信息。
"""

import secrets
import struct
import time
import logging

from ... import utils
from ...config import DrcomConfig
from . import constants

logger = logging.getLogger(__name__)

# =========================================================================
# Challenge (0x01)
# =========================================================================


def build_challenge_request(padding: bytes = b"\x00" * 15) -> bytes:
    """构建 Challenge 请求包 (0x01)。

    Args:
        padding: 填充字节，默认为 15 字节的 0x00。

    Returns:
        bytes: 构建好的 Challenge 请求包。
    """
    # 生成随机 Seed：使用当前时间戳 + 随机数，取模 0xFFFF
    rand_val = 0xF + secrets.randbelow(0xFF - 0xF + 1)
    t = time.time() + rand_val
    seed = struct.pack("<H", int(t) % 0xFFFF)

    # 结构: Code(0x0102) + Seed(2B) + Magic(0x09) + Padding(15B)
    return constants.Code.CHALLENGE_REQ + seed + b"\x09" + padding


def parse_challenge_response(data: bytes) -> bytes | None:
    """解析 Challenge 响应包 (0x02)，提取 Salt。

    Args:
        data: 接收到的 UDP 数据包。

    Returns:
        bytes | None: 如果包有效，返回 4 字节 Salt；否则返回 None。
    """
    # 1. 基础校验：非空且 Code 必须为 0x02
    if not data or not data.startswith(constants.Code.CHALLENGE_RESP):
        return None

    # 2. 长度校验：确保数据足够长，包含了 Salt 字段
    if len(data) < constants.SALT_OFFSET_END:
        return None

    # 3. 提取 Salt：位于偏移量 [4:8]
    salt = data[constants.SALT_OFFSET_START : constants.SALT_OFFSET_END]
    logger.debug("challenge_response: salt=%s", salt.hex())
    return salt


# =========================================================================
# Login (0x03)
# =========================================================================


def build_login_packet(config: DrcomConfig, salt: bytes) -> bytes:
    """构建 5.2.0(D) 标准登录数据包 (Login Request)。

    Args:
        config: 全局配置对象，包含用户名、密码、MAC等信息。
        salt: Challenge 阶段获取的随机盐值。

    Returns:
        bytes: 构建好的登录请求包。
    """
    try:
        # 从 config 提取必要参数
        username = config.username
        password = config.password
        mac_address = config.mac_address

        # 编码转换
        usr_bytes = username.encode("gbk", "strict")
        pwd_bytes = password.encode("gbk", "strict")
        hostname_bytes = config.host_name.encode("gbk", "ignore")
        hostos_bytes = config.host_os.encode("gbk", "ignore")
        mac_bytes = mac_address.to_bytes(6, byteorder="big")

        pkt = bytearray()

        # 1. Header (包头)
        pkt_len = 20 + len(usr_bytes)
        pkt.extend(constants.Code.LOGIN_REQ)
        pkt.append(0x00)
        pkt.append(pkt_len)

        # 2. MD5_A: 基础校验
        md5a = utils.md5_bytes(constants.MD5_SALT_PREFIX + salt + pwd_bytes)
        pkt.extend(md5a)

        # 3. Identity (身份信息)
        pkt.extend(usr_bytes.ljust(constants.USERNAME_MAX_LEN, b"\x00"))
        pkt.extend(config.control_check_status)
        pkt.extend(config.adapter_num)

        # 4. MAC XOR (MAC 地址混淆)
        xor_key = int.from_bytes(md5a[:6], byteorder="big")
        mac_xor = mac_address ^ xor_key
        pkt.extend(mac_xor.to_bytes(constants.LOGIN_MAC_XOR_LEN, byteorder="big"))

        # 5. MD5_B: 密码校验
        md5b_data = (
            constants.MD5B_SALT_PREFIX + pwd_bytes + salt + constants.MD5B_SALT_SUFFIX
        )
        pkt.extend(utils.md5_bytes(md5b_data))

        # 6. IP List & MD5_C (IP 信息校验)
        ip_section = bytearray()
        ip_section.append(0x01)
        ip_section.extend(config.host_ip_bytes)
        ip_section.extend(b"\x00" * 12)
        pkt.extend(ip_section)

        md5c = utils.md5_bytes(ip_section + constants.MD5C_SUFFIX)[
            : constants.LOGIN_MD5C_LEN
        ]
        pkt.extend(md5c)

        # 7. IPDOG (客户端监控位)
        pkt.extend(config.ipdog)
        pkt.extend(config.padding_after_ipdog)

        # 8. Host Info (主机网络信息)
        pkt.extend(hostname_bytes.ljust(constants.HOSTNAME_MAX_LEN, b"\x00"))
        pkt.extend(config.primary_dns_bytes)
        pkt.extend(config.dhcp_address_bytes)
        pkt.extend(config.secondary_dns_bytes)
        pkt.extend(config.padding_after_dhcp)

        # 9. OS Info (操作系统指纹)
        pkt.extend(config.os_info_bytes)
        pkt.extend(hostos_bytes.ljust(constants.HOST_OS_MAX_LEN, b"\x00"))
        pkt.extend(b"\x00" * constants.HOST_OS_SUFFIX_LEN)

        # 10. Version (协议版本)
        pkt.extend(config.auth_version)

        # 11. Checksum (整包 CRC 校验)
        checksum_input = pkt + constants.CHECKSUM_SUFFIX + mac_bytes
        checksum_val = utils.checksum_d_series(checksum_input)

        # 12. Auth Ext (扩展认证区)
        pkt.extend(constants.AUTH_EXT_CODE)
        pkt.extend(constants.AUTH_EXT_LEN)
        pkt.extend(checksum_val)
        pkt.extend(constants.AUTH_EXT_OPTION)
        pkt.extend(mac_bytes)

        # 13. Padding & Tail (尾部)
        pkt.extend(config.padding_auth_ext)
        # [Security] 使用 secrets 生成随机尾部
        pkt.extend(secrets.token_bytes(2))

        return bytes(pkt)
    except UnicodeEncodeError as e:
        from ...exceptions import ConfigError

        raise ConfigError(
            f"参数包含 Dr.COM 不支持的字符 (非 GBK): {e.object[e.start : e.end]}"
        ) from e


def parse_login_response(data: bytes) -> tuple[bool, bytes | None, int | None]:
    """解析登录响应数据包 (0x04/0x05)。

    Args:
        data: 接收到的 UDP 数据包。

    Returns:
        tuple[bool, bytes | None, int | None]:
            - success: 是否登录成功。
            - auth_info: 成功时返回 16 字节 Auth Info，否则为 None。
            - error_code: 失败时返回错误码 (int)，否则为 None。
    """
    if not data:
        return False, None, None

    code = data[0]
    # Case 1: 登录成功 (0x04)
    if code == constants.Code.LOGIN_RESP_SUCC:
        if len(data) >= constants.AUTH_INFO_END:
            auth = data[constants.AUTH_INFO_START : constants.AUTH_INFO_END]
            logger.debug("login_response: success auth_len=%d", len(auth))
            return True, auth, None

    # Case 2: 登录失败 (0x05)
    elif code == constants.Code.LOGIN_RESP_FAIL:
        # 提取错误码，通常位于 index 4
        err = (
            data[constants.ERROR_CODE_INDEX]
            if len(data) > constants.ERROR_CODE_INDEX
            else 0
        )
        logger.debug("login_response: fail code=%d", err)
        return False, None, err

    # Case 3: 未知响应
    logger.debug("login_response: unknown code=%d", code)
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
    """构建 Keep Alive 1 (0xFF) 数据包。

    Args:
        salt: Challenge 阶段的 Salt。
        password: 用户密码。
        auth_info: 登录成功后获取的 Auth Info。
        include_trailing_zeros: 是否包含尾部填充，默认为 True。

    Returns:
        bytes: 构建好的心跳包。
    """
    pwd_bytes = password.encode("gbk", "strict")

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
    """验证 KA1 响应。

    Args:
        data: 接收到的 UDP 数据包。

    Returns:
        bool: 如果响应是以 0x07 开头（MISC/KA2），则视为成功。
    """
    ok = bool(data and data.startswith(constants.Code.MISC))
    logger.debug("ka1_response: ok=%s", ok)
    return ok


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
) -> bytes:
    """构建 Keep Alive 2 (0x07) 数据包。

    Args:
        packet_number: 当前心跳序列号 (0-255)。
        tail: 上一次心跳响应返回的 Tail 签名。
        packet_type: 包类型 (1 或 3)。
        host_ip_bytes: 本机 IP 地址字节。
        keep_alive_version: 心跳版本号。
        is_first_packet: 是否为初始化阶段的首包。
        keep_alive2_flag: P版或变种协议使用的标志位。

    Returns:
        bytes: 构建好的心跳包。
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

    out = bytes(pkt)
    logger.debug(
        "ka2_build: num=%d type=%d is_first=%s tail=%s len=%d",
        packet_number,
        packet_type,
        is_first_packet,
        tail.hex(),
        len(out),
    )
    return out


def parse_keep_alive2_response(data: bytes) -> bytes | None:
    """解析 KA2 响应。

    Args:
        data: 接收到的 UDP 数据包。

    Returns:
        bytes | None: 如果包有效，返回 4 字节 Tail 用于下次请求；否则返回 None。
    """
    if not data or not data.startswith(constants.Code.MISC):
        return None
    if len(data) < 20:
        return None
    # Tail 位于 16:20
    tail = data[16:20]
    logger.debug("ka2_response: tail=%s", tail.hex())
    return tail


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
    """构建注销 (0x06) 数据包。

    Args:
        username: 用户名。
        password: 密码。
        salt: Challenge 阶段获取的 Salt (通常注销前需重新获取)。
        mac: MAC 地址整数。
        auth_info: 登录会话的鉴权信息。
        control_check_status: 控制位。
        adapter_num: 网卡数量/序号位。

    Returns:
        bytes: 构建好的注销请求包。
    """
    usr_bytes = username.encode("gbk", "strict")
    pwd_bytes = password.encode("gbk", "strict")

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
