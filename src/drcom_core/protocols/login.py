# src/drcom_core/protocols/login.py
"""
处理 Dr.COM D 版登录认证 (Code 0x03) 请求包的构建与解析。

本模块实现了协议中最核心的身份验证握手逻辑。
"""

import hashlib
import logging
import random
import struct

from ..exceptions import AuthErrorCode
from . import constants

logger = logging.getLogger(__name__)


def _calculate_checksum(data: bytes) -> bytes:
    """
    计算 Dr.COM 协议专用的 4 字节校验和 (Checksum)。

    算法逻辑：
    1. 对数据进行 4 字节对齐（末尾补零）。
    2. 按 4 字节一组进行异或 (XOR) 累加。
    3. 结果乘以魔数 1968 并截断为 32 位。

    Args:
        data: 需要计算校验和的原始字节流。

    Returns:
        bytes: 4 字节的小端序校验和。
    """
    ret = constants.CHECKSUM2_INIT_VALUE
    padded_data = data + b"\x00" * (-(len(data)) % 4)

    for i in range(0, len(padded_data), 4):
        chunk = padded_data[i : i + 4]
        val = struct.unpack("<I", chunk)[0]
        ret ^= val

    ret = (constants.CHECKSUM2_MULTIPLIER * ret) & 0xFFFFFFFF
    return struct.pack("<I", ret)


def build_login_packet(
    username: str,
    password: str,
    salt: bytes,
    mac_address: int,
    # --- 网络配置 ---
    host_ip_bytes: bytes,
    primary_dns_bytes: bytes,
    dhcp_server_bytes: bytes,
    # --- 身份标识 ---
    host_name: str,
    host_os: str,
    os_info_bytes: bytes,
    adapter_num: bytes,
    ipdog: bytes,
    auth_version: bytes,
    control_check_status: bytes,
    # --- 策略开关 ---
    ror_status: bool,
) -> bytes:
    """
    构建 Dr.COM D 版 (Code 0x03) 登录请求包。

    此函数负责将身份凭据、网络环境指纹和主机特征打包成符合 5.2.0(D) 协议规范的字节流。
    包含多重 MD5 哈希和异或加密逻辑。

    Args:
        username (str): 用户账户名。
        password (str): 用户密码。
        salt (bytes): 从 Challenge 响应中获取的 4 字节随机盐值。
        mac_address (int): 本机网卡 MAC 地址的整数表示 (e.g. 0xAABBCCDDEEFF)。

        host_ip_bytes (bytes): 4 字节本机 IP (Network Byte Order)。
        primary_dns_bytes (bytes): 4 字节主 DNS (Network Byte Order)。
        dhcp_server_bytes (bytes): 4 字节 DHCP/网关 IP (Network Byte Order)。

        host_name (str): 主机名 (将被截断或填充至 32 字节)。
        host_os (str): 操作系统标识字符串 (将被截断或填充至 32 字节)。
        os_info_bytes (bytes): 系统内核指纹 (通常为 20 字节 Hex 转 Bytes)。
                            这通常是校验最严格的部分。

        adapter_num (bytes): 1 字节网卡序号 (e.g. b'\\x01')。
        ipdog (bytes): 1 字节 IPDOG 标志位。
        auth_version (bytes): 2 字节协议版本号 (e.g. b'\\x2c\\x00')。
        control_check_status (bytes): 1 字节控制位状态 (e.g. b'\\x20')。

        ror_status (bool): 是否启用 ROR 防重放 (目前仅预留，建议 False)。

    Returns:
        bytes: 完整的登录请求数据包。
    """
    usr_bytes = username.encode("utf-8", "ignore")
    pwd_bytes = password.encode("utf-8", "ignore")
    hostname_bytes = host_name.encode("utf-8", "ignore")
    hostos_bytes = host_os.encode("utf-8", "ignore")

    data = b""

    packet_len = len(usr_bytes) + constants.LOGIN_PACKET_LENGTH_OFFSET
    header = constants.LOGIN_REQ_CODE + b"\x00" + bytes([packet_len])
    data += header

    md5a_data = constants.MD5_SALT_PREFIX + salt + pwd_bytes
    md5a = hashlib.md5(md5a_data).digest()
    data += md5a

    data += usr_bytes.ljust(constants.USERNAME_PADDING_LENGTH, b"\x00")
    data += control_check_status
    data += adapter_num

    mac_xor_key = int.from_bytes(md5a[:6], byteorder="big")
    xor_result = mac_xor_key ^ mac_address
    data += xor_result.to_bytes(6, byteorder="big")

    md5b_input = (
        constants.MD5B_SALT_PREFIX + pwd_bytes + salt + constants.MD5B_SALT_SUFFIX
    )
    md5b = hashlib.md5(md5b_input).digest()
    data += md5b

    data += b"\x01"
    data += host_ip_bytes
    data += b"\x00" * constants.IP_ADDR_PADDING_LENGTH

    md5c_input = data + constants.MD5C_SUFFIX
    md5c = hashlib.md5(md5c_input).digest()[: constants.CHECKSUM1_LENGTH]
    data += md5c

    data += ipdog
    data += constants.IPDOG_SEPARATOR

    data += hostname_bytes.ljust(constants.HOSTNAME_PADDING_LENGTH, b"\x00")
    data += primary_dns_bytes
    data += dhcp_server_bytes
    data += constants.SECONDARY_DNS_PADDING
    data += constants.WINS_SERVER_PADDING

    data += os_info_bytes

    data += hostos_bytes.ljust(constants.HOSTOS_PADDING_LENGTH, b"\x00")
    data += b"\x00" * constants.HOSTOS_PADDING_SUFFIX_LENGTH
    data += auth_version

    if ror_status:
        logger.warning("ROR 模式已启用但尚未实现。")

    mac_bytes = mac_address.to_bytes(6, byteorder="big")
    checksum2_input = data + constants.CHECKSUM2_SUFFIX + mac_bytes
    checksum2 = _calculate_checksum(checksum2_input)

    data += constants.AUTH_EXT_DATA_CODE
    data += constants.AUTH_EXT_DATA_LEN
    data += checksum2
    data += constants.AUTH_EXT_DATA_OPTION
    data += mac_bytes

    if not ror_status:
        data += constants.AUTO_LOGOUT_PADDING
        data += constants.BROADCAST_MODE_PADDING

    rand_tail = random.randbytes(2)
    data += rand_tail

    return data


def parse_login_response(
    response_data: bytes, expected_server_ip: str, received_from_ip: str
) -> tuple[bool, bytes | None, int | None, str]:
    """
    解析登录响应包 (Code 0x04 或 0x05)。

    Args:
        response_data (bytes): 接收到的原始 UDP 数据包。
        expected_server_ip (str): 配置中指定的认证服务器 IP。
        received_from_ip (str): 实际发送该包的来源 IP (用于防欺骗检查)。

    Returns:
        tuple: 包含以下四个元素的元组:
            - success (bool): 登录是否成功 (Code 0x04)。
            - auth_info (bytes | None): 成功时返回 16 字节 Token，失败为 None。
            - error_code (int | None): 失败时返回原始错误码 (如 0x03)，成功为 None。
            - message (str): 人类可读的结果描述 (包含中文错误映射)。
    """
    if not response_data:
        return False, None, None, "未收到数据"

    if received_from_ip != expected_server_ip:
        return (
            False,
            None,
            None,
            f"来源 IP 不匹配 (期望 {expected_server_ip}, 实际 {received_from_ip})",
        )

    code = response_data[0]

    if code == constants.LOGIN_RESP_SUCCESS_CODE:
        if len(response_data) < constants.AUTH_INFO_END_INDEX:
            return False, None, None, "响应包长度不足"

        auth_info = response_data[
            constants.AUTH_INFO_START_INDEX : constants.AUTH_INFO_END_INDEX
        ]
        return True, auth_info, None, "登录成功"

    elif code == constants.LOGIN_RESP_FAIL_CODE:
        error_code = None
        if len(response_data) > constants.ERROR_CODE_INDEX:
            error_code = response_data[constants.ERROR_CODE_INDEX]

        err_msg = "未知错误"

        if error_code is not None:
            try:
                e_enum = AuthErrorCode(error_code)
                match e_enum:
                    case AuthErrorCode.IN_USE:
                        err_msg = "账号在线或MAC绑定错误"
                    case AuthErrorCode.WRONG_PASSWORD:
                        err_msg = "密码错误"
                    case AuthErrorCode.INSUFFICIENT_FUNDS:
                        err_msg = "余额不足或欠费"
                    case AuthErrorCode.WRONG_MAC:
                        err_msg = "MAC地址不匹配"
                    case AuthErrorCode.WRONG_IP:
                        err_msg = "IP地址不匹配"
                    case AuthErrorCode.WRONG_VERSION:
                        err_msg = "客户端版本不匹配"
                    case AuthErrorCode.FROZEN:
                        err_msg = "账号被冻结"
                    case AuthErrorCode.SERVER_BUSY:
                        err_msg = "服务器繁忙"
                    case _:
                        err_msg = f"其他错误 ({e_enum.name})"
            except ValueError:
                pass

        return (
            False,
            None,
            error_code,
            f"登录失败: {err_msg} (Code: {hex(error_code) if error_code is not None else 'N/A'})",
        )

    else:
        return False, None, None, f"未知的响应代码: {hex(code)}"
