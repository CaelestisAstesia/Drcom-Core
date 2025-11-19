# src/drcom_core/protocols/login.py
"""
处理 Dr.COM D 版登录认证 (Code 0x03) 请求包的构建与解析。
本模块只负责包的构建和解析，不执行网络 I/O。
"""

import hashlib
import logging
import random  # 新增：用于随机包尾
import struct
from typing import Optional, Tuple

from ..exceptions import ProtocolError
from . import constants

logger = logging.getLogger(__name__)


def _calculate_checksum(data: bytes) -> bytes:
    """
    计算 Checksum2 (CRC 变种)。
    算法：按4字节块异或，最后乘以常数。
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
    adapter_num: bytes,
    ipdog: bytes,
    auth_version: bytes,
    control_check_status: bytes,
    # --- 策略开关 ---
    magic_tail: bool = False,
    ror_status: bool = False,
) -> bytes:
    """
    构建 Dr.COM D 版登录请求包。
    """
    # 参数校验
    if not salt or len(salt) != 4:
        raise ProtocolError("Salt 无效，无法构建登录包。")

    # 编码转换
    try:
        pwd_bytes = password.encode(
            "gbk"
        )  # 注意：部分老旧设备可能使用 gbk，这里暂用 utf-8/gbk 兼容策略
        # 为兼容性，这里建议先尝试 utf-8，如果部分学校乱码可改为 gbk。
        # 既然是通用库，这里暂时保持 utf-8，实际部署若有问题可调。
        # 但实际上 Dr.Com 协议对中文支持很差，通常只处理 ASCII。
        # 此处保持原样:
        usr_bytes = username.encode("utf-8", "ignore")
        pwd_bytes = password.encode("utf-8", "ignore")
        hostname_bytes = host_name.encode("utf-8", "ignore")
        hostos_bytes = host_os.encode("utf-8", "ignore")
    except Exception as e:
        raise ProtocolError(f"字符串编码失败: {e}") from e

    data = b""

    # 1. 包头 (Code 0x03, Type 0x01)
    packet_len = len(usr_bytes) + constants.LOGIN_PACKET_LENGTH_OFFSET
    header = constants.LOGIN_REQ_CODE + b"\x00" + bytes([packet_len])
    data += header

    # 2. MD5_A = MD5(0301 + salt + pwd)
    md5a_data = constants.MD5_SALT_PREFIX + salt + pwd_bytes
    md5a = hashlib.md5(md5a_data).digest()
    data += md5a

    # 3. 用户名 (36字节填充)
    data += usr_bytes.ljust(constants.USERNAME_PADDING_LENGTH, b"\x00")

    # 4. ControlStatus & AdapterNum
    data += control_check_status
    data += adapter_num

    # 5. MAC XOR = MAC ^ MD5A[0:6]
    try:
        mac_xor_key = int.from_bytes(md5a[:6], byteorder="big")
        xor_result = mac_xor_key ^ mac_address
        data += xor_result.to_bytes(6, byteorder="big")
    except Exception as e:
        raise ProtocolError(f"MAC地址异或计算失败: {e}") from e

    # 6. MD5_B = MD5(01 + pwd + salt + 00*4)
    md5b_input = (
        constants.MD5B_SALT_PREFIX + pwd_bytes + salt + constants.MD5B_SALT_SUFFIX
    )
    md5b = hashlib.md5(md5b_input).digest()
    data += md5b

    # 7. IP Count (1) & Host IP
    data += b"\x01"
    data += host_ip_bytes
    data += b"\x00" * constants.IP_ADDR_PADDING_LENGTH  # 12字节填充

    # 8. MD5_C (Checksum 1) = MD5(前文 + 1400070b) 前8字节
    md5c_input = data + constants.MD5C_SUFFIX
    md5c = hashlib.md5(md5c_input).digest()[: constants.CHECKSUM1_LENGTH]
    data += md5c

    # 9. IPDOG
    data += ipdog
    data += constants.IPDOG_SEPARATOR

    # 10. Hostname
    data += hostname_bytes.ljust(constants.HOSTNAME_PADDING_LENGTH, b"\x00")

    # 11. DNS & DHCP
    data += primary_dns_bytes
    data += dhcp_server_bytes
    data += constants.SECONDARY_DNS_DEFAULT
    data += constants.WINS_SERVER_DEFAULT

    # 12. OS Info (动态填充)
    data += b"\x94\x00\x00\x00"  # Info Size
    data += b"\x06\x00\x00\x00"  # Major (6=Win10/8/7 range usually)
    data += b"\x00\x00\x00\x00"  # Minor
    data += b"\x28\x0a\x00\x00"  # Build Number (2600)
    data += b"\x02\x00\x00\x00"  # Platform ID

    # 13. Host OS String
    data += hostos_bytes.ljust(constants.HOSTOS_PADDING_LENGTH, b"\x00")
    data += b"\x00" * constants.HOSTOS_PADDING_SUFFIX_LENGTH

    # 14. Auth Version
    data += auth_version

    # 15. ROR (占位, 未启用)
    if ror_status:
        # TODO: 实现 ROR 逻辑
        logger.warning("ROR 模式已启用但尚未实现，可能导致认证失败。")

    # 16. AuthExtData (含 Checksum 2)
    try:
        mac_bytes = mac_address.to_bytes(6, byteorder="big")
    except OverflowError:
        raise ProtocolError("MAC地址无效")

    # 计算 Checksum 2 的输入数据
    checksum2_input = data + constants.CHECKSUM2_SUFFIX + mac_bytes
    checksum2 = _calculate_checksum(checksum2_input)

    data += constants.AUTH_EXT_DATA_CODE
    data += constants.AUTH_EXT_DATA_LEN
    data += checksum2
    data += constants.AUTH_EXT_DATA_OPTION
    data += mac_bytes

    # 17. 尾部填充
    if not ror_status:
        data += constants.AUTO_LOGOUT_DEFAULT
        data += constants.BROADCAST_MODE_DEFAULT

    # 18. Magic Tail (包尾随机化)
    if magic_tail:
        # 生成2字节随机数据代替固定的 e913
        rand_tail = random.randbytes(2)
        data += rand_tail
        logger.debug(f"已应用 Magic Tail: {rand_tail.hex()}")
    else:
        data += constants.LOGIN_PACKET_ENDING

    return data


def parse_login_response(
    response_data: bytes, expected_server_ip: str, received_from_ip: str
) -> Tuple[bool, Optional[bytes], Optional[int], str]:
    """
    解析登录响应。
    返回: (是否成功, AuthInfo/None, ErrorCode/None, 消息)
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

    # 成功 (0x04)
    if code == constants.LOGIN_RESP_SUCCESS_CODE:
        if len(response_data) < constants.AUTH_INFO_END_INDEX:
            return False, None, None, "响应包长度不足，无法提取 AuthInfo"

        auth_info = response_data[
            constants.AUTH_INFO_START_INDEX : constants.AUTH_INFO_END_INDEX
        ]
        return True, auth_info, None, "登录成功"

    # 失败 (0x05)
    elif code == constants.LOGIN_RESP_FAIL_CODE:
        error_code = None
        if len(response_data) > constants.ERROR_CODE_INDEX:
            error_code = response_data[constants.ERROR_CODE_INDEX]

        # 简单的错误描述映射
        err_msg = "未知错误"
        if error_code == constants.ERROR_CODE_IN_USE:
            err_msg = "账号在线或MAC绑定错误"
        elif error_code == constants.ERROR_CODE_WRONG_PASS:
            err_msg = "密码错误"
        elif error_code == constants.ERROR_CODE_INSUFFICIENT:
            err_msg = "余额不足或欠费"
        elif error_code == constants.ERROR_CODE_WRONG_MAC:
            err_msg = "MAC地址不匹配"
        elif error_code == constants.ERROR_CODE_WRONG_IP:
            err_msg = "IP地址不匹配"

        return (
            False,
            None,
            error_code,
            f"登录失败: {err_msg} (Code: {hex(error_code) if error_code else 'N/A'})",
        )

    else:
        return False, None, None, f"未知的响应代码: {hex(code)}"
