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

    Args:
        padding: 尾部填充数据 (默认 15 字节 0x00)。
                 某些学校可能魔改此长度。
    """
    # 生成随机种子 (2字节)
    t = time.time() + random.randint(0xF, 0xFF)
    seed = struct.pack("<H", int(t) % 0xFFFF)

    # 组装: Code(0102) + Seed + 0x09 + Padding
    return constants.Code.CHALLENGE_REQ + seed + b"\x09" + padding


def parse_challenge_response(data: bytes) -> Optional[bytes]:
    """
    解析 Challenge 响应包 (0x02)，提取 Salt。
    """
    if not data:
        return None

    if not data.startswith(constants.Code.CHALLENGE_RESP):
        return None

    if len(data) < constants.SALT_OFFSET_END:
        return None

    # 提取 Salt (4字节)
    return data[constants.SALT_OFFSET_START : constants.SALT_OFFSET_END]


# =========================================================================
# Login (0x03) - The Big One
# =========================================================================


def build_login_packet(
    # --- 基础凭据 ---
    username: str,
    password: str,
    salt: bytes,
    mac_address: int,
    # --- 网络参数 ---
    host_ip_bytes: bytes,
    primary_dns_bytes: bytes,
    dhcp_server_bytes: bytes,
    secondary_dns_bytes: bytes,  # [新增] 必须传入，通常为 0.0.0.0
    # --- 身份与指纹 ---
    host_name: str,
    host_os: str,
    os_info_bytes: bytes,  # 20字节的内核指纹
    # --- 协议参数 ---
    control_check_status: bytes,
    adapter_num: bytes,
    ipdog: bytes,
    auth_version: bytes,
    # --- 填充位 (可变区域) ---
    padding_after_ipdog: bytes,  # [新增] ipdog 后的 4 字节
    padding_after_dhcp: bytes,  # [新增] dhcp 后的 8 字节 (原 wins)
    padding_auth_ext: bytes,  # [新增] 校验尾部的填充 (原 auto_logout 等)
    # --- 功能开关 ---
    ror_enabled: bool = False,  # 是否启用 ROR 加密
) -> bytes:
    """
    构建 5.2.0(D) 标准登录数据包。

    该函数实现了最复杂的协议逻辑，包括 MD5/XOR/Checksum 计算。
    所有可变字段均通过参数传入，杜绝硬编码。
    """
    # 1. 字符串编码处理
    usr_bytes = username.encode("gbk", "ignore")  # 兼容性：GBK 通常比 UTF-8 更安全
    pwd_bytes = password.encode("gbk", "ignore")
    hostname_bytes = host_name.encode("gbk", "ignore")
    hostos_bytes = host_os.encode("gbk", "ignore")

    mac_bytes = mac_address.to_bytes(6, byteorder="big")

    pkt = bytearray()

    # 2. 头部 (Header)
    # 长度 = 20 (固定偏移) + 用户名长度
    pkt_len = 20 + len(usr_bytes)
    pkt.extend(constants.Code.LOGIN_REQ)
    pkt.append(0x00)
    pkt.append(pkt_len)

    # 3. MD5_A (0x03 0x01 + Salt + Password)
    md5a = utils.md5_bytes(constants.MD5_SALT_PREFIX + salt + pwd_bytes)
    pkt.extend(md5a)

    # 4. 身份信息
    # 用户名 (填充至 36 字节)
    pkt.extend(usr_bytes.ljust(constants.USERNAME_MAX_LEN, b"\x00"))
    pkt.extend(control_check_status)
    pkt.extend(adapter_num)

    # 5. MAC XOR 加密
    # 算法: MAC ^ MD5A[0:6]
    xor_key = int.from_bytes(md5a[:6], byteorder="big")
    mac_xor = mac_address ^ xor_key
    pkt.extend(mac_xor.to_bytes(constants.LOGIN_MAC_XOR_LEN, byteorder="big"))

    # 6. MD5_B (0x01 + Password + Salt + 4*00)
    md5b_data = (
        constants.MD5B_SALT_PREFIX + pwd_bytes + salt + constants.MD5B_SALT_SUFFIX
    )
    pkt.extend(utils.md5_bytes(md5b_data))

    # 7. IP 列表与 MD5_C
    # 结构: 0x01 (IP数) + HostIP + 3个 0.0.0.0 (填充)
    ip_section = bytearray()
    ip_section.append(0x01)  # IP Count
    ip_section.extend(host_ip_bytes)
    ip_section.extend(b"\x00" * 12)  # 填充 3 个空 IP
    pkt.extend(ip_section)

    # MD5_C (IP列表 + Magic) 取前 8 字节
    md5c = utils.md5_bytes(ip_section + constants.MD5C_SUFFIX)[
        : constants.LOGIN_MD5C_LEN
    ]
    pkt.extend(md5c)

    # 8. IPDOG 与 填充
    pkt.extend(ipdog)
    pkt.extend(padding_after_ipdog)  # [动态参数] 通常是 4字节 00

    # 9. 主机信息
    pkt.extend(hostname_bytes.ljust(constants.HOSTNAME_MAX_LEN, b"\x00"))
    pkt.extend(primary_dns_bytes)
    pkt.extend(dhcp_server_bytes)
    pkt.extend(secondary_dns_bytes)  # [动态参数] 通常是 0.0.0.0
    pkt.extend(padding_after_dhcp)  # [动态参数] 通常是 8字节 00 (WINS)

    # 10. 系统版本指纹 (重要)
    # 结构: OSVersionInfo (20 bytes) + HostOSStr (32 bytes) + Padding (96 bytes)
    pkt.extend(os_info_bytes)
    pkt.extend(hostos_bytes.ljust(constants.HOST_OS_MAX_LEN, b"\x00"))
    pkt.extend(b"\x00" * constants.HOST_OS_SUFFIX_LEN)

    # 11. 协议版本
    pkt.extend(auth_version)

    # 12. 扩展校验 (Checksum)
    # 计算范围: 目前的包 + Checksum后缀 + MAC
    # 算法: CRC-1968 (D版特有)
    checksum_input = pkt + constants.CHECKSUM_SUFFIX + mac_bytes
    checksum_val = utils.checksum_d_series(checksum_input)

    # 13. 扩展数据段 (Auth Ext Data)
    pkt.extend(constants.AUTH_EXT_CODE)
    pkt.extend(constants.AUTH_EXT_LEN)
    pkt.extend(checksum_val)
    pkt.extend(constants.AUTH_EXT_OPTION)
    pkt.extend(mac_bytes)

    # 14. 尾部填充
    # 如果开启 ROR，这里会不同，目前暂按标准 D 版处理
    pkt.extend(padding_auth_ext)  # [动态参数]

    # 15. 随机尾巴 (2 字节)
    # 随机数
    pkt.extend(random.randbytes(2))

    return bytes(pkt)


def parse_login_response(data: bytes) -> tuple[bool, bytes | None, int | None]:
    """
    解析登录响应。
    Returns: (is_success, auth_info/None, error_code/None)
    """
    if not data:
        return False, None, None

    code = data[0]

    if code == constants.Code.LOGIN_RESP_SUCC:
        # 提取 AuthInfo (16字节)
        if len(data) >= constants.AUTH_INFO_END:
            return True, data[constants.AUTH_INFO_START : constants.AUTH_INFO_END], None
        return False, None, None

    elif code == constants.Code.LOGIN_RESP_FAIL:
        # 提取错误码
        err = (
            data[constants.ERROR_CODE_INDEX]
            if len(data) > constants.ERROR_CODE_INDEX
            else 0
        )
        return False, None, err

    return False, None, None
