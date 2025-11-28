# src/drcom_core/protocols/d_series/constants.py
"""
Dr.COM 5.2.0(D) 协议族常量表 (Constants)

仅定义协议的结构性常量（如 OpCode、偏移量）。
不包含任何默认策略值（如默认填充、默认版本号），这些应由 Config/Strategy 注入。
"""


# =========================================================================
# 协议操作码 (Protocol Codes)
# =========================================================================
class Code:
    """协议包头部的 Code 字段定义"""

    CHALLENGE_REQ = b"\x01\x02"  # 挑战请求 (Client -> Server)
    CHALLENGE_RESP = b"\x02"  # 挑战响应 (Server -> Client)
    LOGIN_REQ = b"\x03\x01"  # 登录请求 (Client -> Server)
    LOGIN_RESP_SUCC = 0x04  # 登录成功
    LOGIN_RESP_FAIL = 0x05  # 登录失败
    LOGOUT_REQ = b"\x06"  # 注销请求
    LOGOUT_TYPE = b"\x01"  # 注销类型
    MISC = b"\x07"  # 杂项/心跳2 (0x07)
    KEEP_ALIVE_1 = b"\xff"  # 心跳1 (0xFF)


# =========================================================================
# 结构偏移量 (Offsets & Structure)
# =========================================================================
# Challenge
SALT_OFFSET_START = 4
SALT_OFFSET_END = 8

# Login 核心结构长度
LOGIN_MD5A_LEN = 16
LOGIN_MD5B_LEN = 16
LOGIN_MD5C_LEN = 8
LOGIN_MAC_XOR_LEN = 6

# Login 填充对齐长度 (用于 ljust)
USERNAME_MAX_LEN = 36  # 用户名填充长度
HOSTNAME_MAX_LEN = 32  # 主机名填充长度
HOST_OS_MAX_LEN = 32  # 操作系统名填充长度
HOST_OS_SUFFIX_LEN = 96  # 操作系统名后的长填充

# 响应包解析
AUTH_INFO_START = 23
AUTH_INFO_END = 39
AUTH_INFO_LEN = 16
ERROR_CODE_INDEX = 4  # 0x05 包中错误码的位置

# =========================================================================
# 算法魔法数字 (Magic Numbers for Algorithms)
# =========================================================================
# MD5 计算辅助
MD5_SALT_PREFIX = b"\x03\x01"
MD5B_SALT_PREFIX = b"\x01"
MD5C_SUFFIX = b"\x14\x00\x07\x0b"

# Checksum 计算辅助
CHECKSUM_SUFFIX = b"\x01\x26\x07\x11\x00\x00"

# 扩展数据段 (Auth Ext Data) 头部
AUTH_EXT_CODE = b"\x02"
AUTH_EXT_LEN = b"\x0c"
AUTH_EXT_OPTION = b"\x00\x00"

# Keep Alive 2 (0x07)
KA2_HEADER_PREFIX = b"\x28\x00\x0b"
KA2_FIXED_PART1 = b"\x2f\x12"
