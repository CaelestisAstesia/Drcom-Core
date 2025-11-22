# src/drcom_core/protocols/constants.py
"""
Dr.COM 协议层 - 常量

定义所有协议相关的魔法数字、偏移量、固定值。
注意：此处不包含任何可配置的策略参数（如超时、重试次数、版本号等），
也不包含任何默认的身份特征。所有可变参数均应通过 Config 对象注入。
"""

# =========================================================================
# 协议代码 (Protocol Codes)
# =========================================================================
MISC_CODE = b"\x07"  # Keep Alive 2 (07 包) 和 FF 包响应的 Code
CHALLENGE_REQ_CODE = b"\x01\x02"  # Challenge 请求 Code
CHALLENGE_RESP_CODE = b"\x02"  # Challenge 响应 Code
LOGIN_REQ_CODE = b"\x03\x01"  # Login 请求 Code
LOGOUT_REQ_CODE = b"\x06"  # Logout 请求 Code
LOGOUT_TYPE = b"\x01"  # Logout 请求 Type
KEEP_ALIVE_CLIENT_CODE = b"\xff"  # Keep Alive 1 (FF 包) Code


# =========================================================================
# Challenge 常量
# =========================================================================
CHALLENGE_REQ_SUFFIX = b"\x09"
CHALLENGE_REQ_PADDING_LENGTH = 15
SALT_START_INDEX = 4
SALT_END_INDEX = 8


# =========================================================================
# Login 常量
# =========================================================================
LOGIN_PACKET_LENGTH_OFFSET = 20  # 包长度 = 用户名长度 + 这个偏移

MD5_SALT_PREFIX = b"\x03\x01"  # MD5A 前缀
MD5B_SALT_PREFIX = b"\x01"  # MD5B 前缀
MD5B_SALT_SUFFIX = b"\x00" * 4  # MD5B 后缀
MD5C_SUFFIX = b"\x14\x00\x07\x0b"  # Checksum1 后缀
CHECKSUM1_LENGTH = 8

CHECKSUM2_SUFFIX = b"\x01\x26\x07\x11\x00\x00"  # Checksum2 后缀
CHECKSUM2_INIT_VALUE = 1234
CHECKSUM2_MULTIPLIER = 1968

AUTH_EXT_DATA_CODE = b"\x02"
AUTH_EXT_DATA_LEN = b"\x0c"
AUTH_EXT_DATA_OPTION = b"\x00\x00"

# 填充长度
USERNAME_PADDING_LENGTH = 36
HOSTNAME_PADDING_LENGTH = 32
HOSTOS_PADDING_LENGTH = 32
HOSTOS_PADDING_SUFFIX_LENGTH = 96
IP_ADDR_PADDING_LENGTH = 12
MAC_XOR_PADDING_LENGTH = 6

# 固定填充值 (属于协议数据结构的必要填充，非默认配置)
IPDOG_SEPARATOR = b"\x00" * 4
SECONDARY_DNS_PADDING = b"\x00" * 4  # 对应原 SECONDARY_DNS_DEFAULT，改为 PADDING 更准确
WINS_SERVER_PADDING = b"\x00" * 8  # 对应原 WINS_SERVER_DEFAULT
AUTO_LOGOUT_PADDING = b"\x00"  # 对应原 AUTO_LOGOUT_DEFAULT
BROADCAST_MODE_PADDING = b"\x00"  # 对应原 BROADCAST_MODE_DEFAULT


# 登录响应
LOGIN_RESP_SUCCESS_CODE = 0x04
LOGIN_RESP_FAIL_CODE = 0x05
AUTH_INFO_START_INDEX = 23
AUTH_INFO_END_INDEX = 39
AUTH_INFO_LENGTH = 16
ERROR_CODE_INDEX = 4

# =========================================================================
# Keep Alive 常量
# =========================================================================
KEEP_ALIVE_RESP_CODE = MISC_CODE
KEEP_ALIVE_EMPTY_BYTES_3 = b"\x00\x00\x00"
KEEP_ALIVE_EMPTY_BYTES_4 = b"\x00\x00\x00\x00"

KA2_HEADER_PREFIX = b"\x28\x00\x0b"
KA2_FIXED_PART1 = b"\x2f\x12"
KA2_FIXED_PART1_PADDING = b"\x00" * 6
KA2_TAIL_PADDING = b"\x00" * 4
KA2_TYPE1_SPECIFIC_PART = b"\x00" * 16
KA2_TYPE3_CRC_DEFAULT = b"\x00" * 4
KA2_TYPE3_PADDING_END = b"\x00" * 8
KA2_FIRST_PACKET_VERSION = b"\x0f\x27"


# =========================================================================
# Logout 常量
# =========================================================================
SUCCESS_RESP_CODE = LOGIN_RESP_SUCCESS_CODE
