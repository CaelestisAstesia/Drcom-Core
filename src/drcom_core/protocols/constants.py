# src/drcom_core/protocols/constants.py
"""
Dr.COM 协议层 - 常量定义 (v1.0.0 Refactor)

本模块定义了所有协议相关的魔法数字、偏移量和固定值。
采用命名空间 (Class Namespace) 组织，不再使用扁平全局变量。
"""

# =========================================================================
# 1. 协议操作码 (Protocol Codes)
# =========================================================================


class PacketCode:
    """协议交互的核心操作码"""

    # Challenge (0x01/0x02)
    CHALLENGE_REQ = b"\x01\x02"
    CHALLENGE_RESP = b"\x02"

    # Login (0x03)
    LOGIN_REQ = b"\x03\x01"

    # Login Response (0x04/0x05)
    LOGIN_SUCCESS = 0x04
    LOGIN_FAILURE = 0x05

    # Logout (0x06)
    LOGOUT_REQ = b"\x06"

    # Keep Alive (0xFF / 0x07)
    KA_CLIENT_HEARTBEAT = b"\xff"  # KA1
    KA_MISC = b"\x07"  # KA2 & KA1_Resp & Logout_Resp


class PacketType:
    """协议子类型"""

    LOGOUT = b"\x01"


# =========================================================================
# 2. Challenge 阶段常量
# =========================================================================


class ChallengeConst:
    REQ_SUFFIX = b"\x09"
    REQ_PADDING_LEN = 15

    # Salt 在响应包中的位置 [4:8]
    SALT_START = 4
    SALT_END = 8


# =========================================================================
# 3. Login 阶段常量
# =========================================================================


class LoginConst:
    # 头部计算
    PACKET_LEN_OFFSET = 20  # 包长度 = 用户名长度 + 20

    # MD5 计算前缀/后缀
    MD5A_SALT_PREFIX = b"\x03\x01"
    MD5B_SALT_PREFIX = b"\x01"
    MD5B_SALT_SUFFIX = b"\x00" * 4
    MD5C_SUFFIX = b"\x14\x00\x07\x0b"
    CHECKSUM1_LEN = 8

    # Checksum2 (CRC样式的校验)
    CHECKSUM2_SUFFIX = b"\x01\x26\x07\x11\x00\x00"
    CHECKSUM2_INIT = 1234
    CHECKSUM2_MULT = 1968

    # 扩展数据段 (Auth Ext)
    AUTH_EXT_CODE = b"\x02"
    AUTH_EXT_LEN = b"\x0c"
    AUTH_EXT_OPTION = b"\x00\x00"

    # 字段填充长度
    PAD_USERNAME = 36
    PAD_HOSTNAME = 32
    PAD_HOST_OS = 32
    PAD_HOST_OS_SUFFIX = 96
    PAD_IP = 12
    PAD_MAC_XOR = 6

    # 固定填充值
    SEP_IPDOG = b"\x00" * 4
    PAD_DNS2 = b"\x00" * 4
    PAD_WINS = b"\x00" * 8
    PAD_AUTO_LOGOUT = b"\x00"
    PAD_BROADCAST = b"\x00"

    # 响应解析
    AUTH_INFO_START = 23
    AUTH_INFO_END = 39
    AUTH_INFO_LEN = 16
    ERROR_CODE_IDX = 4


# =========================================================================
# 4. Keep Alive 阶段常量
# =========================================================================


class KeepAliveConst:
    # 响应码 (复用 0x07)
    RESP_CODE = PacketCode.KA_MISC

    # 填充
    EMPTY_3 = b"\x00\x00\x00"
    EMPTY_4 = b"\x00\x00\x00\x00"

    # KA2 (0x07) 结构
    KA2_HEADER_PREFIX = b"\x28\x00\x0b"
    KA2_FIXED1 = b"\x2f\x12"
    KA2_FIXED1_PAD = b"\x00" * 6
    KA2_TAIL_PAD = b"\x00" * 4

    # KA2 Type 1 (Init/Loop)
    KA2_T1_SPECIFIC = b"\x00" * 16

    # KA2 Type 3 (IP Upload)
    KA2_T3_CRC_DEFAULT = b"\x00" * 4
    KA2_T3_PAD_END = b"\x00" * 8

    # KA2 版本标识 (First Packet Only)
    KA2_FIRST_VER = b"\x0f\x27"


# =========================================================================
# 5. Logout 阶段常量
# =========================================================================


class LogoutConst:
    # 这里其实就是 Login Success Code，但为了语义清晰，定义一个别名
    SUCCESS_CODE = PacketCode.LOGIN_SUCCESS
