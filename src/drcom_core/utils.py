# File: src/drcom_core/utils.py
"""
Dr.COM 核心库 - 通用算法工具箱

本模块汇集了 Dr.COM 协议族（D版/P版/X版）通用的加密与校验算法。
"""

import hashlib
import struct


def checksum_d_series(data: bytes) -> bytes:
    """计算 Dr.COM D系列协议专用的 4 字节校验和 (CRC-1968)。

    此算法常见于 D 版 Login 包末尾的校验字段。

    算法逻辑:
    1. 初始值 ret = 1234
    2. 将数据按 4 字节分组（小端序），不足 4 字节补 0。
    3. 对每组数据进行异或 (XOR) 累加。
    4. 结果乘以魔数 1968，截断为 32 位。

    Args:
        data: 需要计算校验和的原始字节流。

    Returns:
        bytes: 4 字节的小端序校验和。
    """
    CRC1968_INIT_VAL = 1234
    CRC1968_MULTIPLIER = 1968
    ret = CRC1968_INIT_VAL
    # 4字节对齐填充
    padded = data + b"\x00" * (-(len(data)) % 4)

    for i in range(0, len(padded), 4):
        # 提取 4 字节，解包为无符号整数 (Little Endian)
        chunk = padded[i : i + 4]
        val = struct.unpack("<I", chunk)[0]
        ret ^= val

    ret = (CRC1968_MULTIPLIER * ret) & 0xFFFFFFFF
    return struct.pack("<I", ret)


def ror_encrypt(data: bytes, key: bytes) -> bytes:
    """循环异或加密 (ROR - Rotate Right)。

    Dr.COM 协议中常用于对密码字段进行混淆。

    算法逻辑:
    byte[i] = (data[i] ^ key[i]) 的位循环右移操作。
    具体为: ((x << 3) & 0xFF) | (x >> 5)

    Args:
        data: 原始数据 (通常是 MD5 后的哈希)。
        key: 密钥 (通常是原始密码)。

    Returns:
        bytes: 加密后的字节流。
    """
    ret = bytearray()
    key_len = len(key)

    for i in range(len(data)):
        # 循环使用 key
        k = key[i % key_len]
        x = data[i] ^ k
        # Python 的位操作：保留 8 位无符号整数范围
        val = ((x << 3) & 0xFF) | (x >> 5)
        ret.append(val)

    return bytes(ret)


def drcom_crc32(data: bytes, init: int = 0) -> int:
    """Dr.COM 自定义的 CRC32 算法。

    常见于 P 版 (PPPoE) 心跳包的校验。
    不同于标准的 CRC32，它只是简单的 4 字节异或累加。

    Args:
        data: 输入数据。
        init: 初始值，默认为 0。

    Returns:
        int: 计算结果 (整数形式)。
    """
    ret = init
    # 4字节对齐处理 (补0)
    padded = data + b"\x00" * (-(len(data)) % 4)

    for i in range(0, len(padded), 4):
        # P 版某些实现中使用小端序 (<I)
        val = struct.unpack("<I", padded[i : i + 4])[0]
        ret ^= val
        ret &= 0xFFFFFFFF

    return ret


def md5_bytes(data: bytes) -> bytes:
    """计算 MD5 哈希的快捷函数。

    Args:
        data: 输入字节流。

    Returns:
        bytes: 16 字节的 MD5 摘要。
    """
    return hashlib.md5(data).digest()
