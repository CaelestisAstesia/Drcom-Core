# /src/drcom_protocol/challenge.py
"""
处理 Dr.COM 认证过程中的 Challenge 请求与响应 (Code 0x01, 0x02)。
"""

import logging
import random
import socket
import struct
import time
from typing import Optional, Tuple

# 从同一目录下的 constants 模块导入常量
from . import constants

# 获取当前模块的 logger 实例
# 注意：日志级别和处理器通常在主入口点 (main.py) 配置
logger = logging.getLogger(__name__)


def send_challenge_request(
    sock: socket.socket, server_address: str, drcom_port: int
) -> Optional[bytes]:
    """
    构建并发送 Challenge 请求包 (Code 0x01) 到 Dr.COM 服务器。

    Args:
        sock: 用于通信的 UDP socket 对象。
        server_address: Dr.COM 服务器的 IP 地址 (字符串)。
        drcom_port: Dr.COM 服务器的认证端口 (整数)。

    Returns:
        Optional[bytes]: 成功发送则返回构建的 Challenge 请求包 (bytes)，否则返回 None。

    Raises:
        socket.error: 如果发送过程中发生 socket 错误。
    """
    logger.info("正在发送 Challenge 请求到服务器...")
    try:
        # 1. 生成随机数种子
        # 通常基于当前时间戳加上一个小的随机整数，增加随机性
        random_seed: float = time.time() + random.randint(0xF, 0xFF)

        # 2. 将种子打包成 2 字节小端序 (<H) 无符号短整型
        #    对 0xFFFF 取模确保结果在 2 字节范围内
        random_bytes: bytes = struct.pack("<H", int(random_seed) % 0xFFFF)

        # 3. 构建 Challenge 请求包
        #    结构: 请求代码 + 打包后的随机字节 + 请求后缀 + 固定长度的空字节填充
        challenge_packet: bytes = (
            constants.CHALLENGE_REQ_CODE  # b'\x01\x02'
            + random_bytes  # 2 bytes
            + constants.CHALLENGE_REQ_SUFFIX  # b'\x09'
            + b"\x00" * constants.CHALLENGE_REQ_PADDING_LENGTH  # 15 bytes null padding
        )
        logger.debug(f"构建的 Challenge 请求包: {challenge_packet.hex()}")

        # 4. 发送数据包
        sock.sendto(challenge_packet, (server_address, drcom_port))
        logger.debug(f"已发送 Challenge 请求到 {server_address}:{drcom_port}")
        return challenge_packet  # 返回成功发送的数据包

    except socket.error as error:
        logger.error(f"发送 Challenge 请求包时发生 Socket 错误: {error}")
        raise  # 将异常重新抛出给调用者处理
    except Exception as e:
        # 捕获其他可能的异常，例如 struct.pack 错误
        logger.error(f"构建或发送 Challenge 请求时发生意外错误: {e}", exc_info=True)
        return None  # 返回 None 表示失败


def receive_challenge_response(
    sock: socket.socket,
) -> Tuple[Optional[bytes], Optional[Tuple[str, int]]]:
    """
    接收并解析来自 Dr.COM 服务器的 Challenge 响应包 (Code 0x02)。

    Args:
        sock: 用于通信的 UDP socket 对象。

    Returns:
        tuple: (salt, address)
            - salt (Optional[bytes]): 成功解析则为 4 字节的 salt，否则为 None。
            - address (Optional[tuple[str, int]]): 发送响应的服务器 (IP, port) 元组，接收失败时可能为 None。

    Raises:
        socket.timeout: 如果接收响应超时 (由 socket 对象设置决定)。
        socket.error: 如果接收过程中发生 socket 错误。
    """
    logger.info("正在等待 Challenge 响应...")
    salt: Optional[bytes] = None
    address: Optional[Tuple[str, int]] = None
    try:
        # 从 socket 接收数据，设置一个合理的缓冲区大小
        buffer_size = 1024
        data, address = sock.recvfrom(buffer_size)
        logger.debug(f"收到来自 {address} 的响应数据: {data.hex()}")

        # 1. 验证响应代码
        if not data.startswith(constants.CHALLENGE_RESP_CODE):  # b'\x02'
            logger.warning(
                f"收到的响应包 Code 不正确 "
                f"(期望: {constants.CHALLENGE_RESP_CODE.hex()}，"
                f"实际: {data[:1].hex()})。"
            )
            return None, address  # 返回 None 表示 salt 获取失败

        # 2. 验证响应包长度是否足够提取 salt
        #    Salt 在索引 4 到 8 (不含 8) 的位置
        if len(data) < constants.SALT_END_INDEX:
            logger.warning(
                f"收到的 Challenge 响应包过短 (长度 {len(data)})，无法提取 Salt "
                f"(需要至少 {constants.SALT_END_INDEX} 字节)。"
            )
            return None, address  # 返回 None 表示 salt 获取失败

        # 3. 提取 Salt
        salt = data[constants.SALT_START_INDEX : constants.SALT_END_INDEX]
        logger.debug(f"成功从响应中提取 Salt: {salt.hex()}")
        return salt, address

    except socket.timeout:
        logger.warning("接收 Challenge 响应超时。")
        raise  # 重新抛出超时异常
    except socket.error as error:
        logger.error(f"接收 Challenge 响应时发生 Socket 错误: {error}")
        raise  # 重新抛出 Socket 错误异常
    except IndexError:
        # 虽然做了长度检查，理论上不应触发，但以防万一
        logger.error(
            "处理 Challenge 响应时发生索引错误 (数据包可能不完整或格式错误?)。"
        )
        return None, address  # 返回 None 表示失败
    except Exception as e:
        logger.error(f"处理 Challenge 响应时发生意外错误: {e}", exc_info=True)
        return None, address  # 返回 None 表示失败
