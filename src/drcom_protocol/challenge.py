# /src/drcom_protocol/challenge.py

import logging  # 引入日志模块
import random
import socket
import struct
import time
from typing import Optional, Tuple  # 引入类型提示

# 从同一目录下的 constants 模块导入常量 (相对导入)
from . import constants

# 获取当前模块的 logger 实例，名称为 'src.drcom_protocol.challenge'
logger = logging.getLogger(__name__)
# 设置日志级别，使其可以记录 DEBUG 信息 (最终输出级别由 main.py 控制)
logger.setLevel(logging.DEBUG)


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
    logger.info("正在发送 Challenge 请求到服务器...")  # 使用 logger
    try:
        # 生成一个随机数，通常基于当前时间加上一个小的随机偏移
        # 这是为了让每次请求稍微不同
        random_number: float = time.time() + random.randint(0xF, 0xFF)
        # 将随机数打包成 2 字节的小端序 (<H) 无符号短整型
        random_packet: bytes = struct.pack("<H", int(random_number) % 0xFFFF)

        # 构建 Challenge 请求包
        # 结构: Code (0x0102) + 打包后的随机数 (2字节) + 后缀 (0x09) + 15字节的空字节填充
        challenge_packet: bytes = (
            constants.CHALLENGE_REQ_CODE  # \x01\x02
            + random_packet
            + constants.CHALLENGE_REQ_SUFFIX  # \x09
            + b"\x00" * 15  # 填充
        )

        # 通过 socket 发送数据包到服务器地址和端口
        sock.sendto(challenge_packet, (server_address, drcom_port))
        logger.debug(
            f"已发送 Challenge 请求包: {challenge_packet.hex()}"
        )  # 使用 logger (debug 级别)
        return challenge_packet  # 返回成功发送的数据包

    except socket.error as error:
        # 捕获发送时可能发生的 socket 错误
        logger.error(f"发送 Challenge 请求包失败: {error}")
        raise  # 将异常重新抛出，由调用者 (core.py) 处理


def receive_challenge_response(
    sock: socket.socket,
) -> Tuple[Optional[bytes], Optional[Tuple[str, int]]]:
    """
    接收并解析来自 Dr.COM 服务器的 Challenge 响应包 (Code 0x02)。

    Args:
        sock: 用于通信的 UDP socket 对象。

    Returns:
        tuple: 包含两个元素的元组:
            - salt (Optional[bytes]): 如果成功接收并解析，则为提取出的 salt (bytes)，否则为 None。
            - address (Optional[tuple[str, int]]): 发送响应的服务器地址 (IP, port) 元组，如果接收失败则可能为 None (取决于 recvfrom 的行为)。

    Raises:
        socket.timeout: 如果接收响应超时 (由调用者设置的 socket 超时决定)。
        socket.error: 如果接收过程中发生 socket 错误。
    """
    logger.info("正在等待 Challenge 响应...")  # 使用 logger
    salt: Optional[bytes] = None
    address: Optional[Tuple[str, int]] = None
    try:
        # 从 socket 接收数据，最大 1024 字节
        # data 是收到的字节串, address 是发送方的 (IP, port) 元组
        data, address = sock.recvfrom(1024)
        logger.debug(f"收到来自 {address} 的响应数据: {data.hex()}")  # 使用 logger

        # 检查响应包是否以预期的 Code (0x02) 开头
        if data.startswith(constants.CHALLENGE_RESP_CODE):
            # 检查响应包长度是否足够提取 salt
            if len(data) >= constants.SALT_END_INDEX:
                # 从响应包的指定位置提取 salt (字节索引 4 到 7)
                salt = data[constants.SALT_START_INDEX : constants.SALT_END_INDEX]
                logger.debug(f"成功从响应中提取 Salt: {salt.hex()}")
            else:
                # 如果包长度不足，记录警告
                logger.warning("收到的 Challenge 响应包过短，无法提取 Salt。")
                salt = None  # 明确设为 None
        else:
            # 如果响应包 Code 不匹配，记录警告
            logger.warning(
                f"收到的响应包 Code 不正确 (期望: {constants.CHALLENGE_RESP_CODE.hex()}，实际: {data[:1].hex()})。"
            )
            salt = None  # 明确设为 None

        # 无论是否成功提取 salt，都返回结果和地址
        return salt, address

    except socket.timeout:
        # 捕获超时异常
        logger.warning("接收 Challenge 响应超时。")
        raise  # 重新抛出异常，由调用者 (core.py) 处理
    except socket.error as error:
        # 捕获其他 socket 错误
        logger.error(f"接收 Challenge 响应时发生 Socket 错误: {error}")
        raise  # 重新抛出异常
    except IndexError:
        # 这个异常理论上不会因为上面添加了长度检查而触发，但保留以防万一
        logger.error("处理 Challenge 响应时发生索引错误 (数据包可能不完整?)。")
        return None, address  # 返回 None 表示失败
