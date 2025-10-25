# /src/drcom_protocol/logout.py
"""
处理 Dr.COM D 版登出 (Code 0x06) 请求包的构建、发送以及响应的解析。
"""

import hashlib
import logging
import socket
from typing import Optional, Tuple

# 从常量模块导入所需常量
from . import constants

# 获取当前模块的 logger 实例
logger = logging.getLogger(__name__)
# 日志级别和处理器通常在 main.py 配置


def _build_logout_packet(
    username: str,
    password: str,
    salt: bytes,
    mac: int,
    auth_info: bytes,
    control_check_status: bytes,
    adapter_num: bytes,
) -> bytes:
    """
    构建 Dr.COM D 版登出请求包 (Code 0x06)。

    Args:
        username: 用户名。
        password: 密码。
        salt: 4 字节 Challenge Salt (通常是新获取的)。
        mac: MAC 地址的整数表示。
        auth_info: 登录成功时获取的 16 字节认证信息 (Tail)。
        control_check_status: 控制检查状态字节 (与登录时相同)。
        adapter_num: 适配器数字节 (与登录时相同)。

    Returns:
        bytes: 构建完成的登出请求数据包。

    Raises:
        ValueError: 如果输入参数无效 (如 auth_info 或 salt 长度错误)。
    """
    logger.debug("开始构建登出数据包...")

    # --- 参数校验 ---
    if not auth_info or len(auth_info) != constants.AUTH_INFO_LENGTH:
        raise ValueError(
            f"无效的 Auth Info (Tail)，长度应为 {constants.AUTH_INFO_LENGTH}。"
        )
    if not salt or len(salt) != 4:
        raise ValueError("无效的 Salt，长度应为 4。")

    # --- 编码转换 ---
    try:
        username_bytes = username.encode("utf-8", "ignore")
        password_bytes = password.encode("utf-8", "ignore")
    except Exception as e:
        logger.error(f"用户名或密码编码失败: {e}")
        raise ValueError("用户名或密码编码失败") from e

    # --- 开始构建数据包 ---
    packet = b""

    # 1. 包头和长度
    #    长度 = 用户名实际字节长度 + 固定偏移
    pkt_len = (
        len(username_bytes) + constants.LOGIN_PACKET_LENGTH_OFFSET
    )  # 复用登录包的偏移
    header = (
        constants.LOGOUT_REQ_CODE + constants.LOGOUT_TYPE + b"\x00" + bytes([pkt_len])
    )
    packet += header
    logger.debug(f"  步骤 1: 包头和长度 = {header.hex()}")

    # 2. MD5_A (与登录包类似，但基于登出请求的 salt)
    md5a_data = constants.MD5_SALT_PREFIX + salt + password_bytes
    md5a = hashlib.md5(md5a_data).digest()
    packet += md5a
    logger.debug(f"  步骤 2: 添加 MD5_A = {md5a.hex()}")

    # 3. 用户名
    packet += username_bytes.ljust(constants.USERNAME_PADDING_LENGTH, b"\x00")
    logger.debug("  步骤 3: 添加用户名 (填充)")

    # 4. ControlStatus & AdapterNum
    packet += control_check_status
    packet += adapter_num
    logger.debug(
        f"  步骤 4: 添加 ControlStatus ({control_check_status.hex()}) 和 AdapterNum ({adapter_num.hex()})"
    )

    # 5. MAC 地址异或 (与登录包相同)
    mac_xor_md5_part = md5a[: constants.MAC_XOR_PADDING_LENGTH]
    try:
        md5_part_int = int.from_bytes(mac_xor_md5_part, byteorder="big")
        xor_result = md5_part_int ^ mac
        xor_bytes = xor_result.to_bytes(
            constants.MAC_XOR_PADDING_LENGTH, byteorder="big", signed=False
        )
        packet += xor_bytes
        logger.debug(f"  步骤 5: 添加 MAC 异或结果 = {xor_bytes.hex()}")
    except OverflowError:
        logger.error(
            f"MAC 地址 ({hex(mac)}) 或 MD5A 部分 ({mac_xor_md5_part.hex()}) 无法正确转换为{constants.MAC_XOR_PADDING_LENGTH}字节进行异或。"
        )
        raise ValueError("MAC 地址异或计算时发生溢出错误") from None
    except Exception as e:
        logger.error(f"MAC 地址异或计算失败: {e}", exc_info=True)
        # 在登出包中，即使异或失败也继续，但填充0可能导致服务器不识别
        packet += b"\x00" * constants.MAC_XOR_PADDING_LENGTH
        logger.warning("MAC 异或计算失败，填充零字节继续构建登出包。")

    # 6. Auth Info (Tail)
    packet += auth_info
    logger.debug(f"  步骤 6: 添加 Auth Info (Tail) = {auth_info.hex()}")

    logger.info(f"登出数据包构建完成，总长度: {len(packet)} 字节。")
    return packet


def send_logout_request(  # 函数名改为更明确的 logout
    sock: socket.socket, server_address: str, drcom_port: int, packet: bytes
) -> None:
    """
    发送已构建的登出请求包到服务器。

    Args:
        sock: UDP socket 对象。
        server_address: 服务器 IP 地址。
        drcom_port: 服务器端口。
        packet: 登出请求包 (bytes)。

    Raises:
        socket.error: 发送失败时抛出。
    """
    logger.info("正在发送登出请求...")
    try:
        sock.sendto(packet, (server_address, drcom_port))
        logger.debug(f"已发送登出数据包: {packet.hex()}")
    except socket.error as e:
        logger.error(f"发送登出包失败: {e}")
        raise


def parse_logout_response(
    response_data: Optional[bytes],
    expected_server_ip: str,
    received_from_ip: Optional[str],
) -> Tuple[bool, str]:
    """
    解析 Dr.COM 服务器返回的登出响应包。
    服务器通常不响应登出请求，因此收到响应反而可能是异常情况，
    但如果收到 Code 0x04 则明确表示成功。

    Args:
        response_data: 收到的原始响应字节串，可能为 None。
        expected_server_ip: 期望的服务器 IP 地址。
        received_from_ip: 实际发送响应的 IP 地址，可能为 None。

    Returns:
        tuple: (is_success, message)
            - is_success (bool): 登出是否可以视为成功（发送后未收到错误响应或收到成功响应）。
            - message (str): 描述结果的消息。
    """
    logger.debug(
        f"开始解析登出响应: {response_data.hex() if response_data else 'None'}"
    )

    # 情况 1: 未收到响应 (这是登出时的常见且正常情况)
    if not response_data:
        logger.info("未收到登出响应 (正常情况，视为客户端已尝试登出)。")
        return True, "未收到响应 (正常情况)"  # 视为成功

    # 情况 2: 收到响应，但来源 IP 不对或缺失
    if not received_from_ip:
        msg = "收到登出响应但缺少来源 IP"
        logger.warning(msg)
        return False, msg  # 视为异常
    if received_from_ip != expected_server_ip:
        msg = f"收到来源不匹配的登出响应 (来自: {received_from_ip})"
        logger.warning(msg)
        return False, msg  # 视为异常

    # 情况 3: 收到来自正确服务器的响应
    response_code = response_data[:1]
    if response_code == constants.SUCCESS_RESP_CODE:  # b'\x04'
        logger.info("服务器显式返回了成功代码 (0x04)，确认登出。")
        return True, "服务器确认登出成功"
    else:
        # 收到其他代码，视为异常
        msg = f"收到来自服务器的非预期登出响应代码: {response_code.hex()}"
        logger.warning(msg)
        return False, msg
