# /src/drcom_protocol/login.py
"""
处理 Dr.COM D 版登录认证 (Code 0x03) 请求包的构建、发送以及响应包的解析。
"""

import hashlib
import logging
import socket
import struct
from typing import Optional, Tuple

# 从常量模块导入所需常量
from . import constants

# 获取当前模块的 logger 实例
logger = logging.getLogger(__name__)
# 日志级别和处理器通常在 main.py 配置


def _calculate_checksum(data: bytes) -> bytes:
    """
    计算 Dr.COM D 版登录包中特定位置使用的校验和 (Checksum2)。
    算法大致为：将数据按4字节小端整数块进行异或，最终结果乘以一个常数。

    Args:
        data: 需要计算校验和的字节串。
              通常是登录包的一部分 + constants.CHECKSUM2_SUFFIX + MAC地址字节。

    Returns:
        bytes: 计算出的 4 字节校验和 (小端序)。
    """
    ret = constants.CHECKSUM2_INIT_VALUE  # 1234
    # 将数据填充到 4 字节的倍数
    padded_data = data + b"\x00" * (-(len(data)) % 4)
    # 按 4 字节块处理
    for i in range(0, len(padded_data), 4):
        chunk = padded_data[i : i + 4]
        # 读取为小端序无符号整数 (<I)
        val = struct.unpack("<I", chunk)[0]
        ret ^= val
    # 乘以固定常数并保持在 32 位无符号整数范围内
    ret = (constants.CHECKSUM2_MULTIPLIER * ret) & 0xFFFFFFFF  # 1968
    # 打包回小端序的 4 字节 bytes
    return struct.pack("<I", ret)


def build_login_packet(
    username: str,
    password: str,
    salt: bytes,
    mac_address: int,
    host_ip: str,
    host_name: str,
    host_os: str,
    primary_dns: str,
    dhcp_server: str,
    control_check_status: bytes,
    adapter_num: bytes,
    ipdog: bytes,
    auth_version: bytes,
    ror_status: bool,
) -> bytes:
    """
    构建 Dr.COM D 版登录认证请求包 (Code 0x03)。

    Args:
        username: 用户名。
        password: 密码。
        salt: 4字节 Challenge Salt。
        mac_address: MAC 地址的整数表示。
        host_ip: 本机 IP 地址。
        host_name: 主机名。
        host_os: 操作系统标识字符串。
        primary_dns: 主 DNS 服务器地址。
        dhcp_server: DHCP 服务器地址。
        control_check_status: 控制检查状态字节。
        adapter_num: 适配器数字节。
        ipdog: IPDOG 标志字节。
        auth_version: 认证版本字节串 (通常2字节)。
        ror_status: 是否启用 ROR 加密 (当前未实现)。

    Returns:
        bytes: 构建完成的登录请求数据包。

    Raises:
        ValueError: 如果输入参数无效 (如 salt 长度错误, IP 格式错误等)。
    """
    logger.debug("开始构建登录数据包...")
    # 参数校验
    if not salt or len(salt) != 4:
        logger.error("无法构建登录包：Salt 无效或缺失。")
        raise ValueError("无效的 Salt，无法构建登录包。")
    if not username or not password:
        logger.error("无法构建登录包：用户名或密码为空。")
        raise ValueError("用户名或密码不能为空。")
    if len(auth_version) != 2:
        logger.warning(
            f"AUTH_VERSION 长度不是 2 字节 ({auth_version.hex()})，可能导致认证失败。"
        )

    # 编码转换
    try:
        pwd_bytes = password.encode("utf-8", "ignore")
        usr_bytes = username.encode("utf-8", "ignore")
        hostname_bytes = host_name.encode("utf-8", "ignore")
        hostos_bytes = host_os.encode("utf-8", "ignore")
    except Exception as e:
        logger.error(f"用户名、密码、主机名或操作系统标识编码失败: {e}")
        raise ValueError("必要的字符串参数编码失败") from e

    # 开始构建数据包
    data = b""

    # 1. 包头和长度
    packet_len = len(usr_bytes) + constants.LOGIN_PACKET_LENGTH_OFFSET
    header = constants.LOGIN_REQ_CODE + b"\x00" + bytes([packet_len])
    data += header
    logger.debug(f"步骤 1: 包头和长度 = {header.hex()}")

    # 2. MD5_A
    md5a_data = constants.MD5_SALT_PREFIX + salt + pwd_bytes
    md5a = hashlib.md5(md5a_data).digest()
    data += md5a
    logger.debug(f"步骤 2: 添加 MD5_A = {md5a.hex()}")

    # 3. 用户名
    data += usr_bytes.ljust(constants.USERNAME_PADDING_LENGTH, b"\x00")
    logger.debug("步骤 3: 添加用户名 (填充)")

    # 4. ControlStatus & AdapterNum
    data += control_check_status
    data += adapter_num
    logger.debug(
        f"步骤 4: 添加 ControlStatus ({control_check_status.hex()}) 和 AdapterNum ({adapter_num.hex()})"
    )

    # 5. MAC 地址异或
    mac_xor_md5_part = md5a[: constants.MAC_XOR_PADDING_LENGTH]
    try:
        md5_part_int = int.from_bytes(
            mac_xor_md5_part, byteorder="big"
        )  # 假设是网络序(big-endian)
        xor_result = md5_part_int ^ mac_address
        # 转换为字节串，确保长度正确
        xor_bytes = xor_result.to_bytes(
            constants.MAC_XOR_PADDING_LENGTH, byteorder="big", signed=False
        )
        data += xor_bytes
        logger.debug(f"步骤 5: 添加 MAC 异或结果 = {xor_bytes.hex()}")
    except OverflowError:
        logger.error(
            f"MAC 地址 ({hex(mac_address)}) 或 MD5A 部分 ({mac_xor_md5_part.hex()}) 无法正确转换为{constants.MAC_XOR_PADDING_LENGTH}字节进行异或。"
        )
        raise ValueError("MAC 地址异或计算时发生溢出错误") from None
    except Exception as e:
        logger.error(f"MAC 地址异或计算失败: {e}", exc_info=True)
        raise ValueError("MAC 地址异或计算失败") from e

    # 6. MD5_B
    md5b_input = (
        constants.MD5B_SALT_PREFIX + pwd_bytes + salt + constants.MD5B_SALT_SUFFIX
    )
    md5b = hashlib.md5(md5b_input).digest()
    data += md5b
    logger.debug(f"步骤 6: 添加 MD5_B = {md5b.hex()}")

    # 7. IP 地址信息
    data += b"\x01"  # 固定为 1 个 IP
    try:
        host_ip_bytes = socket.inet_aton(host_ip)
        data += host_ip_bytes
        data += b"\x00" * constants.IP_ADDR_PADDING_LENGTH  # 填充
        logger.debug(f"步骤 7: 添加本机 IP 地址 = {host_ip_bytes.hex()}")
    except OSError:
        logger.error(f"无法构建登录包：提供的主机 IP 地址 '{host_ip}' 格式无效。")
        raise ValueError(f"无效的主机 IP 地址: {host_ip}") from None

    # 8. MD5_C (Checksum 1)
    md5c_input = data + constants.MD5C_SUFFIX
    md5c = hashlib.md5(md5c_input).digest()[: constants.CHECKSUM1_LENGTH]
    data += md5c
    logger.debug(
        f"步骤 8: 添加 Checksum 1 (MD5C 前 {constants.CHECKSUM1_LENGTH} 字节) = {md5c.hex()}"
    )

    # 9. IPDOG 标志和分隔符
    data += ipdog
    data += constants.IPDOG_SEPARATOR
    logger.debug(f"步骤 9: 添加 IPDOG ({ipdog.hex()}) 和分隔符")

    # 10. 主机名
    data += hostname_bytes.ljust(constants.HOSTNAME_PADDING_LENGTH, b"\x00")
    logger.debug("步骤 10: 添加主机名 (填充)")

    # 11. DNS 和 DHCP 服务器 IP
    try:
        data += socket.inet_aton(primary_dns)
        data += socket.inet_aton(dhcp_server)
    except OSError as e:
        logger.error(
            f"无法构建登录包：提供的 DNS ({primary_dns}) 或 DHCP ({dhcp_server}) 服务器地址格式无效。"
        )
        raise ValueError("无效的 DNS 或 DHCP 服务器地址") from e
    data += constants.SECONDARY_DNS_DEFAULT
    data += constants.WINS_SERVER_DEFAULT
    logger.debug("步骤 11: 添加 DNS, DHCP, 次 DNS, WINS 地址")

    # 12 & 13. 操作系统信息 (使用配置或默认值)
    # 这部分模拟性较强，可以直接用字节串拼接
    # 使用常量或直接写死
    data += b"\x94\x00\x00\x00"  # OSVersionInfoSize
    data += b"\x0a\x00\x00\x00"  # MajorVersion (Win10/11)
    data += b"\x00\x00\x00\x00"  # MinorVersion
    data += b"\x58\x66\x00\x00"  # BuildNumber (Win11 22H2 22621)
    data += b"\x02\x00\x00\x00"  # PlatformID (WIN32_NT)
    data += hostos_bytes.ljust(constants.HOSTOS_PADDING_LENGTH, b"\x00")
    data += b"\x00" * constants.HOSTOS_PADDING_SUFFIX_LENGTH  # 96 bytes padding
    logger.debug("步骤 12 & 13: 添加操作系统信息和标识")

    # 14. 认证版本
    data += auth_version
    logger.debug(f"步骤 14: 添加 AUTH_VERSION = {auth_version.hex()}")

    # 15. ROR 加密密码部分 (占位符)
    if ror_status:
        logger.warning("步骤 15: ROR 状态已启用，但 ROR 加密逻辑尚未实现！")
        # ROR 逻辑未实现
    else:
        logger.debug("步骤 15: ROR 状态未启用，跳过 ROR 加密部分。")

    # 16. DrcomAuthExtData 结构 (含 Checksum 2)
    ext_data_prefix = data  # 记录当前数据用于计算 Checksum 2
    try:
        # 确保 MAC 地址转为 bytes 长度正确
        mac_bytes_for_checksum = mac_address.to_bytes(6, byteorder="big", signed=False)
    except OverflowError:
        logger.error(f"MAC 地址整数 {hex(mac_address)} 无法转换为 6 字节。")
        raise ValueError("MAC 地址整数过大") from None

    checksum2_input = (
        ext_data_prefix + constants.CHECKSUM2_SUFFIX + mac_bytes_for_checksum
    )
    checksum2 = _calculate_checksum(checksum2_input)

    ext_data = (
        constants.AUTH_EXT_DATA_CODE
        + constants.AUTH_EXT_DATA_LEN
        + checksum2
        + constants.AUTH_EXT_DATA_OPTION
        + mac_bytes_for_checksum
    )
    data += ext_data
    logger.debug(f"步骤 16: 添加 DrcomAuthExtData (含 Checksum2={checksum2.hex()})")

    # 17. 结尾字节
    if not ror_status:
        data += constants.AUTO_LOGOUT_DEFAULT
        data += constants.BROADCAST_MODE_DEFAULT
        logger.debug("步骤 17: 添加 AutoLogout 和 BroadcastMode")
    else:
        logger.debug("步骤 17: ROR 模式，跳过 AutoLogout 和 BroadcastMode")
        pass  # ROR 模式下，根据某些实现会填充其他字节，这里先跳过

    # 18. 末尾未知字节
    data += constants.LOGIN_PACKET_ENDING
    logger.debug(f"步骤 18: 添加末尾字节 = {constants.LOGIN_PACKET_ENDING.hex()}")

    logger.info(f"登录数据包构建完成，总长度: {len(data)} 字节。")
    return data


# 发送登录包函数
def send_login_request(
    sock: socket.socket, server_address: str, drcom_port: int, packet: bytes
) -> None:
    """
    发送已构建的登录请求包到服务器。

    Args:
        sock: UDP socket 对象。
        server_address: 服务器 IP 地址。
        drcom_port: 服务器端口。
        packet: 登录请求包 (bytes)。

    Raises:
        socket.error: 发送失败时抛出。
    """
    logger.info("正在发送登录请求...")
    try:
        sock.sendto(packet, (server_address, drcom_port))
        logger.debug(f"已发送登录数据包: {packet.hex()}")
    except socket.error as e:
        logger.error(f"发送登录包失败: {e}")
        raise


# 解析登录响应函数
def parse_login_response(
    response_data: bytes, expected_server_ip: str, received_from_ip: str
) -> Tuple[bool, Optional[bytes], Optional[int], str]:
    """
    解析 Dr.COM 服务器返回的登录响应包。

    Args:
        response_data: 收到的原始响应字节串。
        expected_server_ip: 期望的服务器 IP 地址。
        received_from_ip: 实际发送响应的 IP 地址。

    Returns:
        tuple: (is_success, auth_info, error_code, message)
            - is_success (bool): 登录是否成功。
            - auth_info (Optional[bytes]): 成功时为 16 字节的心跳认证信息 (tail)，否则为 None。
            - error_code (Optional[int]): 失败时为错误代码 (整数)，否则为 None。
            - message (str): 描述结果或错误原因的消息。
    """
    logger.debug(f"开始解析登录响应: {response_data.hex()}")
    if not response_data or received_from_ip != expected_server_ip:
        msg = f"收到无效响应或来源不匹配 (来自: {received_from_ip})"
        logger.warning(msg)
        return False, None, None, msg

    response_code = response_data[0]

    if response_code == constants.LOGIN_RESP_SUCCESS_CODE:  # 0x04
        # 检查长度是否足够提取 Auth Info
        if len(response_data) >= constants.AUTH_INFO_END_INDEX:
            auth_info = response_data[
                constants.AUTH_INFO_START_INDEX : constants.AUTH_INFO_END_INDEX
            ]
            logger.info("登录成功！")
            logger.debug(f"提取到 Auth Info (Tail): {auth_info.hex()}")
            return True, auth_info, None, "登录成功"
        else:
            msg = (
                f"登录成功响应包过短 (长度 {len(response_data)})，无法提取 Auth Info。"
            )
            logger.error(msg)
            return False, None, None, msg

    elif response_code == constants.LOGIN_RESP_FAIL_CODE:  # 0x05
        error_code: Optional[int] = None
        error_message = "登录失败"
        # 尝试提取错误代码
        if len(response_data) > constants.ERROR_CODE_INDEX:
            error_code = response_data[constants.ERROR_CODE_INDEX]
            # 错误代码到消息的映射 (可以移到 constants.py 或保持在此处)
            error_map = {
                constants.ERROR_CODE_IN_USE: "账号正在使用中或认证 MAC/IP 不匹配",
                constants.ERROR_CODE_SERVER_BUSY: "服务器繁忙",
                constants.ERROR_CODE_WRONG_PASS: "账号或密码错误",
                constants.ERROR_CODE_INSUFFICIENT: "账号余额不足或流量/时长超限",
                constants.ERROR_CODE_FROZEN: "账号被冻结或暂停使用",
                constants.ERROR_CODE_WRONG_IP: "IP 地址不匹配",
                constants.ERROR_CODE_WRONG_MAC: "MAC 地址不匹配",
                constants.ERROR_CODE_TOO_MANY_IP: "登录 IP 数量超限",
                constants.ERROR_CODE_WRONG_VERSION: "客户端版本不匹配或账号被禁用",
                constants.ERROR_CODE_WRONG_IP_MAC: "IP 和 MAC 地址同时绑定错误",
                constants.ERROR_CODE_FORCE_DHCP: "服务器要求使用 DHCP 获取 IP",
                # 可以根据需要添加更多错误代码
            }
            error_detail = error_map.get(error_code, "未知错误")
            error_message += f" (错误码: {hex(error_code)}) - {error_detail}"
        logger.error(error_message)
        return False, None, error_code, error_message

    else:
        msg = f"收到未知的登录响应代码: {hex(response_code)}"
        logger.error(msg)
        return False, None, None, msg
