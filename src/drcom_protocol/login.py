# /src/drcom_protocol/login.py

import binascii
import hashlib
import logging
import socket
import struct
from typing import Optional, Tuple

# 获取当前模块的 logger 实例
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


def _calculate_checksum(data: bytes) -> bytes:
    """
    计算 Dr.COM D 版登录包中使用的特定校验和 (CRC)。
    参考 latest-wired-python3.py 中的 checksum 函数。

    Args:
        data: 需要计算校验和的字节串 (通常是部分登录包 + 固定后缀 + MAC地址)。

    Returns:
        bytes: 计算出的 4 字节校验和 (小端序)。
    """
    ret = 1234
    # 将数据填充到 4 字节的倍数
    padded_data = data + b"\x00" * (-(len(data)) % 4)
    # 按 4 字节块处理
    for i in range(0, len(padded_data), 4):
        chunk = padded_data[i : i + 4]
        # 读取为小端序无符号整数 (<I)
        val = struct.unpack("<I", chunk)[0]
        ret ^= val
    # 乘以固定常数并保持在 32 位无符号整数范围内
    ret = (1968 * ret) & 0xFFFFFFFF
    # 打包回小端序的 4 字节 bytes
    return struct.pack("<I", ret)


# 构建数据包
def _build_login_packet(
    username: str,
    password: str,
    salt: bytes,
    mac_address: int,  # 整数形式的 MAC
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
        username (str): 用户名。
        password (str): 密码。
        salt (bytes): 从 Challenge 响应中获取的 4 字节 salt。
        mac_address (int): 本机 MAC 地址的整数表示。
        host_ip (str): 本机 IP 地址。
        host_name (str): 主机名。
        host_os (str): 操作系统标识字符串。
        primary_dns (str): 主 DNS 服务器地址。
        dhcp_server (str): DHCP 服务器地址。
        control_check_status (bytes): 控制检查状态字节。
        adapter_num (bytes): 适配器数字节。
        ipdog (bytes): IPDOG 标志字节。
        auth_version (bytes): 认证版本字节串 (2字节)。
        ror_status (bool): 是否启用 ROR 加密。

    Returns:
        bytes: 构建完成的登录请求数据包。

    Raises:
        ValueError: 如果 salt 无效或缺少必要的参数。
    """
    logger.debug("开始构建登录数据包...")
    if not salt or len(salt) != 4:
        logger.error("无法构建登录包：Salt 无效或缺失。")
        raise ValueError("无效的 Salt，无法构建登录包。")
    if not username or not password:
        logger.error("无法构建登录包：用户名或密码为空。")
        raise ValueError("用户名或密码不能为空。")

    # 密码和用户名的字节编码
    try:
        # 使用 'ignore' 忽略无法编码的字符，防止报错
        pwd_bytes = password.encode("utf-8", "ignore")
        usr_bytes = username.encode("utf-8", "ignore")
    except Exception as e:
        logger.error(f"用户名或密码编码失败: {e}")
        raise ValueError("用户名或密码编码失败") from e

    #   开始构建数据包
    data = b""  # 初始化一个空的字节串

    # 1. 包头 (Code=0x03, Type=0x01) 和 包总长度
    #    长度 = 用户名实际字节长度 + 20
    packet_len_byte = bytes([len(usr_bytes) + 20])
    data = b"\x03\x01\x00" + packet_len_byte
    logger.debug(f"步骤 1: 包头和长度 = {data.hex()}")

    # 2. 第一个 MD5 (MD5_A)
    #    计算 MD5(b'\x03\x01' + salt + password_bytes)
    md5_a = hashlib.md5(b"\x03\x01" + salt + pwd_bytes).digest()
    data += md5_a
    logger.debug(f"步骤 2: 添加 MD5_A = {md5_a.hex()}")
    logger.debug(f"       当前数据包 = {data.hex()}")

    # 3. 用户名 (Username)
    #    将用户名编码后的字节串填充到 36 字节
    data += (usr_bytes + 36 * b"\x00")[:36]
    logger.debug(f"步骤 3: 添加用户名 {usr_bytes.hex()} (填充至 36 字节)")
    logger.debug(f"       当前数据包 = {data.hex()}")

    # 4. 控制检查状态 (Control Check Status) 和 适配器编号 (Adapter Number)
    data += control_check_status
    data += adapter_num
    logger.debug(
        f"步骤 4: 添加 ControlStatus ({control_check_status.hex()}) 和 AdapterNum ({adapter_num.hex()})"
    )
    logger.debug(f"       当前数据包 = {data.hex()}")

    # 5. MAC 地址异或 (MAC xor MD5_A[0:6])
    #    取出 MD5_A 的前 6 个字节
    mac_xor_md5_part = md5_a[0:6]  # 取前 6 字节
    logger.debug(f"步骤 5: 用于异或的 MD5_A 部分 = {mac_xor_md5_part.hex()}")
    logger.debug(f"       用于异或的 MAC 地址 (整数) = {hex(mac_address)}")
    try:
        # 将 MD5_A 的前 6 字节转换为十六进制整数
        md5_part_int = int(binascii.hexlify(mac_xor_md5_part), 16)
        # 执行整数异或运算
        xor_result = md5_part_int ^ mac_address
        logger.debug(f"       异或结果 (整数) = {hex(xor_result)}")
        # 将异或结果格式化为 12 位的十六进制字符串 (不足位前面补零)
        xor_result_hex = format(xor_result, "012x")
        # 将十六进制字符串转换回 bytes (取最后 6 字节，以防万一结果超过 6 字节)
        xor_bytes = binascii.unhexlify(xor_result_hex)[-6:]
        # 确保结果是 6 字节长，如果不足则在前面补零
        xor_bytes = xor_bytes.rjust(6, b"\x00")

        data += xor_bytes
        logger.debug(f"步骤 5: 添加 MAC 异或结果 = {xor_bytes.hex()}")
        logger.debug(f"       当前数据包 = {data.hex()}")
    except Exception as e:
        logger.error(f"MAC 地址异或计算失败: {e}")
        raise ValueError("MAC 地址异或计算失败") from e

    # 6. 第二次 MD5 (MD5_B)
    #    计算 MD5(b'\x01' + password_bytes + salt + b'\x00\x00\x00\x00')
    md5_b_input = b"\x01" + pwd_bytes + salt + b"\x00" * 4
    md5_b = hashlib.md5(md5_b_input).digest()
    data += md5_b
    logger.debug(f"步骤 6: 添加 MD5_B = {md5_b.hex()}")
    logger.debug(f"       (计算源 = {md5_b_input.hex()})")  # 调试用，可注释掉
    logger.debug(f"       当前数据包 = {data.hex()}")

    # 7. IP 地址信息
    data += b"\x01"
    logger.debug("步骤 7: 添加 1 个 IP 地址数量")
    try:
        # 使用 socket.inet_aton 将点分十进制 IP 字符串转换为 4 字节网络序 bytes
        host_ip_bytes = socket.inet_aton(host_ip)
        data += host_ip_bytes
        data += b"\x00" * 12  # 填充 固定为 12 字节
        logger.debug(
            f"       添加本机 IP 地址 = {host_ip_bytes.hex()} (来自 {host_ip})"
        )
    except OSError:
        # 如果 host_ip 格式不正确，inet_aton 会抛出 OSError
        logger.error(f"无法构建登录包：提供的主机 IP 地址 '{host_ip}' 格式无效。")
        raise ValueError(f"无效的主机 IP 地址: {host_ip}") from None

    # 8. 第三次 MD5 (Checksum 1 / HalfMD5)
    #    计算 MD5(当前所有 data + b'\x14\x00\x07\x0b')，取前 8 字节
    md5_c_input = data + b"\x14\x00\x07\x0b"
    md5_c = hashlib.md5(md5_c_input).digest()[:8]  # 使用切片 [:8] 取前 8 字节
    data += md5_c
    logger.debug(f"步骤 8: 添加 MD5_C (Checksum 1) = {md5_c.hex()}")
    logger.debug(f"       (计算源 = {md5_c_input.hex()})")  # 调试用
    logger.debug(f"       当前数据包 = {data.hex()}")

    # 9. IPDOG 标志 和 分隔符
    data += ipdog  # 从参数传入的 ipdog 字节
    data += b"\x00" * 4  # 4 字节的分隔符
    logger.debug(f"步骤 9: 添加 IPDOG ({ipdog.hex()}) 和分隔符 (00000000)")
    logger.debug(f"       当前数据包 = {data.hex()}")

    # 10. 主机名 (HostName)
    #     将 host_name 编码并填充到 32 字节
    data += (host_name.encode("utf-8", "ignore") + 32 * b"\x00")[:32]
    logger.debug("步骤 10: 添加主机名并填充至 32 字节")
    logger.debug(f"        当前数据包 = {data.hex()}")

    # 11. DNS 和 DHCP 服务器 IP
    try:
        # 主 DNS (Primary DNS)
        data += socket.inet_aton(primary_dns)
        logger.debug(
            f"        添加主 DNS = {socket.inet_aton(primary_dns).hex()} (来自 {primary_dns})"
        )
        # DHCP 服务器
        data += socket.inet_aton(dhcp_server)
        logger.debug(
            f"        添加 DHCP 服务器 = {socket.inet_aton(dhcp_server).hex()} (来自 {dhcp_server})"
        )
    except OSError as e:
        logger.error(
            f"无法构建登录包：提供的 DNS ({primary_dns}) 或 DHCP ({dhcp_server}) 服务器地址格式无效。"
        )
        raise ValueError("无效的 DNS 或 DHCP 服务器地址") from e

    # 次要DNS和WINS服务器似乎并不重要，DRCOM验证服务器通常不关心它们的值
    # 次 DNS (Secondary DNS, 通常为 0.0.0.0)
    data += b"\x00\x00\x00\x00"
    logger.debug("        添加次 DNS = 00000000")
    # WINS 服务器 (通常为 0.0.0.0 x 2)
    data += b"\x00" * 8
    logger.debug("        添加 WINS 服务器 (8 字节 00)")
    logger.debug(f"        当前数据包 = {data.hex()}")

    # 12. 操作系统版本信息 (_tagOSVERSIONINFO 结构)
    #     这部分通常使用固定的模拟值
    data += b"\x94\x00\x00\x00"  # OSVersionInfoSize 我不知道为何是 148，但是老代码是这么写的
    data += b"\x0a\x00\x00\x00"  # MajorVersion
    data += b"\x00\x00\x00\x00"  # MinorVersion
    data += b"\x58\x66\x00\x00"  # BuildNumber 此处取Windows 11 26200版本，即25H2
    data += b"\x02\x00\x00\x00"  # PlatformID (例如 2 代表 VER_PLATFORM_WIN32_NT)
    logger.debug("步骤 12: 添加 OS 版本固定头部信息")

    # 13. 操作系统标识字符串 (ServicePack 字段)
    data += (host_os.encode("utf-8", "ignore") + 32 * b"\x00")[:32]
    data += b"\x00" * 96  # 96 字节填充
    logger.debug("        添加 OS 标识字符串 (填充后)")
    logger.debug(f"        当前数据包 = {data.hex()}")

    # 14. 认证版本 (AUTH_VERSION)
    data += auth_version  # 从参数传入的 2 字节 auth_version  (出于未知的原因，官方客户端在这里显示2c00)
    logger.debug(f"步骤 14: 添加 AUTH_VERSION = {auth_version.hex()}")
    logger.debug(f"        当前数据包 = {data.hex()}")

    # 15. ROR 加密密码部分 (占位符)
    if ror_status:
        # 如果配置中启用了 ROR
        logger.warning("步骤 15: ROR 状态已启用，但 ROR 加密逻辑尚未实现！")
        # --- ROR 逻辑占位符 ---
        # 根据协议，ROR 部分通常包含 Code(0x00), Len(密码长度), 加密后的密码, 以及可能的填充字节。
        # 如果将来需要实现，需要在这里添加 _ror_encrypt 函数的调用和填充逻辑。
        # 目前，我们暂时不添加任何字节到 data 中。
        # 这可能会导致 ROR 模式下的认证失败，直到 ROR 逻辑被实现。
        # --- 占位符结束 ---
    else:
        # 如果配置中未启用 ROR，则正常跳过
        logger.debug("步骤 15: ROR 状态未启用，跳过 ROR 加密部分。")

    # 16. DrcomAuthExtData 结构 (包含 Checksum 2)
    #     Code (0x02) + Len (0x0c) + Checksum 2 (4字节) + Option (0x0000) + MAC地址 (6字节)
    logger.debug("步骤 16: 添加 DrcomAuthExtData 结构...")
    ext_data_prefix = data  # 记录当前数据，用于计算 Checksum 2
    # Checksum 2 的计算源: 当前数据 + 固定后缀 + dump(mac)
    # 注意：这里的 mac_address 是整数形式
    mac_bytes_for_checksum = binascii.unhexlify(format(mac_address, "012x").zfill(12))[
        -6:
    ]
    checksum2_input = (
        ext_data_prefix + b"\x01\x26\x07\x11\x00\x00" + mac_bytes_for_checksum
    )
    checksum2 = _calculate_checksum(checksum2_input)  # 调用校验和计算函数
    logger.debug(f"        计算 Checksum 2 源数据 = {checksum2_input.hex()}")  # 调试用

    ext_data = b"\x02"  # Code
    ext_data += b"\x0c"  # Len
    ext_data += checksum2  # 计算得到的 Checksum 2 (4字节)
    ext_data += b"\x00\x00"  # Option (通常为 0)
    # 再次添加 MAC 地址 (6字节)
    # mac_bytes = binascii.unhexlify(format(mac_address, '012x').zfill(12))[-6:] # 重复了上面的计算
    ext_data += mac_bytes_for_checksum  # 直接使用上面计算 checksum 时用的 bytes

    data += ext_data
    logger.debug("        添加 Code = 02")
    logger.debug("        添加 Len = 0c")
    logger.debug(f"        添加 Checksum2 = {checksum2.hex()}")
    logger.debug("        添加 Option = 0000")
    logger.debug(f"        添加 MAC 地址 = {mac_bytes_for_checksum.hex()}")
    logger.debug(f"        当前数据包 = {data.hex()}")

    # 17. 结尾字节
    #     现在 ROR 部分只是占位符，不添加字节，所以这里的逻辑应该按照非 ROR 情况处理
    #     但是，为了与之前的参考代码 保持一致，我们仍然根据 ror_status 判断
    if not ror_status:
        # 非 ROR 模式下，添加这两个字节
        data += b"\x00"  # auto logout / default: False
        data += b"\x00"  # broadcast mode / default : False
        logger.debug("步骤 17: 添加 AutoLogout (00) 和 BroadcastMode (00)")
    else:
        # ROR 模式下 (虽然未实现)，根据参考代码 跳过这两个字节
        logger.debug(
            "步骤 17: ROR 模式 (即使未实现)，跳过 AutoLogout 和 BroadcastMode 字节"
        )
        pass

    # 18. 末尾未知字节
    data += b"\xe9\x13"
    logger.debug("步骤 18: 添加末尾未知字节 = e913")
    logger.debug(f"        最终登录数据包 = {data.hex()}")
    logger.info(f"登录数据包构建完成，总长度: {len(data)} 字节。")

    return data  # 返回构建完成的数据包


# 发送登录包函数
def send_login_request(
    sock: socket.socket, server_address: str, drcom_port: int, packet: bytes
) -> None:
    """
    发送登录请求包到服务器。

    Args:
        sock: 用于通信的 UDP socket 对象。
        server_address: Dr.COM 服务器 IP 地址。
        drcom_port: Dr.COM 服务器端口。
        packet: 已构建好的登录请求包 (bytes)。

    Raises:
        socket.error: 如果发送失败。
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
    response_data: bytes, server_ip: str, received_from_ip: str
) -> Tuple[bool, Optional[bytes], Optional[int], str]:
    """
    解析 Dr.COM 服务器返回的登录响应包。

    Args:
        response_data (bytes): 收到的原始响应字节串。
        server_ip (str): 期望的服务器 IP 地址。
        received_from_ip (str): 实际发送响应的 IP 地址。

    Returns:
        tuple: (is_success, auth_info, error_code, message)
            - is_success (bool): 登录是否成功。
            - auth_info (Optional[bytes]): 成功时，提取的心跳认证信息 (tail)，否则为 None。
            - error_code (Optional[int]): 失败时，提取的错误代码 (整数)，成功或无法解析时为 None。
            - message (str): 描述登录结果或错误原因的消息。
    """
    logger.debug(f"开始解析登录响应: {response_data.hex()}")
    if not response_data or received_from_ip != server_ip:
        logger.warning(f"收到无效响应或来源不匹配 (来自: {received_from_ip})。")
        return False, None, None, "收到无效响应或来源不匹配"

    response_code = response_data[0]  # 第一个字节是响应代码

    if response_code == 0x04:  # Code 0x04 表示成功
        if len(response_data) >= 39:  # 检查长度是否足够提取 auth_info
            auth_info = response_data[23:39]  # 提取 auth_info (tail)
            logger.info("登录成功！")
            logger.debug(f"提取到 Auth Info (Tail): {auth_info.hex()}")
            return True, auth_info, None, "登录成功"
        else:
            logger.error("登录成功响应包过短，无法提取 Auth Info。")
            return False, None, None, "登录成功响应包过短"

    elif response_code == 0x05:  # Code 0x05 表示失败
        error_code = None
        error_message = "登录失败"
        if len(response_data) > 4:  # 尝试提取错误代码 (通常在第 5 个字节，索引 4)
            error_code = response_data[4]
            # 可以根据 error_code 添加更详细的错误消息
            error_map = {
                0x01: "账号正在使用中或认证 MAC/IP 不匹配",
                0x03: "账号或密码错误",
                0x04: "账号余额不足或流量/时长超限",
                0x05: "账号被冻结或暂停使用",
                0x07: "IP 地址不匹配",
                0x0B: "MAC 地址不匹配",
                0x14: "登录 IP 数量超限",
                0x15: "客户端版本不匹配或账号被禁用",
                0x16: "IP 和 MAC 地址同时绑定错误",
                0x17: "服务器要求使用 DHCP 获取 IP",
                0x02: "服务器繁忙",
            }
            error_message += f" (错误码: {hex(error_code)}) - {error_map.get(error_code, '未知错误')}"
        logger.error(error_message)
        return False, None, error_code, error_message

    else:  # 未知的响应代码
        logger.error(f"收到未知的登录响应代码: {hex(response_code)}")
        return False, None, None, f"收到未知的登录响应代码: {hex(response_code)}"
