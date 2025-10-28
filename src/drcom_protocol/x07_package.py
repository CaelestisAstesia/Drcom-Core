import binascii
import socket  # 用于 IP 地址转换
from typing import Optional


def build_keep_alive2_packet_custom_tail_logic(
    packet_number: int,
    tail_to_use: bytes,  # 这个 tail 根据你的新规则传入
    packet_type: int,
    host_ip: str,
    keep_alive_version: bytes,
    is_first_packet: bool = False,
) -> Optional[bytes]:
    """
    根据指定规则构建 Dr.COM 的 \x07 心跳包 (keep_alive2 类型)。

    结构: 07 + number + 28000b + type + version + 2f12 + 00*6 + tail_to_use + 00*4 + specific_part

    特殊 Tail 继承规则 (根据用户指定):
    - 发送 Type 1 包 (非第一个包) 时，传入的 tail_to_use 应等于【上一个发送的 Type 3 包所使用的 tail 值】。
    - 发送 Type 3 包时，传入的 tail_to_use 应等于【上一个 Type 1 响应包 data[16:20]】。
    - 对于流程最初的 Type 1 包，tail 通常为 b'\x00'*4。

    Args:
        packet_number: 包序号 (0-255 循环)。
        tail_to_use: 4 字节的 tail 值 (bytes 类型)。根据上述特殊规则传入。
        packet_type: 包类型，通常是 1 或 3。
        host_ip: 当前客户端的 IP 地址字符串。
        keep_alive_version: 2 字节的心跳版本号 (bytes 类型, 例如 b'\xdc\x02')。
        is_first_packet: 是否是整个 keep_alive2 序列中的第一个包。默认为 False。

    Returns:
        Optional[bytes]: 构建成功的心跳包，如果参数无效则返回 None。
    """
    # 1. 参数校验 (同前)
    if not isinstance(packet_number, int) or not (0 <= packet_number <= 255):
        print(f"错误：packet_number ({packet_number}) 无效。")
        return None
    if not isinstance(tail_to_use, bytes) or len(tail_to_use) != 4:
        print("错误：tail_to_use 无效或长度不为 4 字节。")
        return None
    if packet_type not in [1, 3]:
        print(f"错误：packet_type ({packet_type}) 无效。")
        return None
    if not isinstance(keep_alive_version, bytes) or len(keep_alive_version) != 2:
        print("错误：keep_alive_version 无效。")
        return None

    # 2. 构建数据包头部和公共部分
    try:
        data = b"\x07"
        data += bytes([packet_number])
        data += b"\x28\x00\x0b"
        data += bytes([packet_type])

        if is_first_packet:
            data += b"\x0f\x27"
        else:
            data += keep_alive_version

        data += b"\x2f\x12"  # 固定部分
        data += b"\x00" * 6  # 填充
        data += tail_to_use  # 使用传入的 tail
        data += b"\x00" * 4  # 填充

    except Exception as e:
        print(f"构建数据包公共部分时出错: {e}")
        return None

    # 3. 构建类型特定部分 (specific_part) - 16字节
    try:
        if packet_type == 3:
            crc = b"\x00" * 4
            host_ip_bytes = socket.inet_aton(host_ip)
            padding_end = b"\x00" * 8
            specific_part = crc + host_ip_bytes + padding_end
        else:  # packet_type == 1
            specific_part = b"\x00" * 16

        data += specific_part

    except socket.error:
        print(f"错误：转换 host_ip '{host_ip}' 失败。")
        return None
    except Exception as e:
        print(f"构建数据包类型特定部分时出错: {e}")
        return None

    return data


def build_keep_alive2_packet_py3(
    packet_number: int,
    tail: bytes,
    packet_type: int,
    host_ip: str,
    keep_alive_version: bytes,
    is_first_packet: bool = False,
) -> Optional[bytes]:
    """
    构建 Dr.COM 的 \x07 心跳包 (keep_alive2 类型)，基于 latest-wired-python3.py 实现。


    结构: 07 + number + 28000b + type + version + 2f12 + 00*6 + tail + 00*4 + specific_part


    Tail 使用说明 (源自 latest-wired-python3.py 的 keep_alive2 函数逻辑):
    - 此函数需要调用者传入 `tail` 参数。
    - 根据源文件 `keep_alive2` 函数的实现，这个 `tail` 值应来自于**上一个收到的响应包**的 data[16:20] 部分。
    - 例如，在发送 Type 3 包之前，会收到一个 Type 1 包的响应，应从该响应中提取 tail 并传入本函数来构建 Type 3 包。
    - 同样，在发送 Type 1 包（循环中）之前，会收到一个 Type 3 包的响应，应从该响应中提取 tail 并传入本函数来构建 Type 1 包。
    - 对于流程最初的 Type 1 包，源文件中使用 b'\\x00'*4 作为 tail。

    Args:
        packet_number: 包序号 (0-255 循环)。
        tail: 4 字节的 tail 值 (bytes 类型)，来自上一个响应包。
        packet_type: 包类型，通常是 1 或 3。
        host_ip: 当前客户端的 IP 地址字符串。
        keep_alive_version: 2 字节的心跳版本号 (bytes 类型, 例如 b'\\xdc\\x02')。
        is_first_packet: 是否是整个 keep_alive2 序列中的第一个包。默认为 False。

    Returns:
        Optional[bytes]: 构建成功的心跳包，如果参数无效则返回 None。
    """
    # 1. 参数校验
    if not isinstance(packet_number, int) or not (0 <= packet_number <= 255):
        print(f"错误：packet_number ({packet_number}) 无效，应为 0-255 之间的整数。")
        return None
    if not isinstance(tail, bytes) or len(tail) != 4:
        # 在源文件的 keep_alive2 函数中，从响应 data[16:20] 获取 tail
        print(
            f"错误：tail 无效或长度不为 4 字节 (实际: {len(tail) if isinstance(tail, bytes) else '非bytes'})。"
        )
        return None
    if packet_type not in [1, 3]:
        print(f"错误：packet_type ({packet_type}) 无效，应为 1 或 3。")
        return None
    if not isinstance(keep_alive_version, bytes) or len(keep_alive_version) != 2:
        print("错误：keep_alive_version 无效或长度不为 2 字节。")
        return None

    # 2. 构建数据包头部和公共部分
    try:
        data = b"\x07"  # Code: 0x07
        data += bytes([packet_number])  # Number (ID)
        data += b"\x28\x00\x0b"  # 固定部分
        data += bytes([packet_type])  # Type (1 or 3)

        # Version 字段
        if is_first_packet:
            data += b"\x0f\x27"  # 第一个包固定为此值
        else:
            data += keep_alive_version  # 后续包使用配置的版本号

        data += b"\x2f\x12"  # 固定部分
        data += b"\x00" * 6  # 6字节填充
        data += tail  # 传入的 tail (来自上一个响应)
        data += b"\x00" * 4  # 4字节填充

    except Exception as e:
        print(f"构建数据包公共部分时出错: {e}")
        return None

    # 3. 构建类型特定部分 (specific_part) - 16字节
    try:
        if packet_type == 3:
            # Type 3: CRC(0) + Host IP + Padding(8)
            crc = b"\x00" * 4  # CRC，脚本中实际填充 0
            host_ip_bytes = socket.inet_aton(host_ip)  # IP 转 bytes
            padding_end = b"\x00" * 8  # 8字节末尾填充
            specific_part = crc + host_ip_bytes + padding_end
        else:  # packet_type == 1
            # Type 1: Padding(16)
            specific_part = b"\x00" * 16  # 16 字节填充 0

        data += specific_part

    except socket.error:
        print(f"错误：转换 host_ip '{host_ip}' 失败，请检查 IP 地址格式。")
        return None
    except Exception as e:
        print(f"构建数据包类型特定部分时出错: {e}")
        return None

    # 返回构建好的包 (Python 3 bytes 类型)
    return data


# --- 示例用法 (与之前的示例类似，演示 tail 如何根据源文件逻辑更新) ---
if __name__ == "__main__":
    # 假设的配置值
    example_host_ip = "10.30.22.17"
    example_keep_alive_version = b"\xdc\x02"

    # 初始状态
    current_packet_number = 0
    current_tail = b"\x00\x00\x00\x00"  # 初始 tail

    print("--- 模拟 keep_alive2 流程 (基于源文件 Tail 逻辑) ---")

    # 1. 发送第一个 type=1 包 (is_first=True, tail=0000)
    packet1 = build_keep_alive2_packet_py3(
        current_packet_number,
        current_tail,
        1,
        example_host_ip,
        example_keep_alive_version,
        is_first_packet=True,
    )
    if packet1:
        print(f"\n构建: 第 {current_packet_number} 包 (Type 1, First)")
        print(f"  Hex: {binascii.hexlify(packet1).decode()}")
        # 模拟收到响应1
        simulated_response1_data = (
            b"\x07\x00\x28\x00\x0b\x02"
            + example_keep_alive_version
            + b"\x2f\x12"
            + b"\x00" * 6
            + b"\xaa\xbb\xcc\xdd"
            + b"\x00" * 20
        )  # 假设响应
        current_tail = simulated_response1_data[16:20]  # 从响应更新 tail
        print(
            f"(模拟收到响应1, 更新 Tail 为: {binascii.hexlify(current_tail).decode()})"
        )
        current_packet_number = (current_packet_number + 1) % 256
    else:
        exit()

    # 2. 发送第二个 type=1 包 (is_first=False, tail=来自响应1)
    # 注意: 源文件逻辑是第二个 type 1 包依然用 0000 发送，然后用其响应更新 tail 给 type 3
    # 这里我们严格按照代码逻辑模拟
    packet2 = build_keep_alive2_packet_py3(
        current_packet_number,
        b"\x00" * 4,
        1,  # 仍然用 0000 发送
        example_host_ip,
        example_keep_alive_version,
        is_first_packet=False,
    )
    if packet2:
        print(f"\n构建: 第 {current_packet_number} 包 (Type 1)")
        print(f"  Hex: {binascii.hexlify(packet2).decode()}")
        # 模拟收到响应2
        simulated_response2_data = (
            b"\x07\x01\x28\x00\x0b\x02"
            + example_keep_alive_version
            + b"\x2f\x12"
            + b"\x00" * 6
            + b"\x11\x22\x33\x44"
            + b"\x00" * 20
        )
        current_tail = simulated_response2_data[16:20]  # 从响应更新 tail
        print(
            f"(模拟收到响应2, 更新 Tail 为: {binascii.hexlify(current_tail).decode()})"
        )
        current_packet_number = (current_packet_number + 1) % 256
    else:
        exit()

    # 3. 发送第一个 type=3 包 (is_first=False, tail=来自响应2)
    packet3 = build_keep_alive2_packet_py3(
        current_packet_number,
        current_tail,
        3,  # 使用响应2的 tail
        example_host_ip,
        example_keep_alive_version,
        is_first_packet=False,
    )
    if packet3:
        print(f"\n构建: 第 {current_packet_number} 包 (Type 3)")
        print(f"  Hex: {binascii.hexlify(packet3).decode()}")
        # 模拟收到响应3
        simulated_response3_data = (
            b"\x07\x02\x28\x00\x0b\x04"
            + example_keep_alive_version
            + b"\x2f\x12"
            + b"\x00" * 6
            + b"\x55\x66\x77\x88"
            + b"\x00" * 20
        )
        current_tail = simulated_response3_data[16:20]  # 从响应更新 tail
        print(
            f"(模拟收到响应3, 更新 Tail 为: {binascii.hexlify(current_tail).decode()})"
        )
        current_packet_number = (current_packet_number + 1) % 256
    else:
        exit()

    print("\n--- 进入稳定循环 ---")

    # 4. 发送 Type 1 包 (is_first=False, tail=来自响应3)
    packet4 = build_keep_alive2_packet_py3(
        current_packet_number,
        current_tail,
        1,  # 使用响应3的 tail
        example_host_ip,
        example_keep_alive_version,
        is_first_packet=False,
    )
    if packet4:
        print(f"\n构建: 第 {current_packet_number} 包 (Type 1, 循环中)")
        print(f"  Hex: {binascii.hexlify(packet4).decode()}")
        # 模拟收到响应4
        simulated_response4_data = (
            b"\x07\x03\x28\x00\x0b\x02"
            + example_keep_alive_version
            + b"\x2f\x12"
            + b"\x00" * 6
            + b"\xab\xcd\xef\x01"
            + b"\x00" * 20
        )
        current_tail = simulated_response4_data[16:20]  # 从响应更新 tail
        print(
            f"(模拟收到响应4, 更新 Tail 为: {binascii.hexlify(current_tail).decode()})"
        )
        current_packet_number = (current_packet_number + 1) % 256
    else:
        exit()

    # 5. 发送 Type 3 包 (is_first=False, tail=来自响应4)
    packet5 = build_keep_alive2_packet_py3(
        current_packet_number,
        current_tail,
        3,  # 使用响应4的 tail
        example_host_ip,
        example_keep_alive_version,
        is_first_packet=False,
    )
    if packet5:
        print(f"\n构建: 第 {current_packet_number} 包 (Type 3, 循环中)")
        print(f"  Hex: {binascii.hexlify(packet5).decode()}")
        # 模拟收到响应5
        simulated_response5_data = (
            b"\x07\x04\x28\x00\x0b\x04"
            + example_keep_alive_version
            + b"\x2f\x12"
            + b"\x00" * 6
            + b"\xfe\xdc\xba\x98"
            + b"\x00" * 20
        )
        current_tail = simulated_response5_data[16:20]  # 从响应更新 tail
        print(
            f"(模拟收到响应5, 更新 Tail 为: {binascii.hexlify(current_tail).decode()})"
        )
        current_packet_number = (current_packet_number + 1) % 256
    else:
        exit()
