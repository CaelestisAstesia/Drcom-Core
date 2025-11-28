# src/drcom_core/exceptions.py
"""
Dr.COM 核心库 - 异常体系 (Exceptions)

定义库内统一使用的异常类，以便上层应用（如 CLI/GUI）能进行精细的错误处理。
参考资料: drcom-generic/analyses/error_no.md
"""

from enum import IntEnum
from typing import Optional


class DrcomError(Exception):
    """Dr.COM 核心库的所有内部异常的基类"""

    pass


class ConfigError(DrcomError):
    """配置加载或校验失败"""

    pass


class NetworkError(DrcomError):
    """
    网络层面的错误。
    如: Socket 创建失败、端口占用、发送/接收超时、DNS 解析失败。
    """

    pass


class ProtocolError(DrcomError):
    """
    协议交互错误。
    如: 收到非预期的包头、校验和不匹配、数据长度不足。
    """

    pass


class StateError(DrcomError):
    """状态机错误 (如未登录时尝试注销)"""

    pass


class AuthErrorCode(IntEnum):
    """
    Dr.COM 认证失败错误代码 (来自 0x05 响应包)。
    """

    IN_USE_WIRED = 0x01  # 有人正在使用这个账号，且是有线的方式
    SERVER_BUSY = 0x02  # 服务器繁忙
    WRONG_PASSWORD = 0x03  # 密码错误
    INSUFFICIENT_FUNDS = 0x04  # 余额不足或时长超限
    ACCOUNT_FROZEN = 0x05  # 账号被冻结/暂停使用
    WRONG_IP = 0x07  # IP地址不匹配
    WRONG_MAC = 0x0B  # MAC地址不匹配
    TOO_MANY_IP = 0x14  # IP 数量过多
    WRONG_VERSION = 0x15  # 客户端版本不正确 (需升级)
    WRONG_IP_MAC_BIND = 0x16  # IP/MAC 绑定错误
    FORCE_DHCP = 0x17  # 禁止静态 IP，强制 DHCP

    # 预留/未知错误码
    UNKNOWN_18 = 0x18
    UNKNOWN_19 = 0x19
    UNKNOWN_1A = 0x1A
    UNKNOWN_1B = 0x1B
    UNKNOWN_1C = 0x1C

    @property
    def description(self) -> str:
        """返回错误码对应的中文描述"""
        _DESC_MAP = {
            0x01: "账号已在别处登录 (有线)",
            0x02: "服务器繁忙，请稍后重试",
            0x03: "账号或密码错误",
            0x04: "账户余额不足或时长超限",
            0x05: "账号已暂停使用",
            0x07: "IP地址不匹配 (请检查是否获取到了正确的内网IP)",
            0x0B: "MAC地址不匹配",
            0x14: "在线IP数量超出限制",
            0x15: "客户端版本过低或账号被封禁",
            0x16: "IP/MAC 绑定错误",
            0x17: "检测到静态IP，请改为自动获取 (DHCP)",
        }
        return _DESC_MAP.get(self.value, f"未知认证错误 (Code: {hex(self.value)})")


class AuthError(DrcomError):
    """
    认证被拒绝 (业务层面的失败)。
    """

    def __init__(self, message: str, error_code: Optional[int] = None):
        """
        初始化认证错误。

        Args:
            message: 错误描述信息。
            error_code: 原始错误代码。会自动尝试转换为 AuthErrorCode 枚举。
        """
        self.error_code_enum: Optional[AuthErrorCode] = None

        if error_code is not None:
            try:
                self.error_code_enum = AuthErrorCode(error_code)
                # 如果有标准的错误描述，优先使用
                message = f"{self.error_code_enum.description}"
            except ValueError:
                pass

        super().__init__(message)
        self.error_code = error_code
