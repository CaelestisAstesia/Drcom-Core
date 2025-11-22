# src/drcom_core/exceptions.py

"""
Dr.COM 核心库 - 异常体系

定义库内统一使用的异常类，以便上层应用（如 CLI/GUI）能进行精细的错误处理。
"""

from enum import IntEnum
from typing import Optional


class DrcomError(Exception):
    """
    Dr.COM 核心库的所有内部异常的基类。
    """

    pass


class ConfigError(DrcomError):
    """配置加载或校验失败。"""

    pass


class NetworkError(DrcomError):
    """网络层面的错误。"""

    pass


class ProtocolError(DrcomError):
    """协议交互错误。"""

    pass


class AuthErrorCode(IntEnum):
    """
    Dr.COM 认证失败错误代码 (来自 0x05 响应包)。
    """

    IN_USE = 0x01  # 账号在线或MAC绑定错误
    SERVER_BUSY = 0x02  # 服务器繁忙
    WRONG_PASSWORD = 0x03  # 密码错误
    INSUFFICIENT_FUNDS = 0x04  # 余额不足或欠费
    FROZEN = 0x05  # 账号被冻结
    WRONG_IP = 0x07  # IP地址不匹配
    WRONG_MAC = 0x0B  # MAC地址不匹配
    TOO_MANY_IP = 0x14  # IP 数量过多
    WRONG_VERSION = 0x15  # 客户端版本不匹配
    WRONG_IP_MAC = 0x16  # IP/MAC 绑定错误
    FORCE_DHCP = 0x17  # 强制 DHCP


class AuthError(DrcomError):
    """
    认证逻辑错误 (业务层面的失败)。
    """

    def __init__(self, message: str, error_code: Optional[int] = None):
        """
        初始化认证错误。

        Args:
            message: 错误描述信息。
            error_code: 原始错误代码。会自动尝试转换为 AuthErrorCode 枚举。
        """
        super().__init__(message)

        self.error_code: int | AuthErrorCode | None = error_code
        """Dr.COM 服务器返回的错误代码。"""

        if error_code is not None:
            try:
                self.error_code = AuthErrorCode(error_code)
            except ValueError:
                # 如果收到未知的代码，保持 int 原值
                pass
