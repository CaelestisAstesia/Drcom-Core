# src/drcom_core/exceptions.py
"""
Dr.COM 核心库 - 异常体系

定义库内统一使用的异常类，以便上层应用（如 CLI/GUI）能进行精细的错误处理。
"""

from typing import Optional


class DrcomError(Exception):
    """
    Dr.COM 核心库的所有内部异常的基类。
    捕获此异常可处理所有库抛出的已知错误。
    """

    pass


class ConfigError(DrcomError):
    """
    配置加载或校验失败。
    例如：MAC 地址格式错误、缺少必要字段、IP 地址非法。
    """

    pass


class NetworkError(DrcomError):
    """
    网络层面的错误。
    例如：Socket 绑定失败 (端口占用)、发送/接收超时、网络不可达。
    """

    pass


class ProtocolError(DrcomError):
    """
    协议交互错误。
    例如：收到非预期的包头、Checksum 校验失败、响应包长度不足、无法解析 Challenge。
    """

    pass


class AuthError(DrcomError):
    """
    认证逻辑错误 (业务层面的失败)。
    通常指服务器明确返回了 0x05 失败包。
    """

    def __init__(self, message: str, error_code: Optional[int] = None):
        """
        初始化认证错误。

        Args:
            message: 错误描述信息。
            error_code: Dr.COM 服务器返回的原始错误代码 (如 0x01, 0x03)。
                        如果无法提取，则为 None。
        """
        super().__init__(message)
        self.error_code = error_code
        """Dr.COM 服务器返回的原始错误代码 (如 0x01, 0x03)。"""
