# File: src/drcom_core/exceptions.py
"""
Dr.COM 核心库 - 异常体系 (Exceptions)

定义库内统一使用的异常类，以便上层应用（如 CLI/GUI）能进行精细的错误处理。
"""

from enum import IntEnum


class DrcomError(Exception):
    """Dr.COM 核心库的所有内部异常的基类。

    上层应用可以通过捕获此异常来处理所有由 drcom-core 抛出的已知错误。
    """

    pass


class ConfigError(DrcomError):
    """配置加载或校验失败。

    触发场景:
    1. 缺少必要字段 (如 username/password)。
    2. 字段格式错误 (如 IP 地址非法、Hex 字符串无法解析)。
    3. 找不到配置文件或环境变量。
    """

    pass


class NetworkError(DrcomError):
    """网络层面的错误 (I/O 级别)。

    触发场景:
    1. Socket 创建失败或端口被占用。
    2. 发送 (send) 或 接收 (recv) 超时。
    3. DNS 解析失败。
    4. 物理连接中断。

    注意: 此类错误通常是暂时的，上层逻辑应尝试重试 (Retry)。
    """

    pass


class ProtocolError(DrcomError):
    """协议交互错误 (逻辑级别)。

    触发场景:
    1. 收到非 Dr.COM 协议的数据包 (Magic Number 不匹配)。
    2. 校验和 (Checksum/CRC) 验证失败。
    3. 数据包长度不足或结构损坏。
    4. 收到非预期的响应代码 (如 Challenge 阶段收到 Logout 包)。
    """

    pass


class StateError(DrcomError):
    """状态机错误 (FSM Violation)。

    触发场景:
    1. 在未登录状态下尝试注销。
    2. 在未登录状态下尝试启动心跳。
    3. 在已登录状态下重复调用登录。
    """

    pass


class AuthErrorCode(IntEnum):
    """Dr.COM 认证失败错误代码枚举。

    这些代码直接来自登录失败响应包 (0x05) 的第 5 字节 (Index 4)。
    """

    IN_USE_WIRED = 0x01  # 有人正在使用这个账号，且是有线的方式
    SERVER_BUSY = 0x02  # 服务器繁忙 (通常需要退避重试)
    WRONG_PASSWORD = 0x03  # 密码错误
    INSUFFICIENT_FUNDS = 0x04  # 余额不足或时长超限
    ACCOUNT_FROZEN = 0x05  # 账号被冻结/暂停使用
    WRONG_IP = 0x07  # IP地址不匹配 (常见于双网卡环境选错网卡)
    WRONG_MAC = 0x0B  # MAC地址不匹配 (常见于路由器克隆 MAC 失败)
    TOO_MANY_IP = 0x14  # 在线 IP 数量过多 (超出一号多端限制)
    WRONG_VERSION = 0x15  # 客户端版本不正确 (需升级协议版本)
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
        """获取错误码对应的人类可读中文描述。

        Returns:
            str: 对应的中文错误提示。
        """
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
    """认证被拒绝 (业务层面的失败)。

    当登录请求被服务器明确拒绝 (收到 0x05 包) 时抛出。
    这通常意味着不可恢复的配置错误 (如密码错)，需要用户干预。
    """

    def __init__(self, message: str, error_code: int | None = None) -> None:
        """初始化认证错误。

        Args:
            message: 错误描述信息。
            error_code: 原始错误代码。构造函数会自动尝试将其转换为
                AuthErrorCode 枚举，并使用标准化的中文描述覆盖 message。
        """
        self.error_code_enum: AuthErrorCode | None = None

        if error_code is not None:
            try:
                self.error_code_enum = AuthErrorCode(error_code)
                # 如果有标准的错误描述，优先使用标准描述，保证 UI 显示一致性
                message = f"{self.error_code_enum.description}"
            except ValueError:
                # 如果是未知的错误码，保留原始 message 并记录
                pass

        super().__init__(message)
        self.error_code = error_code
