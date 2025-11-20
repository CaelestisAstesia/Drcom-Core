# API 参考手册

Drcom-Core 的公共 API 设计简洁，主要围绕 DrcomCore 引擎类展开。

## 核心引擎 (drcom_core.core)

### class DrcomCore

Dr.COM 认证核心引擎。负责编排协议策略、网络客户端和状态管理。

#### __init__(self, config: DrcomConfig, status_callback: Callable[[CoreStatus, str], None] | None = None)

* config: 已加载的配置对象。
* status_callback: (可选) 状态变更回调函数。接收 (status, message) 两个参数。

#### login(self) -> bool

执行登录流程。
* 返回: True 表示登录成功，False 表示失败。
* 异常: 可能会抛出 AuthError (密码错误等) 或 NetworkError。

#### start_heartbeat(self) -> None

启动后台心跳守护线程。
* 前提: 必须先调用 login() 成功且状态为 LOGGED_IN。
* 该线程会自动处理心跳包发送和异常重试。

#### stop(self) -> None

停止引擎。
* 设置停止信号，等待心跳线程结束。
* 尝试发送注销 (Logout) 数据包。
* 关闭网络套接字。

---

## 状态管理 (drcom_core.state)

### class CoreStatus(Enum)

核心引擎的生命周期状态枚举。

* IDLE: 初始化完成，未操作。
* CONNECTING: 正在执行 Challenge 或 Login 流程。
* LOGGED_IN: 登录成功，等待心跳启动。
* HEARTBEAT: 心跳线程正在运行 (在线保活中)。
* OFFLINE: 已离线 (主动登出或掉线)。
* ERROR: 发生错误。

### class DrcomState

存储会话的动态数据。

* salt (bytes): 挑战获取的盐值。
* auth_info (bytes): 登录成功后获取的 Token (用于心跳)。
* status (CoreStatus): 当前状态。
* is_online (property): 辅助属性，判断是否处于 LOGGED_IN 或 HEARTBEAT 状态。

---

## 异常体系 (drcom_core.exceptions)

所有异常均继承自 DrcomError。

* DrcomError: 基类。
* ConfigError: 配置加载或校验失败。
* NetworkError: Socket 错误或超时。
* AuthError: 认证被拒绝 (如密码错误)。包含 error_code 属性 (如 0x03)。
* ProtocolError: 协议交互数据异常。
