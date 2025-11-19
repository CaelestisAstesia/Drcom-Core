# 架构概览 (v1.0.0-alpha.1)

`drcom-core` 的设计核心是**职责分离 (Separation of Concerns)**。其目标是构建一个高内聚、低耦合的认证库，将“协议实现”与“核心逻辑”解耦，使其易于维护、测试和扩展。

## 1. 核心设计哲学

我们遵循以下几个关键原则：

1.  **引擎/策略 分离：**
    * `DrcomCore` (引擎) 作为 API 入口，它不关心认证的 *具体步骤*。
    * 它只知道自己持有一个符合 `BaseProtocol` 接口 的 `protocol` 对象（策略）。
    * 当 `core.login()` 被调用时，它仅仅是委托 `self.protocol.login()` 来执行。
    * **好处：** 未来支持 P 版时，我们只需实现一个新的 `P_Protocol` 策略，引擎代码 *无需改动*。

2.  **状态/逻辑 分离：**
    * 认证过程中所有 *易变的状态*（如 `salt`, `auth_info`, `keep_alive_serial_num`）被统一存储在 `DrcomState` (数据类) 中。
    * `DrcomCore` 和 `D_Protocol` (逻辑) 都持有 `state` 对象的引用。
    * **好处：** 逻辑执行层 (`D_Protocol`) 本身是无状态的，它只是读取 `config` 并修改 `state`。

3.  **逻辑/I/O 分离：**
    * `drcom-core` 库中，**只有 `NetworkClient` (`network.py`) 允许 `import socket`**。
    * `D_Protocol` (逻辑) **绝不**直接执行 `socket.sendto()`。它必须调用 `self.net_client.send()`。
    * **好处：** I/O 操作被封装。这使得 `D_Protocol` 的单元测试变得极其简单：我们只需 Mock `net_client` 对象，而无需处理真实的 UDP 收发。

4.  **配置/代码 分离：**
    * 所有配置（IP, MAC, 版本号等）都被 `load_config_from_dict` 解析并冻结在 `DrcomConfig` (不可变数据类) 中。
    * `DrcomConfig` 作为依赖项被注入到 `DrcomCore` 和 `D_Protocol`。
    * **好处：** 库中没有任何硬编码的学校配置。

5.  **协议包/协议逻辑 分离：**
    * `src/drcom_core/protocols/` (包) 下的 `login.py`, `keep_alive.py` 等文件只包含**纯函数 (Pure Functions)**。
    * 它们负责 *构建* (build) 和 *解析* (parse) 数据包，是无状态的。
    * **好处：** 这部分是协议拟真度（Fidelity）的核心，可以被独立、完整地进行单元测试。

## 2. 组件职责

* `DrcomCore` (`core.py`)：
    * **角色：引擎 / 编排器 (Orchestrator)**。
    * 职责：
        1.  提供 `login()`, `start_heartbeat()`, `logout()` 公共 API。
        2.  初始化 `DrcomConfig`, `DrcomState`, `NetworkClient`。
        3.  根据 `config.protocol_version` 加载正确的协议策略（如 `D_Protocol`）。
        4.  管理心跳 `threading.Thread` 的生命周期（启动、停止、`_heartbeat_loop` 循环）。
        5.  将 API 调用委托给 `self.protocol`。

* `DrcomConfig` (`config.py`)：
    * **角色：只读配置 (Read-Only Config)**。
    * 职责：
        1.  `@dataclass(frozen=True)` 确保配置在运行时不可变。
        2.  `load_config_from_dict()` 负责验证原始 `dict` (来自 .env) 并将其转换为强类型（如 `mac_address: int`, `host_ip_bytes: bytes`）。

* `DrcomState` (`state.py`)：
    * **角色：易变状态 (Mutable State)**。
    * 职责：存储所有认证会话信息，如 `salt`, `auth_info`, `login_success` 等。

* `NetworkClient` (`network.py`)：
    * **角色：网络 I/O 封装**。
    * 职责：
        1.  **唯一** `import socket` 的地方。
        2.  初始化时 `socket.bind()` 到 `61440` 端口（D 版要求）。
        3.  提供 `send()` 和 `receive()` 方法。

* `BaseProtocol` (`protocols/base.py`)：
    * **角色：策略接口 (Strategy Interface)**。
    * 职责：定义 `login`, `keep_alive`, `logout` 抽象方法，确保所有协议策略都遵守此“契约”。

* `D_Protocol` (`protocols/version_520d.py`)：
    * **角色：D 版策略实现 (Concrete Strategy)**。
    * 职责：
        1.  实现 `BaseProtocol` 接口。
        2.  编排 D 版的完整认证流程（如 `_challenge`, `_login`, `_manage_keep_alive2_sequence`）。
        3.  通过 `self.net_client` 执行 I/O。
        4.  读写 `self.state`。

* `protocols/*.py` (`login.py`, `challenge.py`, `keep_alive.py`)：
    * **角色：工具包 (Toolkit)**。
    * 职责：提供无状态的、纯粹的 `build_...` 和 `parse_...` 函数，供策略层 (`D_Protocol`) 调用。

## 3. 核心数据流 (以 `login` 为例)

1.  **应用层 (`run.py`)**：
    * `config = load_config_from_dict(...)`
    * `core = DrcomCore(config)`
    * `core.login()`

2.  **引擎 (`core.py`)**：
    * `DrcomCore.login()` 被调用。
    * 它委托 `self.protocol.login()`（此时 `self.protocol` 是 `D_Protocol` 实例）。

3.  **策略层 (`version_520d.py`)**：
    * `D_Protocol.login()` 被调用。
    * 它首先调用 `self._challenge()`。
    * `D_Protocol._challenge()`...
        * 调用 `challenge.build_challenge_request()`。
        * 调用 `self.net_client.send()`。
        * 调用 `self.net_client.receive()`。
        * 调用 `challenge.parse_challenge_response()`。
        * **[状态变更]** `self.state.salt = ...`。
    * `D_Protocol.login()` 检查 `_challenge()` 结果。
    * 它接着调用 `self._login()`。
    * `D_Protocol._login()`...
        * 调用 `login.build_login_packet(self.config, self.state.salt, ...)`。
        * 调用 `self.net_client.send()`。
        * 调用 `self.net_client.receive()`。
        * 调用 `login.parse_login_response()`。
        * **[状态变更]** `self.state.auth_info = ...`。
        * **[状态变更]** `self.state.login_success = True`。
    * `D_Protocol.login()` 返回 `True`。

4.  **引擎 (`core.py`)**：
    * `DrcomCore.login()` 收到 `True`，返回 `True`。

5.  **应用层 (`run.py`)**：
    * `core.login()` 返回 `True`，程序继续。

