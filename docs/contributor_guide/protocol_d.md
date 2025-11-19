# D 版协议详解 (drcom-core 实现)

本文档映射了 Dr.Com 5.2.0(D) 版协议的认证流程与 `drcom-core` 库的内部代码实现。

本文档的目标读者是 `drcom-core` 的贡献者。

## 1. Challenge 阶段 (Code 0x01, 0x02)

**协议流：**
客户端向服务器 `61440` 端口发送 `0x01` Challenge 请求包。服务器返回 `0x02` 响应包，其中 `[4:8]` 字节为关键的 4 字节 `Salt`。

**代码映射：**

* **包构建/解析 (纯函数)：**
    * `src/drcom_core/protocols/challenge.py`
    * `build_challenge_request()`: 构建 `0x01` 包。
    * `parse_challenge_response()`: 从 `0x02` 响应中提取 `Salt`。

* **流程编排 (有状态)：**
    * `src/drcom_core/protocols/version_520d.py`
    * `D_Protocol._challenge()`: 此方法负责完整的 Challenge 流程。它调用 `build_challenge_request()`，使用 `self.net_client` 发送和接收，并调用 `parse_challenge_response()` 来获取 Salt，最后将其存入 `self.state.salt`。

## 2. Login 阶段 (Code 0x03, 0x04/0x05)

**协议流：**
客户端使用上一步的 `Salt` 和用户凭据构建 `0x03` 登录包发送给服务器。服务器返回 `0x04` (成功) 或 `0x05` (失败)。

**代码映射：**

* **包构建/解析 (纯函数)：**
    * `src/drcom_core/protocols/login.py`
    * `build_login_packet()`: 核心函数，负责组装复杂的 `0x03` 包，包括计算 MD5A, MD5B, MD5C (Checksum1) 和 `_calculate_checksum` (Checksum2)。它从 `DrcomConfig` 对象中获取所有必需参数（如 MAC, Host IP, Auth Version 等）。
    * `parse_login_response()`: 负责解析 `0x04`（提取 `[23:39]` 的 `Auth_Info`）或 `0x05`（提取 `[4]` 的 `error_code`）。

* **流程编排 (有状态)：**
    * `src/drcom_core/protocols/version_520d.py`
    * `D_Protocol._login()`: 此方法负责登录流程。它调用 `build_login_packet()`，发送包，并使用 `parse_login_response()` 处理结果。
    * 如果成功，它会将 `Auth_Info` 存入 `self.state.auth_info` 并设置 `self.state.login_success = True`。
    * 如果失败，它会检查 `error_code` 是否在 `constants.NO_RETRY_ERROR_CODES` 中，以决定是否立即中止登录。

## 3. Keep Alive 1 (FF 包)

**协议流：**
作为心跳的第一部分，客户端发送 `0xFF` 包（携带登录时用的 `Salt` 计算的 MD5 和 `Auth_Info`）。服务器回复 `0x07` 包作为确认。

**代码映射：**

* **包构建/解析 (纯函数)：**
    * `src/drcom_core/protocols/keep_alive.py`
    * `build_keep_alive1_packet()`: 构建 `0xFF` 包。
    * `parse_keep_alive1_response()`: 验证响应是否以 `0x07` 开头。

* **流程编排 (有状态)：**
    * `src/drcom_core/protocols/version_520d.py`
    * `D_Protocol.keep_alive()`: 心跳 API 的**第一部分**。它调用 `_send_and_receive_ka` 辅助函数来发送 `0xFF` 包并验证响应。

## 4. Keep Alive 2 (07 包序列)

**协议流：**
紧接着 KA1 成功后，客户端**立即**执行 `0x07` 包序列。此序列的核心是 `tail` 值（服务器响应包的 `[16:20]` 字节）的传递，该逻辑继承自 `drcom-generic`。

* **首次序列 (三步握手)：**
    1.  `[C->S]` Type 1 (使用 `KA2_FIRST_PACKET_VERSION` `0x0f27`), Num=0, Tail=0000
    2.  `[S->C]` 回复 `0x07`
    3.  `[C->S]` Type 1 (使用 `KEEP_ALIVE_VERSION` `0xdc02`), Num=1, Tail=0000
    4.  `[S->C]` 回复 `0x07` (包含 **Tail A**)
    5.  `[C->S]` Type 3 (含 `host_ip_bytes`), Num=2, Tail=**Tail A**
    6.  `[S->C]` 回复 `0x07` (包含 **Tail B**)
* **循环序列 (两步)：**
    1.  `[C->S]` Type 1, Num=i, Tail=**Tail X** (来自上周期)
    2.  `[S->C]` 回复 `0x07` (包含 **Tail Y**)
    3.  `[C->S]` Type 3 (含 `host_ip_bytes`), Num=i+1, Tail=**Tail Y**
    4.  `[S->C]` 回复 `0x07` (包含 **Tail X+1**)

**代码映射：**

* **包构建/解析 (纯函数)：**
    * `src/drcom_core/protocols/keep_alive.py`
    * `build_keep_alive2_packet()`: 构建 `0x07` 包，通过 `is_first_packet` 标志区分使用 `0x0f27` 还是配置的 `keep_alive_version`。
    * `parse_keep_alive2_response()`: 从 `0x07` 响应中提取 `[16:20]` 的 `new_tail`。

* **流程编排 (有状态)：**
    * `src/drcom_core/protocols/version_520d.py`
    * `D_Protocol._manage_keep_alive2_sequence()`: **KA2 的核心逻辑**，在 `D_Protocol.keep_alive()` 的第二部分被调用。
    * 该函数使用 `self.state._ka2_initialized` (布尔值) 来区分是执行“首次序列 (三步握手)”还是“循环序列 (两步)”。
    * 它负责管理 `self.state.keep_alive_serial_num` (包序号) 和 `self.state.keep_alive_tail` (Tail 值) 的状态更新。

## 5. Logout 阶段 (Code 0x06)

**协议流：**
客户端主动下线。基于 `drcom-generic` 的实现，安全的登出需要**先执行一次新的 Challenge** 获取新 Salt，然后使用**新 Salt** 和**登录时获取的 Auth_Info** 来构建 `0x06` 包。服务器通常不响应。

**代码映射：**

* **包构建/解析 (纯函数)：**
    * `src/drcom_core/protocols/logout.py`
    * `build_logout_packet()`: 构建 `0x06` 包。
    * `parse_logout_response()`: 处理服务器的响应。`response_data` 为 `None` (即 `socket.timeout`) 在此被视作登出成功。

* **流程编排 (有状态)：**
    * `src/drcom_core/protocols/version_520d.py`
    * `D_Protocol.logout()`: 登出 API。
    * 它首先调用 `self._challenge()` 获取新 Salt。
    * 然后调用 `build_logout_packet()`。
    * 最后，在 `finally` 块中，它**必须**调用 `self._reset_state()` 来清理 `self.state` 中的所有会话信息（`salt`, `auth_info` 等）。
