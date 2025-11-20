# D 版 (5.2.0) 协议详解

本文档详细解构了 Dr.COM 5.2.0(D) 版协议的交互流程，并映射到 `drcom-core` 的代码实现。

## 1. 协议概览

D 版协议基于 UDP，默认端口 `61440`。它是一个有状态的协议，认证过程强依赖于上一步获取的 `Salt` (盐值) 和 `Token` (尾巴)。

### 代码映射
* **策略实现**: `src/drcom_core/protocols/version_520d.py`
* **包构建器**: `src/drcom_core/protocols/*.py`

---

## 2. 阶段一：Challenge (挑战)

**目的**: 获取用于加密密码的随机盐值 (`Salt`)。

### 交互流程
1.  **Client -> Server (0x01)**: 发送 Challenge 请求。
    * 包含：随机数种子。
2.  **Server -> Client (0x02)**: 返回 Challenge 响应。
    * 包含：**4 字节 Salt** (偏移量 4-7)。

### 代码实现
* **构建**: `protocols.challenge.build_challenge_request()`
* **解析**: `protocols.challenge.parse_challenge_response()`
* **状态**: 这里的 Salt 会被存入 `self.state.salt`。

---

## 3. 阶段二：Login (登录)

**目的**: 提交身份凭据。这是协议中最复杂的包。

### 交互流程
1.  **Client -> Server (0x03)**: 发送登录包 (通常约 300+ 字节)。
    * **核心加密**:
        * `MD5A` = MD5(0x03 + 0x01 + Salt + Password)
        * `MAC_XOR` = Mac Address ^ MD5A[0:6]
        * `MD5B` = MD5(0x01 + Password + Salt + 4x00)
    * **指纹字段**:
        * `ControlCheckStatus` (0x20)
        * `AdapterNum` (网卡序号)
        * `OS Info` (系统指纹，由 `config.os_info_hex` 注入)
2.  **Server -> Client (0x04/0x05)**:
    * **0x04 (成功)**: 返回 **16 字节 AuthInfo/Token** (偏移量 23-38)。此 Token 是后续心跳的凭证。
    * **0x05 (失败)**: 返回错误代码 (如 0x03 密码错误)。

### 代码实现
* **构建**: `protocols.login.build_login_packet()`

---

## 4. 阶段三：Keep Alive 1 (握手心跳)

**目的**: 确认登录成功，并建立心跳通道。

### 交互流程
1.  **Client -> Server (0xFF)**: 发送 `0xFF` 包。
    * 包含：`MD5(0x03 + 0x01 + Salt + Password)` + `AuthInfo` (来自登录响应)。
2.  **Server -> Client (0x07)**: 回复 `0x07` 包。

---

## 5. 阶段四：Keep Alive 2 (循环保活)

**目的**: 维持在线状态，并检测服务器是否存活。D 版心跳通过 `Tail` (尾巴) 机制来防止重放。

### 交互流程 (每 20 秒)

这是一个 "Ping-Pong" 式的 Tail 交换过程：

1.  **Client -> Server (Type 1)**:
    * 发送上一次收到的 `Tail`。
    * 如果是第一次，发送全 0。
2.  **Server -> Client**:
    * 返回一个新的 `Tail A`。
3.  **Client -> Server (Type 3)**:
    * 发送 `Tail A`。
    * 此包额外包含客户端 IP。
4.  **Server -> Client**:
    * 返回一个新的 `Tail B` (用于下个周期)。

### 代码实现
* **逻辑**: `D_Protocol._manage_keep_alive2_sequence()`
* **状态机**: 代码内部维护了 `_ka2_initialized` 标志，以区分是“初次握手”还是“稳定循环”。

---

## 6. 阶段五：Logout (注销)

**目的**: 主动下线。

### 交互流程
1.  **Client**: 再次发起 **Challenge** 流程，获取一个新的 `New_Salt`。
2.  **Client -> Server (0x06)**: 发送注销包。
    * 加密：使用 `New_Salt` 和登录时获取的 `AuthInfo` 进行计算。

### 注意
很多 Dr.COM 实现会忽略注销前的 Challenge，直接使用旧 Salt，这会导致注销失败（服务器提示 "Password Error"）。Drcom-Core 严格遵循标准流程，确保注销成功率。
