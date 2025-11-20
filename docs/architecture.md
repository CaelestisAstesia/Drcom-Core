# 架构与贡献指南

drcom-core 的设计遵循高内聚、低耦合的原则，采用了引擎 (Engine) + 策略 (Strategy) 模式。

## 架构概览

### 1. 引擎层 (Engine)
* 位置: src/drcom_core/core.py
* 职责: 这是"大脑"。它不关心数据包怎么拼，只负责：
    * 生命周期管理（Login -> Heartbeat -> Logout）。
    * 线程管理（启动和回收心跳线程）。
    * 状态流转（通知 UI 状态变更）。

### 2. 策略层 (Strategy)
* 位置: src/drcom_core/protocols/
* 职责: 这是"执行者"。例如 D_Protocol (version_520d.py) 实现了具体的 D 版协议：
    * 构建 Challenge 包。
    * 计算 MD5 校验和。
    * 处理心跳的 Sequence Number 逻辑。

### 3. 基础设施 (Infrastructure)
* Network: network.py 封装了 UDP Socket，处理超时和重试。
* State: state.py 纯数据类，存储 Salt, Token 等易变状态。
* Config: config.py 负责 TOML 加载和强类型校验。

## 数据流向 (Login)

```mermaid
sequenceDiagram
    participant User as 用户/run.py
    participant Core as DrcomCore (引擎)
    participant Proto as D_Protocol (策略)
    participant Net as NetworkClient

    User->>Core: login()
    Core->>Proto: login()

    Note right of Proto: 1. Challenge 阶段
    Proto->>Net: send(Challenge_Packet)
    Net-->>Proto: receive(Salt)

    Note right of Proto: 2. Login 阶段
    Proto->>Proto: calculate_md5(Salt, Password...)
    Proto->>Net: send(Login_Packet)
    Net-->>Proto: receive(Auth_Info)

    Proto-->>Core: True (Success)
    Core-->>User: True
