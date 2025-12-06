# Drcom-Core 架构文档

## 项目概述

**Drcom-Core** 是一个基于 Python 3.13+ 构建的现代化 Dr.COM 认证协议核心库。它采用 **引擎 (Engine) + 策略 (Strategy)** 的解耦架构，提供类型安全、零运行时依赖、易于扩展的底层认证框架。

## 核心设计理念

1. **零第三方依赖**：仅使用 Python 标准库，适合嵌入式环境
2. **全异步 I/O**：基于 `asyncio` 和 `Queue` 构建，高效处理并发与心跳维持
3. **类型安全**：100% Type Hints 覆盖，配合 Pydantic 风格的配置校验
4. **策略模式**：协议实现与核心引擎解耦，易于扩展新协议版本

## 架构层次

### 1. 核心引擎层 (Core Engine)

**文件**: `src/drcom_core/core.py`

**核心类**: `DrcomCore`

**职责**:
- 资源组装：State + Network + Config
- 策略分发：根据配置加载对应的协议策略
- 生命周期管理：Login -> Heartbeat -> Stop
- 状态回调：支持多个监听器监听状态变更

**主要方法**:
- `login()`: 执行登录流程
- `start_heartbeat()`: 启动内置后台心跳任务
- `step()`: 执行单次心跳步进（供外部 Event Loop 精细控制）
- `probe_server()`: 探测服务器连通性
- `stop()`: 优雅停止引擎

### 2. 配置层 (Configuration)

**文件**: `src/drcom_core/config.py`

**核心类**: `DrcomConfig`

**特性**:
- 不可变配置对象 (`frozen=True`)
- 支持从 TOML 文件、环境变量或字典加载
- 自动类型转换和验证
- 支持多 Profile 配置

**配置加载方式**:
- `load_config_from_toml()`: 从 TOML 文件加载
- `load_config_from_env()`: 从环境变量加载（Docker/Cloud Friendly）
- `create_config_from_dict()`: 从字典创建

### 3. 状态管理层 (State Management)

**文件**: `src/drcom_core/state.py`

**核心类**: `DrcomState`, `CoreStatus`

**状态枚举**:
- `IDLE`: 初始状态
- `CONNECTING`: 正在连接中
- `LOGGED_IN`: 登录成功
- `HEARTBEAT`: 在线保活中
- `OFFLINE`: 已离线
- `ERROR`: 错误状态

**状态流转**:
```
IDLE -> CONNECTING -> LOGGED_IN -> HEARTBEAT -> OFFLINE
         |              |            |
         v              v            v
       ERROR          ERROR        ERROR
```

### 4. 网络层 (Network Layer)

**文件**: `src/drcom_core/network.py`

**核心类**: `NetworkClient`

**职责**:
- 封装 UDP Socket 与异步队列
- 提供 `send()` 和 `receive()` 方法
- 处理网络超时和重试

### 5. 协议策略层 (Protocol Strategy)

**目录**: `src/drcom_core/protocols/`

**接口**: `BaseProtocol` (在 `base.py` 中定义)

**实现**: `Protocol520D` (在 `d_series/` 目录中)

**职责**:
- 实现具体的协议逻辑
- 构建和解析数据包
- 处理登录、心跳、注销流程

**协议实现结构**:
```
protocols/
├── base.py              # 协议接口定义
└── d_series/
    ├── __init__.py
    ├── constants.py     # 协议常量
    ├── packets.py       # 数据包构建器
    └── strategy.py      # D 版协议实现
```

### 6. 异常体系 (Exception System)

**文件**: `src/drcom_core/exceptions.py`

**异常类型**:
- `DrcomError`: 基础异常类
- `ConfigError`: 配置错误
- `NetworkError`: 网络通信异常
- `AuthError`: 认证被拒绝（密码错误、欠费）
- `ProtocolError`: 协议解析错误

## 数据流

### 登录流程

```
用户调用 core.login()
    ↓
NetworkClient.connect() 建立 UDP 连接
    ↓
Protocol.login() 执行登录协议
    ↓
发送 Challenge 包 (0x01)
    ↓
接收 Challenge Response (0x02)，提取 Salt
    ↓
构建 Login 包 (0x03)，使用 Salt 加密密码
    ↓
发送 Login 包
    ↓
接收 Login Response (0x04)，提取 Auth Info
    ↓
更新 DrcomState 状态为 LOGGED_IN
    ↓
返回成功
```

### 心跳流程

```
用户调用 core.start_heartbeat()
    ↓
创建后台心跳任务
    ↓
循环执行（每 20 秒）:
    ↓
Protocol.keep_alive() 发送心跳包
    ↓
接收服务器响应
    ↓
更新序列号和状态
    ↓
继续循环直到 stop() 被调用
```

## 扩展性设计

### 添加新协议版本

1. 在 `protocols/` 下创建新目录（如 `p_series/`）
2. 实现 `BaseProtocol` 接口
3. 在 `DrcomCore._load_strategy()` 中添加版本判断逻辑

### 添加新配置源

1. 在 `config.py` 中添加新的加载函数
2. 使用 `create_config_from_dict()` 统一转换

## 依赖关系图

```
DrcomCore
    ├── DrcomConfig (配置)
    ├── DrcomState (状态)
    ├── NetworkClient (网络)
    └── BaseProtocol (协议)
            └── Protocol520D (D版实现)
                    ├── PacketBuilder (封包构建)
                    └── Constants (协议常量)
```

## 线程安全

- `DrcomCore` 的方法都是异步的，应在同一个事件循环中调用
- `DrcomState` 是数据类，由 `DrcomCore` 内部管理，外部通过 `state` 属性获取只读副本
- `NetworkClient` 使用异步队列，线程安全

## 错误处理策略

1. **AuthError**: 认证错误，不应重试，应提示用户检查账号
2. **NetworkError**: 网络错误，建议执行指数退避重试
3. **ConfigError**: 配置错误，应提示用户修复配置
4. **ProtocolError**: 协议错误，可能是服务器升级，需要更新协议实现

## 性能优化

1. **异步 I/O**: 所有网络操作使用 `asyncio`，不阻塞事件循环
2. **状态缓存**: `DrcomState` 在内存中维护，避免频繁序列化
3. **连接复用**: `NetworkClient` 保持 UDP Socket 连接，避免重复创建

## 测试策略

测试文件位于 `tests/` 目录，使用 `pytest` 框架。

测试覆盖：
- 配置加载和验证
- 协议包构建和解析
- 状态管理
- 异常处理

## 版本历史

- **v1.1.0** (LTS): 异步重构，引擎-策略解耦架构
- **v1.0.0**: 初始版本

## 维护状态

当前版本 (v1.1.0) 已进入 **LTS (Long-Term Support)** 阶段：
- API 冻结，不再进行破坏性变更
- 仅进行 Bug 修复和安全性更新
- 欢迎社区贡献新协议适配

