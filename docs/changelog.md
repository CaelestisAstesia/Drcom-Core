---
layout: default
title: 更新日志
nav_order: 9
---

# 更新日志

本项目遵循 [Semantic Versioning](https://semver.org/lang/zh-CN/) 语义化版本规范。

## [1.0.0] - 2025-11-27

**Official Release: 第一个正式版本**

Drcom-Core 经过了 Beta 阶段的测试与验证，现发布第一个正式版本。
此版本API已冻结，适合用于生产环境。

### 变更 (Changed)
* **元数据**: 修正了 PyPI 分类器状态为 `Production/Stable`。
* **文档**: 清理了代码库中的注释拼写错误和格式问题。
* **版本**: 移除 Beta 后缀，正式定版为 1.0.0。

---

## [1.0.0b1] - 2025-11-22

**Beta 1 Release: 生产环境就绪 (Production Ready)**

此版本标志着 Drcom-Core 完成了所有核心重构任务，代码库已达到工业级健壮性标准，准备好进行广泛测试。

### 新增 (Added)
* **类型安全异常体系**: 引入 `AuthErrorCode(IntEnum)` 枚举，彻底消除魔法数字，支持 IDE 自动补全。
* **混合式错误反馈**: 实现了“强类型内核 + 本地化反馈”机制，既保证了代码逻辑严密，又保留了适合国内环境的中文报错（如“余额不足”、“密码错误”）。
* **工业级鲁棒性**:
    * **UDP 重传**: 协议层新增 `_send_and_recv_with_retry`，在网络抖动时自动重发关键包，不再硬等超时。
    * **守护进程**: 参考实现 `run.py` 新增无限重连循环与信号处理，支持 7x24 小时无人值守运行。
* **文档补全**: 核心模块（`core.py`, `login.py` 等）全面覆盖 Google Style Docstrings，明确了 API 契约。
* **深度测试**: 新增 KA2 状态机流转测试 (`test_state_machine.py`) 和错误码映射测试 (`test_error_mapping.py`)。

### 变更 (Changed)
* **构建系统**: 更新 `pyproject.toml` 以符合最新的 Python 打包标准 (SPDX License)，消除了构建时的废弃警告。
* **常量清理**: 移除了 `constants.py` 中冗余的错误码常量，统一由 `exceptions.py` 管理事实来源 (SSOT)。
* **状态管理**: 优化了 `DrcomState` 的生命周期管理，确保在重连时彻底清除脏数据。

### 修复 (Fixed)
* 修复了在高丢包率环境下心跳线程容易假死的问题。
* 修复了构建过程中关于 License 定义的 DeprecationWarning。

---

## [1.0.0a3] - 2025-11-20

**Alpha 3 Release: 现代化重构里程碑**

在此版本中，我们完成了对 `drcom-generic` JLU 5.2.0 D 版的现代化重构，引入了完整的类型系统和文档体系。

### 新增 (Added)
* **配置管理**: 全面转向 TOML 配置 (`config.toml`)，支持强类型校验，废弃了旧的 Python 脚本配置方式。
* **类型安全**: 全项目实现 100% Python Type Hinting 覆盖。
* **开发者工具**: 新增 `run.py` 作为标准启动入口。

### 变更 (Changed)
* **架构解耦**: 将核心逻辑与 D 版协议实现解耦，采用 **引擎 (Engine) + 策略 (Strategy)** 模式。
* **状态管理**: 引入 `DrcomState` 单一数据源。
* **网络层封装**: 所有的 Socket 操作被隔离在 `NetworkClient` 中。

### 修复 (Fixed)
* 修复了心跳线程在主进程退出后无法正确清理的问题。
* 修复了 `os_info` 在不同操作系统下可能被错误截断的问题。

---

## [1.0.0a2] - 2025-11-20

**Alpha 2 Release: API 稳定化**

此版本固化了 `DrcomCore` 的公共方法签名，准备好作为依赖库供下游应用调用。

### 改进 (Improved)
* **API 稳定性**：固化了 `login`, `keep_alive`, `logout` 接口。
* **类型提示**：完善了 `src/drcom_core` 下的 Type Hints。

---

## [1.0.0a1] - 2025-11-08

**Alpha 1 Release: 架构原型**

本次更新进行了彻底的架构重构，引入了“引擎 + 策略”模式。

### 重大变更 (Breaking Changes)
* **核心重构**：项目核心不再是单个巨型类，而是重构为轻量级的“引擎”和可插拔的“策略”。
* **职责分离**：彻底剥离了网络 I/O、状态管理和配置依赖。

### 新增 (Added)
* **标准打包**：添加 `pyproject.toml`，支持 `pip install .`。
* **协议基类**：定义了 `BaseProtocol` 抽象接口。

### 修复 (Fixed)
* 修复了 Ctrl + C 登出时无法响应的问题。

---

## [0.1.0a1] - 2025-10-28

**Pre-Alpha: 概念验证**

### 新增 (Added)
* 初步实现 Dr.Com D 版认证协议 (Challenge, Login, KeepAlive FF/07, Logout)。
* 实现基于 `.env` 文件的配置加载。
* 添加命令行入口 (`main.py`) 和基础测试框架。
