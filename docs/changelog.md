# 更新日志

本项目遵循 [Semantic Versioning](https://semver.org/lang/zh-CN/) 语义化版本规范。

## [1.0.0a3] - 2025-11-20

**Alpha 3 Release: 现代化重构里程碑**

在此版本中，我们完成了对 `drcom-generic` 的全面现代化重构，不仅提升了代码质量，还引入了完整的类型系统和文档体系。

### 新增功能 (Added)
* **配置管理**: 全面转向 TOML 配置 (`config.toml`)，支持强类型校验，废弃了旧的 Python 脚本配置方式。
* **类型安全**: 全项目实现 100% Python Type Hinting 覆盖，支持静态类型检查。
* **开发者工具**: 新增 `run.py` 作为标准启动入口，支持优雅的信号处理（Ctrl+C）。
* **文档站点**: 集成 MkDocs + Material Theme，提供自动生成的 API 文档。

### 架构变更 (Changed)
* **引擎/策略分离**: 将核心逻辑与 D 版协议实现解耦，为未来支持 P/X 版协议奠定基础。
* **状态管理**: 引入 `DrcomState` 单一数据源，清晰管理 `Salt`, `Token` 和心跳序列号。
* **网络层封装**: 所有的 Socket 操作被隔离在 `NetworkClient` 中，不再散落在逻辑代码里。

### 修复 (Fixed)
* 修复了心跳线程在主进程退出后无法正确清理的问题。
* 修复了 `os_info` 在不同操作系统下可能被错误截断的问题。

## [1.0.0-alpha.2] - 2025-11-20

### 发布说明 (Release Notes)

此版本标志着核心库重构工作的完成。API 接口 (`login`, `keep_alive`, `logout`) 已趋于稳定，准备好作为依赖库供下游应用 (`drcom-cli`) 调用。

### 改进 (Improved)
* **API 稳定性**：固化了 `DrcomCore` 的公共方法签名，不再计划进行破坏性变更。
* **类型提示**：全面完善了 `src/drcom_core` 下的 Type Hints，提升了 IDE 的开发体验。
* **文档**：更新了 README，明确了作为库使用的示例。


## [1.0.0-alpha.1] - 2025-11-08

### 重大变更 (Breaking Changes) / 架构升级

本次更新对 `drcom-core` 进行了彻底的架构重构，为未来支持多协议版本（如 P 版、X 版）, 开发独立的命令行管理工具等打下了坚实的基础。

* **引入“引擎 + 策略”模式：**
    * 项目核心不再是单个巨型类，而是重构为一个轻量级的**“引擎”** (`core.py`) 和可插拔的**“协议策略”** (`protocols/`)。

* **彻底的职责分离 (Separation of Concerns)：**
    * **协议层 (`protocols/`)：** 现已成为纯粹的协议实现。**彻底剥离**了所有网络 I/O (socket)、状态管理和配置依赖。只负责协议包的构建、解析和认证逻辑。
    * **核心服务层：** 将原先耦合在 `core` 中的职责，抽离为独立的服务模块：
        * `network.py`: 专职负责 UDP Socket 的收发和网络绑定。
        * `state.py`: 专职负责以 `DrcomState` (Dataclass) 存储所有易变会话状态。
        * `config.py`: 专职负责加载和校验配置。
    * **引擎层 (`core.py`)：** 重构为一个精简的“编排器”，负责管理 `atexit` 钩子、心跳线程的生命周期，并*调用*协议策略，不再关心协议的*具体实现*。

### 新增 (Added)

* **标准打包 (`pyproject.toml`)：**
    * 项目已迁移到 `src-layout` 布局。
    * 添加了 `pyproject.toml`，使 `drcom-core` 成为一个符合 PEP 621 标准的、可安装的 Python 库。
* **协议基类 (`protocols/base.py`)：**
    * 定义了 `BaseProtocol` 和 `D_Protocol` 抽象接口，为所有协议策略提供了统一的契约。

### 修复 (Fixed)

* **中断BUG：** 修复了 Ctrl + C 登出时无法响应的问题。

## [0.1.0-alpha.1] - 2025-10-28

### 新增 (Added)
- 初步实现 Dr.Com D 版认证协议 (Challenge, Login, KeepAlive FF/07, Logout)
- 实现基于 `.env` 文件的配置加载
- 添加命令行入口 (`main.py`)
- 添加基础的测试框架

### 修复 (Fixed)
- 第一个版本，没有修复任何问题

### 更改 (Changed)
- 第一个版本，没有任何改动
