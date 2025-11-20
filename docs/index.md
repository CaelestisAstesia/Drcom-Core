---
layout: default
title: 首页
nav_order: 1
---

# 欢迎使用 Drcom-Core

**Drcom-Core** 是为了解决 Dr.COM 认证协议在现代 Python 环境下缺乏高质量实现而诞生的项目。

它是一个经过严格设计、类型安全、架构解耦的 **Python 核心库**。

## 为什么选择 Drcom-Core？

### 1. 开发者优先
如果你想为你的学校开发一个 CLI 工具、GUI 客户端，或者只是想写个脚本跑在路由器上，**Drcom-Core** 是最佳的底层依赖。
你不需要去处理 Socket 粘包、MD5 校验或者是心跳逻辑，只需要调用 `login()`。

### 2. 现代 Python 体验
我们摒弃了旧时代的代码风格。在 Drcom-Core 中，你将看到：

* **全覆盖的类型提示 (Type Hinting)**：配合 VS Code / PyCharm，开发体验极其顺滑。
* **不可变配置**：基于 `dataclass(frozen=True)` 的配置对象，杜绝运行时意外修改。
* **纯粹的 Python**：除了标准库（和开发时的 `pytest`），运行时零依赖。

### 3. 协议研究价值
我们的代码与文档紧密对应。如果你对 Dr.COM 协议的底层实现感兴趣（比如它是如何传递 Challenge Salt 的，心跳包里的 Tail 是什么），这里就是最好的教科书。

## 下一步

* **准备好了吗？** 请前往 [安装指南](install.md)。
* **想直接看代码？** 请查看 [快速上手](quickstart.md)。
* **需要配置参数？** 请查阅 [配置文件参考](config_reference.md)。
