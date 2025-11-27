# README.md

# Drcom-Core: 现代化 Dr.Com 认证协议核心库

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Python 3.13+](https://img.shields.io/badge/python-3.13+-blue.svg)](https://www.python.org/downloads/)
[![Code Style: Black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Release: 1.0.0](https://img.shields.io/badge/release-v1.0.0-green.svg)](https://github.com/CaelestisAstesia/Drcom-Core/releases)

## 简介
`drcom-core` 是一个现代化的 Dr.COM 认证协议核心库。使用 **Python 3.13+** 构建，基于对 `drcom-generic` 项目和网络数据包的分析，采用了**引擎 (Engine) + 策略 (Strategy)** 的架构设计。旨在为开发者提供一个类型安全、易于扩展、高度解耦的认证底层，轻松集成到 CLI 工具、GUI 客户端或系统服务中。

## 特性

* **现代 Python**：利用 Python 3.13+ 最新特性构建，提供全覆盖的类型提示 (Type Hinting)。
* **架构解耦**：核心引擎 (`DrcomCore`) 与协议策略 (`D_Protocol`) 完全分离，易于扩展 P 版、X 版等新协议。
* **零依赖**：运行时仅依赖标准库（`tomllib` 等），轻量且安全。
* **状态管理**：逻辑清晰的 `DrcomState` 会话生命周期管理。
* **配置分离**：基于 TOML 的强类型配置，代码零侵入。

## 文档索引

* **入门**
    * [快速上手](docs/quickstart.md) - 运行演示脚本，立即上线。
    * [配置文件参考](docs/config_reference.md) - config.toml 所有参数详解。
    * [安装指南](docs/install.md) - 从 whl 或源码安装。
* **开发与原理**
    * [架构设计与贡献指南](docs/architecture.md) - 理解引擎+策略模式。
    * [D 版协议详解](docs/protocol_d.md) - 深入了解 Challenge, Salt, KeepAlive 机制。
    * [API 参考手册](docs/api_reference.md) - 核心类与方法说明。
* **其他**
    * [更新日志](docs/changelog.md)

## 贡献
我们非常欢迎任何形式的贡献，特别是来自不同网络环境的配置和测试反馈。请在提交 PR 或 Issue 之前，阅读我们的《贡献指南》。

## 免责声明

本项目是一个独立的第三方实现，与 **广州热点软件科技股份有限公司** 没有任何关联，也未获得其官方认可或支持。

"Dr.Com" 是广州热点软件科技股份有限公司的注册商标。本项目中提及该名称仅为指示性目的，用于说明本项目所实现的协议兼容性。

本项目按“原样”提供，不提供任何形式的明示或暗示担保。开发者不对使用本软件可能导致的任何直接或间接后果负责，包括但不限于账户异常、网络中断、或与 Dr.Com 最终用户许可协议 (EULA) 的潜在冲突。

**请您自行承担所有使用风险。您有责任在遵守当地法律法规和您所在机构的“网络管理规定”的前提下使用本软件。严禁将本软件用于任何非法或违规目的。**

## 许可证

本项目采用 **GNU Affero General Public License v3.0 (AGPLv3)** 许可证开源。

简而言之：您可以自由地运行、研究、共享和修改本软件。但任何基于本项目的衍生作品（包括通过网络提供服务）都必须同样采用 AGPLv3 许可证开源。

详细文本请参见 LICENSE 文件。

## 致谢
本项目是在 `drcom-generic` (https://github.com/drcoms/drcom-generic) 项目的基础上进行的现代化重构。向`drcom-generic` 社区的前辈们致敬。

本项目的大部分代码和文档是在 AI 辅助工具 (Google Gemini Pro) 的帮助下完成的，特此告知。
