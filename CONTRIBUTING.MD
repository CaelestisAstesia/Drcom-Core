# 贡献指南

感谢你抽出宝贵时间为 Drcom-Core 做出贡献！你的帮助对这个项目至关重要。

由于 Dr.Com 协议版本繁多，仅靠维护者寥寥几人无法覆盖所有学校和所有版本。我们非常欢迎来自不同环境的测试反馈、配置提交和代码贡献。

## 如何贡献

我们欢迎任何形式的贡献，包括但不限于：

* 报告 Bug
* 提交适配新学校的配置
* 完善代码和功能 (PR)
* 改进文档

## 报告 Bug (Issue)

在提交 Issue 之前，请务必：

1.  搜索现有的 Issue，确保你的问题没有被重复提交。
2.  确保你使用的是最新版本的 `main` 分支代码。

提交 Issue 时，请**务必**提供以下信息：

1.  **学校名称和校区**：
2.  **Dr.Com 客户端版本**：（例如 5.2.0 D 版）
3.  **操作系统**：（例如 Windows 11 / Ubuntu 24.04 / macOS Sonoma）
4.  **Python 版本**： (本项目要求 Python 3.13+)
5.  **完整的日志输出**：在启用调试模式（设置 `DEBUG=True`）后，复现问题并粘贴完整的终端输出。

## 提交适配新学校的配置

注意！这部分内容在未来可能会有所变动，Drcom-Core将成为专门的API库。

本项目通过 `.env` 文件 来管理不同学校的配置，而不是像旧项目那样使用独立的 Python 脚本。

如果你在你的学校成功运行了 `Drcom-Core`，我们非常欢迎你分享你的配置！

1.  复制你的 `.env` 文件（隐去你的 `USERNAME` 和 `PASSWORD`）。
2.  创建一个新的 Issue，标题为 `[配置分享] XX大学XX校区 (D版/P版)`。
3.  在 Issue 内容中贴出你的 `.env` 配置内容。

我们会收集这些配置，未来可能会建立一个配置档案库。

## 提交代码 (Pull Request)

我们欢迎任何能提升代码质量、增加新功能或修复 Bug 的 PR。

**开发环境设置**：

1.  Fork 本仓库到你自己的 GitHub 账户。
2.  Clone 你的 Fork 到本地：`git clone https://github.com/YOUR_USERNAME/Drcom-Core.git`
3.  创建并切换到一个新的特性分支：`git checkout -b feature/my-new-feature`
4.  安装依赖，`pip install -r requirements.txt`

**编码规范**：

本项目使用现代 Python 3.13+ 范式：

1.  **代码风格**：请遵循 [PEP 8](https://www.python.org/dev/peps/pep-0008/) 规范。
2.  **类型提示 (Type Hinting)**：请为所有函数定义和变量添加类型提示（可参考 `src/drcom_protocol/login.py`）。
3.  **模块化**：核心认证逻辑应保持在 `src/drcom_core/core.py` 中，而协议包的构建和解析应放在 `src/drcom_protocol/` 目录下。

**提交 PR**：

1.  提交你的修改：`git commit -m "feat: 增加XX功能"`
2.  推送的你的分支：`git push origin feature/my-new-feature`
3.  在 GitHub 上打开一个 Pull Request，清晰描述你所做的工作。
