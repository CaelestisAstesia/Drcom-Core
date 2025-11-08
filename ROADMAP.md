# 项目路线图

本项目 `drcom-core` 致力于为 Dr.Com 认证提供一个现代、稳定且可重用的 Python 核心库。

这是一个动态文档，会随着项目的发展而更新。欢迎所有贡献者围绕这些目标提交 Issue 和 Pull Request。

## 核心目标

* **API 优先**：提供一个稳定、文档齐全的 `DrcomCore` API，供命令行工具、GUI 和其他第三方应用调用。
* **现代范式**：使用 Python 3.13+、类型提示、规范的日志记录和健壮的错误处理。
* **社区驱动**：在 `drcom-generic` 的基础上，构建一个易于维护和贡献的新平台。

---

## 近期目标 (Short-Term)

这些是我们当前正在进行或即将开始的工作。

* [x] **D 版协议 API 化**：完成 `DrcomCore` 类的封装，提供 `login`, `start_heartbeat`, `logout` 接口。
* [x] **文档完善**：为核心 API 编写 Docstrings，并更新 `README.md` 和 `CONTRIBUTING.MD`。
* [ ] **建立单元测试**：为 `drcom_protocol` 中的各个包构建函数编写单元测试（使用 `pytest`）。
* [ ] **Mock 测试**：为 `DrcomCore` 编写集成测试，使用 `pytest-mock` 模拟 `socket` 收发，测试登录失败、心跳超时等逻辑。
* [ ] **协议拟真度提升**：研究并实现抓包中发现的动态字段（如动态 `HostIpNum` 和随机 `LOGIN_PACKET_ENDING`）。

## 中期目标 (Mid-Term)

* [ ] **CLI 客户端**：写一个配置方便灵活的控制台程序，并且实现开机启动、后台运行等功能。
* [ ] **P 版协议支持**：分析 P 版（PPPoE）逻辑，并将其封装为 `drcom_protocol` 下的一个新模块。~~真的有地方还在拨号上网吗~~
* [x] **打包与发布**：将项目配置 `pyproject.toml` 打包。
* [ ] **配置收集**：建立一个机制来收集和展示来自不同学校的 `.env` 配置模板。

## 长期目标 (Long-Term / "项目集")

* [ ] **GUI 客户端**：利用 `drcom-core` API，开发一个独立的、跨平台的图形界面客户端（例如使用 PyQt ）。
* [ ] **Web 管理面板**：开发一个轻量级的 Web 服务（例如使用 FastAPI 或 Flask），用于在路由器或树莓派上远程管理 `drcom-core`。
