# Changelog

All notable changes to this project will be documented in this file.

## [1.1.0] - 2025-12-05

- 增强 `DEBUG` 级日志：`network` 收发、D 系列 `packets` 构包/解析、`strategy` 登录与 KA2 状态机。
- 测试套件扩展并镜像 `src` 结构：`tests/drcom_core/protocols/d_series/strategy.py` 与 `tests/drcom_core/protocols/d_series/packets.py` 等。
- 统一测试收集配置：`pyproject.toml` 中启用 `python_files = ["*.py"]`。
- 补齐项目代码注释与文件头路径标识，提升可读性与可维护性。
- 验证通过：`pytest -q` 共 17 个测试全部通过。

### 发布说明

- 本版本不发布到 PyPI；改用内部/私有分发渠道（GitHub Release 附件或内部制品库）。
- 原因：优先满足内部分发与环境验证需求；后续版本将根据兼容性反馈评估公开发布。

### 兼容性

- 保持零运行时依赖；对 Python 3.13 进行验证。

### 已知问题

- 暂无高优先级缺陷报告。

[1.1.0]: https://github.com/CaelestisAstesia/Drcom-Core/releases/tag/v1.1.0
