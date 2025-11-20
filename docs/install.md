---
layout: default
title: 安装指南
nav_order: 3
---

# 安装指南

## 环境要求

在安装 Drcom-Core 之前，请确保您的环境满足以下要求：

* **Python 3.13** 或更高版本。
    * 这是一个硬性要求，因为我们使用了 Python 3.13 的最新特性。
    * 您可以通过 `python --version` 命令检查当前版本。
* **操作系统**：
    * 支持 **Python 3.13** 及以上版本的任何操作系统。

---

## 方式一：从下载的whl包安装 (推荐)

如果您只是想在您的项目（如 CLI 工具、GUI 客户端）中**使用** Drcom-Core，这是最简单的方式。

务必更改`version`为具体版本。

```bash
pip install drcom_core-version-py3-none-any.whl
```

## 方式二：源码安装 (开发模式)
如果您希望修改 Drcom-Core 的源码，或者参与项目贡献，请使用此方式。

我们推荐使用 -e (editable) 模式安装。在此模式下，您对 `src/` 目录下代码的任何修改都会立即生效，无需重新安装。

1. 获取源码
    ```Bash
    git clone [https://github.com/CaelestisAstesia/Drcom-Core.git](https://github.com/CaelestisAstesia/Drcom-Core.git)
    cd Drcom-Core
    ```
2. 安装依赖
    ```Bash
    # 注意最后的 "." 不能省略，它代表当前目录
    pip install -e .
    ```
3. 验证安装
    ```Bash
    python -c "import drcom_core; print(f'Drcom-Core v{drcom_core.__version__} 安装成功')"
    ```

## 常见问题 (FAQ)
Q: 安装时提示 `tomllib` 找不到？

A: 请检查您的 Python 版本。tomllib 是 Python 3.11+ 的标准库。本项目要求 Python 3.13+，只要版本正确，不需要额外安装任何包。

Q: 为什么没有 `requirements.txt`？

A: 本项目遵循现代 Python 打包标准 (PEP 621)，所有的依赖关系都定义在 pyproject.toml 中。当您运行 `pip install .` 时，pip 会自动处理依赖。
