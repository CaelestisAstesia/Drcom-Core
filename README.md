# Drcom-Core

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Python 3.13+](https://img.shields.io/badge/python-3.13+-blue.svg)](https://www.python.org/downloads/)
[![Code Style: Black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Release: 1.0.0](https://img.shields.io/badge/release-v1.0.0-green.svg)](https://github.com/CaelestisAstesia/Drcom-Core/releases)

**Drcom-Core** 是一个基于 Python 3.13+ 构建的现代化 Dr.COM 认证协议核心库。

它采用了 **引擎 (Engine) + 策略 (Strategy)** 的解耦架构，旨在提供一个类型安全、零运行时依赖（仅标准库）、易于扩展的底层认证框架。你可以轻松将其集成到 CLI 工具、GUI 客户端、系统服务或路由器脚本中。

> 📚 **详细文档、配置参数及开发指南，请查阅项目的 [GitHub Wiki](../../wiki)。**

## ✨ 核心特性

* 🐍 **现代 Python**：完全利用 Python 3.13+ 特性，100% 类型提示。
* 🧩 **架构解耦**：核心逻辑与协议版本（D版/P版/X版）分离，易于维护和扩展。
* ⚡ **零外部依赖**：运行时仅依赖 Python 标准库，轻量且安全。
* 🛡️ **健壮稳定**：内置完整的状态机管理及断线重连逻辑。
* ⚙️ **灵活配置**：支持 TOML 配置文件或环境变量。

## 📦 安装

由于本项目零依赖，你可以直接将源码放入项目，或使用 pip 安装（建议使用可编辑模式开发）：

```bash
git clone [https://github.com/CaelestisAstesia/Drcom-Core.git](https://github.com/CaelestisAstesia/Drcom-Core.git)
cd Drcom-Core
pip install -e .
````

*系统要求：Python 3.13 或更高版本。*

## 🚀 快速上手

以下代码展示了如何加载配置、登录并启动后台心跳保活：

```python
import time
import logging
from pathlib import Path
from drcom_core import DrcomCore, load_config_from_toml, CoreStatus

# 1. 配置日志
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# 2. 定义状态回调
def on_status_change(status: CoreStatus, msg: str):
    print(f"==> [状态变更] {status.name}: {msg}")

def main():
    # 3. 加载配置
    # 假设当前目录下有 config.toml
    try:
        config = load_config_from_toml(Path("config.toml"), profile="default")

        # 4. 初始化引擎
        core = DrcomCore(config, status_callback=on_status_change)

        # 5. 执行登录
        if core.login():
            # 6. 登录成功，启动心跳守护线程
            core.start_heartbeat()

            # 模拟主程序运行
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                print("正在退出...")
                core.stop()
        else:
            print("登录失败，请检查配置或网络。")

    except Exception as e:
        print(f"发生错误: {e}")

if __name__ == "__main__":
    main()
```

## ⚖️ 免责声明与许可证

本项目是一个独立的第三方实现，与**广州热点软件科技股份有限公司或任何机构**没有任何关联，也未获得其官方认可或支持。

"Dr.Com" 是广州热点软件科技股份有限公司的注册商标。本项目中提及该名称仅为指示性目的，用于说明本项目所实现的协议兼容性。

本项目按“原样”提供，不提供任何形式的明示或暗示担保。开发者不对使用本软件可能导致的任何直接或间接后果负责，包括但不限于账户异常、网络中断、或与 Dr.Com 最终用户许可协议 (EULA) 的潜在冲突。

请您自行承担所有使用风险。您有责任在遵守当地法律法规和您所在机构的“网络管理规定”的前提下使用本软件。严禁将本软件用于任何非法或违规目的。

本项目采用 **GNU Affero General Public License v3.0 (AGPLv3)** 许可证开源。

简而言之：您可以自由地运行、研究、共享和修改本软件。但任何基于本项目的衍生作品（包括通过网络提供服务）都必须同样采用 AGPLv3 许可证开源。

详细文本请参见 [*LICENSE*](LICENSE) 文件。

## 致谢

本项目是在 [drcom-generic](https://github.com/drcoms/drcom-generic) 项目的基础上进行的现代化重构。向drcom-generic 社区的前辈们致敬。

本项目的大部分代码和文档是在 AI 辅助工具 (Google Gemini Pro) 的帮助下完成的，特此告知。
