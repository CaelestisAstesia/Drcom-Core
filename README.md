# Drcom-Core: 现代化 Dr.Com 认证协议核心库

[](https://www.gnu.org/licenses/agpl-3.0)

`drcom-core` 是一个基于 Python 3.13+ 开发的第三方 Dr.Com 认证核心库与命令行工具。

本项目基于对 `drcom-generic` 项目和网络数据包 的分析，旨在实现**技术研究**与**互操作性 (Interoperability)**，为 Dr.Com 官方尚未支持的平台提供一个纯粹的 Python 核心库，用于实现基础的网络认证。

## 特性

  * **现代 Python**：完全使用 Python 3.13+ 重构，包含完整的类型提示 (Type Hinting) 和现代范式。
  * **API 优先**：封装为 `DrcomCore` 类，提供清晰的 `login()`, `start_heartbeat()`, `logout()` 接口，易于二次开发。
  * **配置分离**：通过 `.env` 文件管理所有认证参数，代码零侵入。
  * **健壮的会话管理**：通过 `atexit` 和线程事件 (`threading.Event`) 确保进程的灵活性。

## 重要声明与免责

**本项目是一个独立的第三方实现，与 广州热点软件科技股份有限公司 没有任何关联，也未获得其官方认可或支持。**

"Dr.Com" 是广州热点软件科技股份有限公司的注册商标。本项目中提及该名称仅为指示性目的，用于说明本项目所实现的协议兼容性。

本项目按“原样”提供，不提供任何形式的明示或暗示担保。开发者不对使用本软件可能导致的任何直接或间接后果负责，包括但不限于账户异常、网络中断、或与 Dr.Com 最终用户许可协议 (EULA) 的潜在冲突。

**请您自行承担所有使用风险。您有责任在遵守当地法律法规和您所在机构的“网络管理规定”的前提下使用本软件。严禁将本软件用于任何非法或违规目的。**

## 安装

1.  本项目需要 **Python 3.13** 或更高版本。
2.  克隆本仓库：
    ```bash
    git clone https://github.com/CaelestisAstesia/Drcom-Core.git
    cd Drcom-Core
    ```
3.  安装依赖：
    ```bash
    pip install -r requirements.txt
    ```

## 使用

本项目既可以作为即开即用的**命令行工具**运行，也可以作为**库**导入到你自己的项目中。

### 1\. 配置

无论使用哪种方式，你都必须先创建配置文件：

1.  复制配置模板：
    ```bash
    cp .env.example .env
    ```
2.  编辑 `.env` 文件，填入你**自己**的认证信息（如 `USERNAME`, `PASSWORD`, `SERVER_IP`, `MAC` 等）。
3.  对于部分学校用户，请先参考`drcom-generic`的各校配置文件、其他配置来源，或者简单抓包分析一下，我们暂时没有做到所有的院校都即开即用（暂时没有来自多种环境的开发者）。


### 2\. 作为命令行工具

配置好 `.env` 文件后，直接在项目根目录运行 `src/main.py` 模块：

```bash
python -m src.main
```

程序将会自动读取 `.env` 配置，执行登录，启动后台心跳，并保持在线。

按 `Ctrl+C` 退出，程序会自动调用登出。

### 3\. 作为库使用

你可以 `import DrcomCore` 到你自己的 Python 项目中。

我们提供了一个完整的最小示例，请参考项目根目录下的 `example.py` 文件。

## 贡献

我们非常欢迎任何形式的贡献，特别是来自不同网络环境的配置和测试反馈。请在提交 PR 或 Issue 之前，阅读我们的《贡献指南》。如果你正在寻找可以开始的地方，请查看我们的和[项目路线图](./ROADMAP.md)。

## 许可证

本项目基于 **GNU Affero General Public License v3.0 (AGPLv3)** 许可证发布。

简而言之：您可以自由地运行、研究、共享和修改本软件。但任何基于本项目的衍生作品（**包括通过网络提供服务**）都**必须**同样采用 AGPLv3 许可证开源。

详细文本请参见 `LICENSE` 文件。

## 致谢

  * 本项目是在 `drcom-generic` (https://github.com/drcoms/drcom-generic) 项目的基础上进行的现代化重构。向 `drcom-generic` 社区的前辈们致敬。
  * 本项目的大部分代码和文档是在 AI 辅助工具 (Google Gemini Pro) 的帮助下完成的。
