---
layout: default
title: 快速上手
nav_order: 2
---

# 快速上手

Drcom-Core 提供了一个生产级的启动脚本 `run.py`，内置了优雅的日志记录、掉线重连检测和信号处理。

你无需编写任何代码，仅需两步即可上线。

## 准备配置

在项目根目录下，将配置模板复制为实际配置文件：

```bash
# Linux / macOS
cp config.toml.example config.toml

# Windows (PowerShell)
Copy-Item config.toml.example config.toml
```

然后使用你喜欢的编辑器修改 `config.toml`，填入你的账号、密码和学校特定的指纹信息（如 `os_info_hex`）。

提示：关于配置项的详细说明，请查阅[配置文件参考](config_reference.md)。

### 启动
直接运行根目录下的 `run.py`：
```Bash
python run.py
```
预期输出：
```Plaintext

10:00:01 - [INFO] App: 正在加载配置: /path/to/config.toml
10:00:01 - [INFO] drcom_core.core: [状态变更] CONNECTING: 正在登录...
10:00:02 - [INFO] drcom_core.protocols.version_520d: D 版登录成功...
10:00:02 - [INFO] drcom_core.core: [状态变更] LOGGED_IN: 登录成功
>>> [UI更新] 状态: LOGGED_IN ✅ | 消息: 登录成功

10:00:02 - [INFO] App: 认证通过，准备启动心跳...
10:00:02 - [INFO] drcom_core.core: [状态变更] HEARTBEAT: 心跳维持中
10:00:02 - [INFO] App: 服务已就绪。按 Ctrl+C 退出。
>>> [UI更新] 状态: HEARTBEAT 💓 | 消息: 心跳维持中
```
程序将持续运行并保持在线。你可以放心地将其挂在后台。

## 进阶：作为库调用 (Library Usage)
如果你是开发者，希望将 Drcom-Core 集成到自己的 GUI 程序（如 PyQt/Tkinter）或 Web 服务中，`run.py` 本身就是最好的参考实现。

核心 API 调用逻辑如下：
```Python
from drcom_core import DrcomCore, load_config_from_toml

# 1. 加载配置
config = load_config_from_toml("config.toml")

# 2. 初始化
core = DrcomCore(config)

# 3. 登录
if core.login():
    # 4. 启动后台保活线程
    core.start_heartbeat()
    print("在线中...")
else:
    print("登录失败")

# 5. 停止
core.stop()
```
