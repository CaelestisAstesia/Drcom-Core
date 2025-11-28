---
layout: default
title: 快速上手
nav_order: 2
---

# 快速上手

Drcom-Core 被设计为极其易于集成。你只需要一个配置文件和不到 50 行代码，就能构建一个具备**自动掉线重连**功能的认证客户端。

## 1. 准备配置

在项目根目录下创建一个 `config.toml` 文件。
（你可以复制 `config.toml.example` 并修改其中的账号、密码和 IP 信息）

## 2. 最小实现示例

新建一个 Python 脚本（例如 `main.py`），写入以下代码。

这个示例展示了 `Drcom-Core` 的最佳实践：
* **状态回调**：通过 callback 实时打印漂亮的 Log。
* **守护循环**：主线程阻塞监听掉线，一旦掉线自动触发重连。
* **优雅退出**：捕获 Ctrl+C 并执行清理。

```python
import signal
import sys
import time
from drcom_core import DrcomCore, CoreStatus, AuthError, load_config_from_toml

# --- 1. 定义漂亮的日志回调 ---
def on_status(status: CoreStatus, msg: str):
    """当引擎状态发生变化时，打印带 Emoji 的提示"""
    icons = {
        CoreStatus.CONNECTING: "⏳",
        CoreStatus.LOGGED_IN:  "✅",
        CoreStatus.HEARTBEAT:  "💓",
        CoreStatus.OFFLINE:    "🔌",
        CoreStatus.ERROR:      "❌",
    }
    print(f"[{icons.get(status, ' ')}] {status.name}: {msg}")

def main():
    # --- 2. 加载配置与初始化 ---
    try:
        config = load_config_from_toml("config.toml")
        core = DrcomCore(config, status_callback=on_status)
    except Exception as e:
        print(f"初始化失败: {e}")
        return

    # --- 3. 注册退出信号 (Ctrl+C) ---
    def stop_handler(signum, frame):
        print("\n正在停止服务...")
        core.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, stop_handler)
    signal.signal(signal.SIGTERM, stop_handler)

    # --- 4. 无限重连循环 ---
    print(f">>> Drcom-Core 启动 (用户: {config.username})")

    while True:
        try:
            # 尝试登录
            if core.login():
                # 登录成功，启动后台心跳线程
                core.start_heartbeat()

                # 主线程阻塞，直到掉线 (is_online 变为 False)
                while core.state.is_online:
                    time.sleep(1)
            else:
                # 登录返回 False (通常是网络不通)
                print("登录失败，3秒后重试...")

        except AuthError as e:
            # 致命错误（密码错误、欠费等），不应重试
            print(f"认证被拒绝: {e}")
            break
        except Exception as e:
            print(f"发生异常: {e}")

        # 掉线或异常后的退避等待
        time.sleep(3)

if __name__ == "__main__":
    main()
