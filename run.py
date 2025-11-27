#!/usr/bin/env python
# run.py
"""
Drcom-Core V1.0.0 参考实现

功能特点：
1. 全自动守护：掉线自动重连，异常自动恢复。
2. 信号处理：支持优雅退出。
3. 状态反馈：通过回调输出实时状态。
"""

import logging
import signal
import sys
import time
from pathlib import Path

# --- 导入 drcom-core API ---
try:
    from drcom_core import (
        AuthError,  # 用于处理认证拒绝 (不可恢复错误)
        ConfigError,  # 用于配置加载错误
        CoreStatus,  # 用于状态枚举
        DrcomCore,  # 核心引擎
        load_config_from_toml,  # 配置加载器
    )
except ImportError as ie:
    print(f"导入 DrcomCore API 失败: {ie}", file=sys.stderr)
    sys.exit(1)


# =========================================================================
# 日志配置
# =========================================================================
def setup_logging():
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    formatter = logging.Formatter(
        "%(asctime)s - [%(levelname)s] %(name)s: %(message)s", datefmt="%H:%M:%S"
    )
    console_handler.setFormatter(formatter)

    # 库日志
    lib_logger = logging.getLogger("drcom_core")
    lib_logger.setLevel(logging.DEBUG)  # 生产环境建议 INFO，调试改 DEBUG
    lib_logger.addHandler(console_handler)

    # 应用日志
    app_logger = logging.getLogger("App")
    app_logger.setLevel(logging.DEBUG)
    app_logger.addHandler(console_handler)

    return app_logger


# =========================================================================
# 状态回调
# =========================================================================
def on_status_change(status: CoreStatus, msg: str):
    icons = {
        CoreStatus.IDLE: "💤",
        CoreStatus.CONNECTING: "⏳",
        CoreStatus.LOGGED_IN: "✅",
        CoreStatus.HEARTBEAT: "💓",
        CoreStatus.OFFLINE: "🔌",
        CoreStatus.ERROR: "❌",
    }
    icon = icons.get(status, "❓")
    print(f"\n>>> [UI更新] 状态: {status.name} {icon} | 消息: {msg}\n")


# =========================================================================
# 主程序
# =========================================================================
def main():
    logger = setup_logging()

    # 1. 加载配置
    project_root = Path(__file__).resolve().parent
    config_path = project_root / "config.toml"
    logger.info(f"正在加载配置: {config_path}")

    try:
        config = load_config_from_toml(config_path)
    except ConfigError as e:
        logger.critical(f"配置加载失败: {e}")
        sys.exit(1)

    # 2. 初始化引擎
    core = DrcomCore(config, status_callback=on_status_change)

    # 3. 注册信号 (Ctrl+C)
    def signal_handler(sig, frame):
        logger.info("收到退出信号，正在停止...")
        core.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # 4. 无限重连循环 (Daemon Loop)
    retry_count = 0

    while True:
        try:
            # --- 尝试登录 ---
            if core.login():
                retry_count = 0  # 成功登录，重置计数器

                # --- 启动心跳 ---
                core.start_heartbeat()

                # --- 阻塞监控 (直到掉线) ---
                # 只要 core 认为自己在线，主线程就在这里挂起
                # 心跳失败 3 次后，core 会自动将状态改为 OFFLINE，这里的循环就会结束
                while core.state.is_online:
                    time.sleep(1)

                logger.warning("检测到掉线或心跳停止，准备重连...")
            else:
                logger.error("登录流程未成功，准备重试...")
                retry_count += 1

        except AuthError as ae:
            # [特殊处理] 认证被拒绝 (如密码错误、欠费、MAC绑定错误)
            # 这些错误重试通常没用，应该直接退出报警
            logger.critical(f"认证失败 (不可恢复): {ae}")
            if ae.error_code == 0x04:  # 余额不足
                logger.critical(">>> 提示: 您的账户可能已欠费！ <<<")

            # 也可以选择不退出，而是长时间等待后重试 (防止只是服务器抽风误报)
            # 这里我们选择退出，因为 AuthError 通常是硬伤
            sys.exit(2)

        except Exception as e:
            # [兜底处理] 捕获 NetworkError, ProtocolError 以及所有未知的 Python 异常
            logger.error(f"发生异常: {e}")
            retry_count += 1

        # --- 退避重连策略 ---
        # 失败次数越多，等待时间越长 (3s -> 6s -> 9s ... Max 60s)
        wait_time = min(retry_count * 3, 60)
        if wait_time < 3:
            wait_time = 3

        logger.info(f"{wait_time} 秒后尝试第 {retry_count} 次重连...")

        # 确保清理旧连接 (关闭 Socket，重置状态)
        core.stop()
        time.sleep(wait_time)


if __name__ == "__main__":
    main()
