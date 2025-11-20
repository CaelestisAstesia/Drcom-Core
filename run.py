#!/usr/bin/env python
# run.py
"""
Drcom-Core V1.0.0a3 参考实现

本文件演示了如何作为"应用层"消费 drcom-core 库：
1. 配置层：从 config.toml 加载严格类型化的配置。
2. 交互层：通过 status_callback 接收核心库的状态变更。
3. 控制层：处理登录逻辑、异常捕获 (AuthError) 和生命周期管理。
"""

import logging
import signal
import sys
import time
from pathlib import Path

# --- 导入 drcom-core API ---
try:
    from drcom_core import (
        AuthError,
        ConfigError,
        CoreStatus,
        DrcomCore,
        DrcomError,
        load_config_from_toml,  # [变更] 使用新的加载器
    )
except ImportError as ie:
    print(f"导入 DrcomCore API 失败: {ie}", file=sys.stderr)
    print("提示: 如果是在源码目录运行，请设置 PYTHONPATH=src", file=sys.stderr)
    sys.exit(1)


# =========================================================================
# 1. 应用层日志配置
# =========================================================================
def setup_logging():
    """配置日志格式和输出目标"""
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    formatter = logging.Formatter(
        "%(asctime)s - [%(levelname)s] %(name)s: %(message)s", datefmt="%H:%M:%S"
    )
    console_handler.setFormatter(formatter)

    # 库日志 (显示 DEBUG 以便排查)
    lib_logger = logging.getLogger("drcom_core")
    lib_logger.setLevel(logging.DEBUG)
    lib_logger.addHandler(console_handler)
    lib_logger.propagate = False

    # 应用日志
    app_logger = logging.getLogger("App")
    app_logger.setLevel(logging.INFO)
    app_logger.addHandler(console_handler)
    app_logger.propagate = False

    return app_logger


# =========================================================================
# 2. 状态回调
# =========================================================================
def on_status_change(status: CoreStatus, msg: str):
    """当核心库状态发生变化时调用"""
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
# 3. 主程序
# =========================================================================
def main():
    logger = setup_logging()

    # [变更] 配置文件路径解析
    project_root = Path(__file__).resolve().parent
    config_path = project_root / "config.toml"

    # A. 加载配置 (从 TOML)
    logger.info(f"正在加载配置: {config_path}")
    try:
        # 使用 v1.0.0a3 新增的 TOML 加载器
        config = load_config_from_toml(config_path)
    except ConfigError as e:
        logger.critical(f"配置加载失败: {e}")
        logger.critical("请检查 config.toml 是否存在且格式正确。")
        sys.exit(1)

    # B. 初始化引擎
    core = DrcomCore(config, status_callback=on_status_change)

    # C. 注册优雅退出
    def signal_handler(sig, frame):
        logger.info("收到退出信号，正在停止...")
        core.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # D. 执行业务流程
    try:
        # 1. 登录
        if core.login():
            logger.info("认证通过，准备启动心跳...")

            # 2. 启动心跳 (后台线程)
            core.start_heartbeat()

            # 3. 保持运行
            logger.info("服务已就绪。按 Ctrl+C 退出。")
            while True:
                time.sleep(1)
                if not core.state.is_online:
                    logger.error("检测到掉线！")
                    break
        else:
            logger.error("登录失败。")
            sys.exit(1)

    except AuthError as ae:
        logger.error(f"认证被拒绝: {ae}")
        if ae.error_code == 0x04:
            logger.critical(">>> 提示: 您的账户可能已欠费！ <<<")
        sys.exit(2)

    except DrcomError as e:
        logger.error(f"运行时错误: {e}")
        sys.exit(3)


if __name__ == "__main__":
    main()
