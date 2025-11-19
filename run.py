#!/usr/bin/env python
# run.py
"""
Drcom-Core V1.1 参考实现 (Reference Implementation)

本文件演示了如何作为"应用层"消费 drcom-core 库：
1. 配置层：负责加载 .env 和配置日志。
2. 交互层：通过 status_callback 接收核心库的状态变更。
3. 控制层：处理登录逻辑、异常捕获 (AuthError) 和生命周期管理。
"""

import logging
import os
import signal
import sys
import time
from pathlib import Path

# 尝试导入外部依赖 python-dotenv
try:
    from dotenv import load_dotenv
except ImportError:
    print("错误：未找到 python-dotenv 库。", file=sys.stderr)
    print("请运行: pip install python-dotenv", file=sys.stderr)
    sys.exit(1)

# --- 导入 drcom-core API ---
# 注意：在开发环境中，确保 src 目录在 PYTHONPATH 中，或者你已经安装了 whl
try:
    from drcom_core import (
        AuthError,
        ConfigError,
        CoreStatus,
        DrcomCore,
        DrcomError,
        load_config_from_dict,
    )
except ImportError as ie:
    print(f"导入 DrcomCore API 失败: {ie}", file=sys.stderr)
    print("提示: 如果是在源码目录运行，请设置 PYTHONPATH=src", file=sys.stderr)
    sys.exit(1)


# =========================================================================
# 1. 应用层日志配置 (Application Logging)
# =========================================================================
def setup_logging():
    """配置日志格式和输出目标"""
    # 创建一个控制台处理器
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    formatter = logging.Formatter(
        "%(asctime)s - [%(levelname)s] %(name)s: %(message)s", datefmt="%H:%M:%S"
    )
    console_handler.setFormatter(formatter)

    # 配置库的 Logger ("drcom_core")
    # 我们希望看到库的 DEBUG 信息以便排查问题
    lib_logger = logging.getLogger("drcom_core")
    lib_logger.setLevel(logging.DEBUG)
    lib_logger.addHandler(console_handler)
    lib_logger.propagate = False

    # 配置应用的 Logger
    app_logger = logging.getLogger("App")
    app_logger.setLevel(logging.INFO)
    app_logger.addHandler(console_handler)
    app_logger.propagate = False

    return app_logger


# =========================================================================
# 2. 状态回调 (IPC/UI 接口)
# =========================================================================
def on_status_change(status: CoreStatus, msg: str):
    """
    当核心库状态发生变化时，此函数会被调用。
    这是 CLI/GUI 更新界面的最佳位置。
    """
    # 定义一些 emoji 让终端输出好看点
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
# 3. 主程序 (Main Controller)
# =========================================================================
def main():
    logger = setup_logging()
    project_root = Path(__file__).resolve().parent
    env_path = project_root / ".env"

    # A. 加载配置
    logger.info(f"正在加载配置: {env_path}")
    if not env_path.exists():
        logger.error("未找到 .env 文件，请从 .env.example 复制并配置。")
        sys.exit(1)

    load_dotenv(dotenv_path=env_path, override=True)

    try:
        # 使用库提供的加载器，它会自动进行类型转换和校验
        config = load_config_from_dict(dict(os.environ))
    except ConfigError as e:
        logger.critical(f"配置错误: {e}")
        sys.exit(1)

    # B. 初始化引擎
    # 将回调函数注入引擎
    core = DrcomCore(config, status_callback=on_status_change)

    # C. 注册优雅退出 (Ctrl+C)
    def signal_handler(sig, frame):
        logger.info("收到退出信号，正在停止...")
        core.stop()  # 调用 V1.1 新增的 stop() API
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # D. 执行业务流程
    try:
        # 1. 登录
        # login() 方法内部会处理 Challenge -> Login 的全流程
        if core.login():
            logger.info("认证通过，准备启动心跳...")

            # 2. 启动心跳 (非阻塞，后台线程)
            core.start_heartbeat()

            # 3. 保持主线程运行 (模拟 CLI 的守护进程模式)
            logger.info("服务已就绪。按 Ctrl+C 退出。")
            while True:
                time.sleep(1)
                # 如果心跳线程意外挂了（比如连续超时），core.state.status 会变
                if not core.state.is_online:
                    logger.error("检测到掉线！(可能是心跳失败或被踢下线)")
                    # 这里可以添加【自动重连】逻辑
                    # time.sleep(5)
                    # core.login() ...
                    break
        else:
            logger.error("登录失败。")
            sys.exit(1)

    except AuthError as ae:
        # V1.1 特性：可以捕获具体的认证业务错误
        logger.error(f"认证被拒绝: {ae}")
        if ae.error_code == 0x04:  # 假设 0x04 是欠费
            logger.critical(">>> 提示: 您的账户可能已欠费，请充值！ <<<")
        elif ae.error_code == 0x01:
            logger.critical(">>> 提示: 账户已在别处登录。 <<<")
        sys.exit(2)

    except DrcomError as e:
        # 捕获其他所有库内错误 (网络、协议等)
        logger.error(f"发生运行时错误: {e}")
        sys.exit(3)


if __name__ == "__main__":
    main()
