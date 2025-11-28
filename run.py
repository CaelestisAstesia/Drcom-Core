#!/usr/bin/env python
# run_debug.py (临时测试脚本，不提交到 git)
# 功能：优先加载本地 config.toml 进行真实连接测试

import logging
import signal
import socket
import sys
import time
from pathlib import Path

# --- 0. 环境准备 ---
PROJECT_ROOT = Path(__file__).resolve().parent
# 指向代码目录 (根据实际情况调整为 src 或 src_rebuild)
SRC_PATH = PROJECT_ROOT / "src_rebuild"

if str(SRC_PATH) not in sys.path:
    sys.path.insert(0, str(SRC_PATH))

try:
    from drcom_core import (
        AuthError,
        ConfigError,
        CoreStatus,
        DrcomCore,
        __version__,
        create_config_from_dict,
        load_config_from_toml,  # 改用文件加载器
    )
except ImportError as e:
    print(f"❌ 无法导入 drcom_core: {e}")
    sys.exit(1)

# --- 1. 配置日志 ---
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(name)s - [%(levelname)s] - %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("DebugApp")


# --- 2. 状态回调 ---
def on_status_change(status: CoreStatus, msg: str):
    icon_map = {
        CoreStatus.CONNECTING: "⏳",
        CoreStatus.LOGGED_IN: "✅",
        CoreStatus.HEARTBEAT: "💓",
        CoreStatus.OFFLINE: "🔌",
        CoreStatus.ERROR: "❌",
    }
    icon = icon_map.get(status, "ℹ️")
    print(f"\n>>> [UI Callback] {icon} 状态变更: {status.name} | 消息: {msg}\n")


# --- 3. 主程序 ---
def main():
    print("==========================================")
    print(f"   Drcom-Core v{__version__} Config Runner")
    print("==========================================")

    core = None
    config_path = PROJECT_ROOT / "config.toml"

    # 注册退出信号
    def stop_handler(sig, frame):
        print("\n🛑 收到中断信号，正在停止...")
        if core:
            core.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, stop_handler)

    try:
        # A. 加载配置
        if config_path.exists():
            logger.info(f"📄 发现配置文件: {config_path}")
            # 默认加载 [drcom] 或 [profile.default]
            config = load_config_from_toml(config_path)
        else:
            logger.warning("⚠️ 未找到 config.toml，将使用硬编码的 Mock 数据 (必然超时)")
            # 仅作 Fallback，防止脚本直接崩溃
            MOCK_CONFIG = {
                "username": "mock_user",
                "password": "123",
                "server_ip": "1.1.1.1",
                "drcom_port": 61440,
                "protocol_version": "D",
                "mac": "00:00:00:00:00:00",
                "host_ip": "127.0.0.1",
                "primary_dns": "8.8.8.8",
                "dhcp_server": "1.1.1.1",
            }
            config = create_config_from_dict(MOCK_CONFIG)

        logger.debug(
            f"配置加载完成: HostIP={socket.inet_ntoa(config.host_ip_bytes)} Server={config.server_address}"
        )

        # B. 初始化引擎
        logger.info("正在初始化引擎...")
        core = DrcomCore(config, status_callback=on_status_change)

        # C. 登录流程
        logger.info(">>> 发起登录请求...")
        if core.login():
            logger.info(">>> 登录成功！启动心跳保活...")
            core.start_heartbeat()

            logger.info(">>> 服务平稳运行中 (按 Ctrl+C 退出)...")
            # 阻塞主线程，直到核心状态变为离线
            while core.state.is_online:
                time.sleep(1)

            logger.warning(">>> 核心已离线 (心跳丢失或被踢)，测试结束。")
        else:
            logger.error(
                ">>> 登录失败 (返回 False)。请检查：1.IP是否被拦截 2.网线是否插好"
            )

    except AuthError as ae:
        logger.error(f"⛔ 认证被拒绝: {ae}")
    except ConfigError as ce:
        logger.error(f"🔧 配置错误: {ce}")
    except Exception as e:
        logger.exception(f"⚠️ 运行时异常: {e}")
    finally:
        if core:
            core.stop()
        logger.info("进程退出。")


if __name__ == "__main__":
    main()
