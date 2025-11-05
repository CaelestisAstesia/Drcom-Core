# example.py
"""
这是一个 DrcomCore API 的最小示例。

它演示了如何将 drcom-core 作为一个库导入到你自己的项目中，
并通过“依赖注入”的方式传入配置。
"""

import atexit
import logging
import sys
import time
from typing import Optional

# (可选) 日志配置
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("DrcomExample")

try:
    # (绝对导入)
    from src.drcom_core.core import DrcomCore

    logger.info("成功导入 DrcomCore。")
except ImportError as ie:
    logger.critical(f"导入 DrcomCore 失败: {ie}")
    sys.exit(1)


# --- 这是 API 调用者（你的 GUI 或 CLI）需要做的事 ---
def get_my_configuration() -> dict:
    """
    [示例] 模拟一个函数来加载配置。
    在实际应用中，你可能会从 GUI 的输入框、
    你自己的 .ini 文件或动态参数来获取这些值。
    """
    logger.info("示例程序: 正在加载配置...")
    # 为了演示，我们硬编码配置。
    # 在实际的 CLI 中，你应该使用 load_dotenv() 从 .env 加载。
    config = {
        "SERVER_IP": "10.100.61.3",  # 必须
        "USERNAME": "your_username",  # 必须
        "PASSWORD": "your_password",  # 必须
        "HOST_IP": "49.1.1.1",  # 必须
        "MAC": "001122334455",  # 必须
        # --- 以下是某些大学的特定配置 (来自抓包，根据实际情况修改) ---
        "AUTH_VERSION": "2c00",
        "ADAPTERNUM": "07",
        "PRIMARY_DNS": "10.10.10.10",
        "HOST_OS": "DrCOM...",
        # --- 其他可选配置 (使用库的默认值) ---
        # "HOST_NAME": "My-PC",
        # "KEEP_ALIVE_VERSION": "dc02",
        # "CONTROL_CHECK_STATUS": "20",
    }

    # 检查基本配置
    required_keys = ["SERVER_IP", "USERNAME", "PASSWORD", "HOST_IP", "MAC"]
    if any(not config.get(k) for k in required_keys):
        logger.critical("示例配置不完整！请编辑 example.py 并填入你的信息。")
        sys.exit(1)

    return config


# --- 配置加载结束 ---


def main() -> None:
    """
    程序主入口点。
    """
    logger.info("启动 Dr.COM 客户端 (API 示例模式)...")
    core_instance: Optional[DrcomCore] = None

    try:
        # 1. 获取配置
        my_config = get_my_configuration()

        # 2. 实例化 Core，注入配置
        core_instance = DrcomCore(config=my_config)

        # 3. 注册退出钩子 (重要!)
        atexit.register(core_instance.logout)

        # 4. 执行登录
        if core_instance.login():
            logger.info("登录成功。启动后台心跳维持...")

            # 5. 启动心跳线程
            core_instance.start_heartbeat()

            # 6. 主线程保持活动
            logger.info("认证完成，正在维持在线状态。按 Ctrl+C 退出。")
            while True:
                time.sleep(10)
                if not core_instance.login_success:
                    logger.warning("检测到心跳停止或掉线，主程序将退出。")
                    break
        else:
            logger.error("登录失败，请检查配置和网络。程序退出。")
            sys.exit(1)

    except (ValueError, KeyError) as config_err:
        logger.critical(f"启动失败: {config_err}")
        sys.exit(1)
    except KeyboardInterrupt:
        logger.info("收到用户中断信号 (Ctrl+C)，准备退出...")
    except SystemExit as e:
        logger.info(f"程序因调用 sys.exit() 而退出: {e}")
    except Exception:
        logger.critical("主程序发生意外错误。", exc_info=True)
    finally:
        logger.info("Dr.COM 客户端 (示例) 已停止。")


# 程序入口
if __name__ == "__main__":
    main()
