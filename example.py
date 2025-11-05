# example.py
"""
这是一个 DrcomCore API 的最小示例。

它演示了如何将 drcom-core 作为一个库导入到你自己的项目中，
并实现一个健壮的“登录-维持心跳-自动登出”循环。

运行此示例：
1. 确保已在根目录创建并配置了 .env 文件。
2. 确保已安装依赖： pip install -r requirements.txt
3. 从项目根目录运行： python example.py
"""

import atexit
import logging
import sys
import time
from typing import Optional

# 日志配置开始
log_formatter = logging.Formatter(
    "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logging.basicConfig(
    level=logging.DEBUG, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
console_handler = logging.StreamHandler()
console_handler.setFormatter(log_formatter)
logger = logging.getLogger("DrcomExample")
# 日志配置结束

try:
    from src.drcom_core.core import DrcomCore

    logger.info("成功导入 DrcomCore。")
except ImportError as ie:
    logger.critical(f"导入 DrcomCore 失败: {ie}")
    logger.critical("请确保你是从项目根目录运行此脚本 (python example.py)")
    sys.exit(1)
except Exception as e:
    logger.critical(f"导入过程中发生意外错误: {e}", exc_info=True)
    sys.exit(1)


def main() -> None:
    """
    程序主入口点。
    使用 DrcomCore API 启动认证并维持心跳。
    """
    logger.info("启动 Dr.COM 客户端 (API 示例模式)...")
    core_instance: Optional[DrcomCore] = None

    try:
        # 1. 实例化 Core
        #    (在 __init__ 期间会自动加载 .env 配置并初始化网络)
        core_instance = DrcomCore()

        # 2. 注册退出钩子 (重要!)
        #    atexit 确保程序在任何情况下退出前，都会尝试调用 logout()
        atexit.register(core_instance.logout)

        # 3. 执行登录
        if core_instance.login():
            logger.info("登录成功。启动后台心跳维持...")

            # 4. 启动心跳线程
            core_instance.start_heartbeat()

            # 5. 主线程保持活动
            logger.info("认证完成，正在维持在线状态。按 Ctrl+C 退出。")
            while True:
                time.sleep(10)
                # 如果心跳线程因为掉线等原因意外停止，login_success 会被设为 False
                if not core_instance.login_success:
                    logger.warning("检测到心跳停止或掉线，主程序将退出。")
                    break  # 退出 while True，程序将进入 finally

        else:
            # 登录失败
            logger.error("登录失败，请检查配置和网络。程序退出。")
            sys.exit(1)  # 主动退出

    except KeyboardInterrupt:
        # 用户按下了 Ctrl+C
        logger.info("收到用户中断信号 (Ctrl+C)，准备退出...")
        # atexit 注册的 core_instance.logout() 会在这里被自动调用

    except SystemExit as e:
        # 捕获到 sys.exit()
        logger.info(f"程序因调用 sys.exit() 而退出: {e}")

    except Exception:
        # 捕获所有其他未知错误
        logger.critical("主程序发生意外错误。", exc_info=True)

    finally:
        # atexit 已经处理了 logout，这里只打印最终信息
        logger.info("Dr.COM 客户端 (示例) 已停止。")


# 程序入口
if __name__ == "__main__":
    main()
