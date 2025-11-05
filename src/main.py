# src/main.py

import atexit
import logging
import sys
import time
from typing import Optional

# 日志配置 (保持不变)
log_formatter = logging.Formatter(
    "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logging.basicConfig(
    level=logging.DEBUG, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
console_handler = logging.StreamHandler()
console_handler.setFormatter(log_formatter)
logger = logging.getLogger(__name__)
# 日志配置结束

try:
    from .drcom_core.core import DrcomCore

    logger.info("成功导入 DrcomCore。")
except ImportError as ie:
    # ... (导入错误处理保持不变) ...
    logger.critical(f"导入 DrcomCore 失败: {ie}")
    # ... (打印调试信息) ...
    sys.exit(1)
except Exception as e:
    logger.critical(f"导入过程中发生意外错误: {e}", exc_info=True)
    sys.exit(1)


def main() -> None:
    """
    程序主入口点。
    使用 DrcomCore API 启动认证并维持心跳。
    """
    logger.info("启动 Dr.COM 客户端 (API 模式)...")
    core_instance: Optional[DrcomCore] = None

    try:
        # 1. 实例化 Core
        core_instance = DrcomCore()

        # 2. 注册退出钩子 (关键！)
        #    atexit.register 会确保在程序以任何方式退出前
        #    （无论是正常结束、异常、还是 Ctrl+C），
        #    都会尝试调用 core_instance.logout()
        atexit.register(core_instance.logout)

        # 3. 执行登录
        if core_instance.login():
            logger.info("登录成功。启动后台心跳维持...")

            # 4. 启动心跳线程
            core_instance.start_heartbeat()

            # 5. 主线程保持活动
            #    主线程不能退出，否则守护线程(心跳)也会随之退出
            logger.info("认证完成，正在维持在线状态。按 Ctrl+C 退出。")
            while True:
                time.sleep(10)  # 我们可以每 10 秒检查一次
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
        logger.info("Dr.COM 客户端已停止。")


# 程序入口
if __name__ == "__main__":
    main()
