# src/main.py

import logging
import traceback
from typing import Optional

from .drcom_core.core import DrcomCore

# 配置日志记录
# 获取根 logger
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        # logging.FileHandler("main.log", encoding='utf-8'), # 如果需要写入文件
        logging.StreamHandler()  # 输出到控制台
    ],
)
# 可以单独为 core 模块设置更低的级别，例如 DEBUG
# logging.getLogger("src.drcom_core.core").setLevel(logging.INFO)
# 打印调试信息
# logger.debug(f"Current working directory: {os.getcwd()}")
# logger.debug(f"sys.path inside main.py: {sys.path}")

logger = logging.getLogger(__name__)  # 获取 main 模块的 logger

# 日志配置结束


# 主函数定义
def main() -> None:
    """程序主入口点"""
    logger.info("启动 Dr.COM 客户端。")
    core: Optional[DrcomCore] = None  # 类型提示，初始化为 None
    try:
        # 实例化 DrcomCore
        core = DrcomCore()

        # 启动核心认证和心跳循环
        # run() 方法内部会处理 Challenge, Login, Keep Alive 以及异常和重连
        core.run()

    except KeyboardInterrupt:
        logger.info("收到用户中断信号 (Ctrl+C)，准备退出...")
        # run() 方法内部的 finally 应该会处理登出和关闭 socket
    except SystemExit as e:
        # 捕获由 core 内部 sys.exit() 引发的退出
        logger.info(f"程序因调用 sys.exit() 而退出: {e}")
    except Exception as e:
        # 捕获主函数层面未预料的异常
        logger.critical(
            "\n==================== 主程序发生意外错误 ===================="
        )
        logger.critical(f"错误类型: {type(e).__name__}")
        logger.critical(f"错误详情: {e}")
        logger.critical("------------------------- Traceback -------------------------")
        logger.critical(traceback.format_exc())
        logger.critical("============================================================")
        logger.critical("因发生严重错误而退出。")
    finally:
        # 最终清理
        # 这里的清理主要是为了应对 core 对象未能成功创建或 run() 方法未能正常退出的情况
        logger.info("执行主程序最终清理...")
        if (
            core
            and hasattr(core, "core_socket")
            and core.core_socket
            and not core.core_socket._closed
        ):
            try:
                # 尝试再次确保 socket 关闭，以防 core.run() 的 finally 未执行
                logger.debug("尝试关闭核心 socket")
                core.core_socket.close()
            except Exception as final_close_e:
                logger.error(f"最终关闭 socket 时发生错误: {final_close_e}")
        else:
            logger.debug("核心 socket 不存在或已关闭。")

        logger.info("Dr.COM 客户端已停止。")


# 程序入口
if __name__ == "__main__":
    main()  # 调用主函数
