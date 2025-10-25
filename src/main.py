# src/main.py

import logging  # 用于日志记录
import traceback  # 用于打印详细的错误堆栈信息
from pathlib import Path  # 用于路径操作
from typing import Optional  # 用于类型提示

# 日志配置
# 定义日志格式
log_formatter = logging.Formatter(
    "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)

# 配置根 logger
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)

# 添加控制台输出 handler
console_handler = logging.StreamHandler()
console_handler.setFormatter(log_formatter)

logger = logging.getLogger(__name__)

# 日志配置结束


# 尝试相对导入 DrcomCore
try:
    from .drcom_core.core import DrcomCore

    logger.info("成功导入 DrcomCore。")  # 移动日志记录到 try 块内部
except ImportError as ie:
    # 如果相对导入失败，提供更详细的调试信息
    logger.error(f"导入 DrcomCore 失败: {ie}")
    logger.error("请确保:")
    import os
    import sys

    logger.error(
        f"    1. 你正从项目根目录 ({os.path.dirname(os.path.dirname(os.path.abspath(__file__)))}) 使用 'python -m src.main' 运行。"
    )
    logger.error("    2. 目录结构正确 (例如 src/drcom_core/core.py)。")
    logger.error(
        "    3. 所有必要的 __init__.py 文件存在 (在 src/, src/drcom_core/, src/drcom_protocol/ 目录下)。"
    )

    init_files_to_check = [
        Path("src/__init__.py"),
        Path("src/drcom_core/__init__.py"),
        Path("src/drcom_protocol/__init__.py"),
    ]
    missing_files = [str(f) for f in init_files_to_check if not f.exists()]
    if missing_files:
        logger.warning(f"    [警告] 缺少文件: {', '.join(missing_files)}")

    # 打印 sys.path 帮助调试导入问题
    # logger.debug(f"    sys.path: {sys.path}") # 可以取消注释以进行深度调试

    logger.critical("依赖导入失败，程序退出。")
    sys.exit(1)
except Exception as e:
    logger.critical(f"导入过程中发生意外错误: {e}", exc_info=True)
    logger.critical("导入检查时发生错误，程序退出。")
    sys.exit(1)


# 主函数定义
def main() -> None:
    """
    程序主入口点。
    负责初始化 DrcomCore 实例并启动认证和心跳维持流程。
    处理顶层异常和程序退出。
    """
    logger.info("启动 Dr.COM 客户端...")
    core_instance: Optional[DrcomCore] = None  # 类型提示，初始化为 None

    try:
        # 1. 实例化 DrcomCore
        #    初始化过程中会加载配置并设置网络
        core_instance = DrcomCore()

        # 2. 启动核心认证和心跳循环
        #    run() 方法内部处理 Challenge, Login, Keep Alive, 异常, 重连和登出逻辑
        core_instance.run()

    except KeyboardInterrupt:
        logger.info("收到用户中断信号 (Ctrl+C)，准备退出...")
        # run() 方法内部的 finally 会处理登出和 socket 关闭
    except SystemExit as e:
        # 捕获由 core 内部 sys.exit() 引发的退出 (通常是初始化或配置错误)
        logger.info(f"程序因调用 sys.exit() 而退出: {e}")
        # 这里不需要额外处理，因为 core.run() 未必执行，core_instance 可能为 None
    except Exception as e:
        # 捕获主函数层面未预料的严重异常
        logger.critical(
            "\n==================== 主程序发生意外错误 ===================="
        )
        logger.critical(f"错误类型: {type(e).__name__}")
        logger.critical(f"错误详情: {e}")
        logger.critical("------------------------- Traceback -------------------------")
        logger.critical(traceback.format_exc())  # 记录完整的错误堆栈
        logger.critical("============================================================")
        logger.critical("因发生严重错误而退出。")
    finally:
        # 最终清理：确保资源被释放，尤其是在 core_instance 未成功创建或 run() 未正常结束时
        logger.info("执行主程序最终清理...")

        # 尝试关闭 socket (如果 core 实例和 socket 存在且未关闭)
        # 这是为了防止 core.run() 的 finally 未被执行或执行不完整
        if (
            core_instance
            and hasattr(core_instance, "core_socket")
            and core_instance.core_socket
            and not core_instance.core_socket._closed
        ):
            try:
                logger.debug("尝试最终关闭核心 socket...")
                core_instance.core_socket.close()
            except Exception as final_close_e:
                logger.error(f"最终关闭 socket 时发生错误: {final_close_e}")
        # else: # 可以取消注释以增加调试信息
        #     if not core_instance:
        #         logger.debug("最终清理：DrcomCore 实例未创建。")
        #     elif not hasattr(core_instance, "core_socket") or not core_instance.core_socket:
        #         logger.debug("最终清理：核心 socket 不存在。")
        #     else: # core_instance.core_socket._closed is True
        #         logger.debug("最终清理：核心 socket 已关闭。")

        logger.info("Dr.COM 客户端已停止。")


# 程序入口
if __name__ == "__main__":
    main()  # 调用主函数
