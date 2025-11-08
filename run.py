#!/usr/bin/env python
# run.py
"""
Drcom-Core 临时启动器 (替代旧的 src/main.py)

本文件演示了如何正确地将 drcom-core 作为一个库来使用：
1. (应用层) 配置专业的、可轮转的日志记录。
2. (应用层) 从 .env 加载配置到字典。
3. (API调用) 使用库的 `load_config_from_dict` 解析字典为强类型 Config 对象。
4. (API调用) 将 Config 对象注入 DrcomCore。
5. (API调用) 调用 core 的 API (login, start_heartbeat)。
"""

import atexit
import logging
import os
import sys
import time
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Dict, Optional

try:
    from dotenv import load_dotenv
except ImportError:
    print("错误：未找到 python-dotenv 库。", file=sys.stderr)
    print("请运行: pip install python-dotenv", file=sys.stderr)
    sys.exit(1)

# --- 导入 drcom-core API ---
try:
    from drcom_core import DrcomCore, load_config_from_dict
except ImportError as ie:
    print(f"导入 DrcomCore API 失败: {ie}", file=sys.stderr)
    print("你是否忘记安装whl包 ?", file=sys.stderr)
    sys.exit(1)


def setup_logging(log_dir: Path):
    """
    (应用层) 配置日志记录。
    库 (drcom-core) 绝不能调用这个。
    """
    log_file = log_dir / "drcom.log"

    # 1. 定义格式
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )

    # 2. 配置 Handler 1: 轮转文件处理器 (记录 DEBUG 及以上)
    # 5MB * 5个备份文件
    try:
        file_handler = RotatingFileHandler(
            log_file, maxBytes=5 * 1024 * 1024, backupCount=5, encoding="utf-8"
        )
    except PermissionError:
        print(f"错误：无法写入日志文件 {log_file}，请检查权限。", file=sys.stderr)
        # 即使文件日志失败，我们仍然可以继续（日志将只输出到控制台）
        file_handler = None
    except Exception as e:
        print(f"设置文件日志时发生未知错误: {e}", file=sys.stderr)
        file_handler = None

    if file_handler:
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)

    # 3. 配置 Handler 2: 控制台处理器 (只记录 INFO 及以上)
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)

    # 4. 获取我们关心的两个 Logger，并应用配置

    # a) "drcom_core" (库的所有日志)
    #    (drcom_core/core.py, drcom_core/network.py,
    #     等文件中的 getLogger(__name__) 都会是这个 logger 的子孙)
    lib_logger = logging.getLogger("drcom_core")
    lib_logger.setLevel(logging.DEBUG)  # 必须设置 Logger 级别为最低 (DEBUG)
    if file_handler:
        lib_logger.addHandler(file_handler)
    lib_logger.addHandler(console_handler)
    lib_logger.propagate = False  # 阻止日志冒泡到根 logger (防止重复打印)

    # b) "DrcomLauncher" (本启动器应用的日志)
    app_logger = logging.getLogger("DrcomLauncher")
    app_logger.setLevel(logging.DEBUG)
    if file_handler:
        app_logger.addHandler(file_handler)
    app_logger.addHandler(console_handler)
    app_logger.propagate = False

    app_logger.info("日志系统初始化完成。")
    if file_handler:
        app_logger.info(f"文件日志将记录到: {log_file}")
    else:
        app_logger.warning("文件日志记录失败，日志将只输出到控制台。")


def load_env_config(root_dir: Path) -> Dict[str, Any]:
    """
    (应用层) 从 .env 文件加载配置到原始字典。
    """
    env_path = root_dir / ".env"
    example_path = root_dir / ".env.example"

    logger = logging.getLogger("DrcomLauncher")  # 获取我们刚配置好的 logger
    logger.info(f"正在从 {env_path} 加载配置...")

    if not env_path.exists():
        logger.warning("未找到 .env 文件。")
        if example_path.exists():
            logger.warning(f"请从 {example_path} 复制并创建 .env 文件。")
        else:
            logger.warning(f"也未找到 {example_path} 模板文件。")

    # override=True: 允许环境变量覆盖 .env 文件中的值
    load_dotenv(dotenv_path=env_path, override=True)

    # os.environ 是一个字典，我们将其复制一份
    return dict(os.environ)


def main() -> None:
    """
    程序主入口点。
    """
    # 0. 确定项目根目录
    project_root = Path(__file__).resolve().parent

    # 1. 配置日志系统 (必须在所有日志记录之前)
    setup_logging(project_root)

    # 获取应用 logger
    logger = logging.getLogger("DrcomLauncher")
    logger.info("启动 Dr.COM 客户端 (run.py 模式)...")

    core_instance: Optional[DrcomCore] = None

    try:
        # 2. (应用层) 加载原始配置
        raw_config_dict = load_env_config(project_root)

        # 3. [API] 使用库来解析和验证配置
        #    如果缺少关键键或格式错误 (如MAC)，这里会抛出异常
        config = load_config_from_dict(raw_config_dict)

        # 4. [API] 实例化 Core，注入配置
        core_instance = DrcomCore(config=config)

        # 5. (应用层) 注册退出钩子 (重要!)
        #    atexit 会在程序正常退出或 Ctrl+C 中断时调用 core_instance.logout()
        atexit.register(core_instance.logout)

        # 6. [API] 执行登录
        if core_instance.login():
            logger.info("登录成功。启动后台心跳维持...")

            # 7. [API] 启动心跳线程
            core_instance.start_heartbeat()

            # 8. (应用层) 主线程保持活动
            logger.info("认证完成，正在维持在线状态。按 Ctrl+C 退出。")
            while True:
                time.sleep(10)
                # (core.state.login_success 会在心跳失败时被 core 内部设置为 False)
                if not core_instance.state.login_success:
                    logger.warning("检测到心跳停止或掉线，主程序将退出。")
                    break
        else:
            logger.error("登录失败，请检查配置和网络。程序退出。")
            sys.exit(1)

    except (ValueError, KeyError) as config_err:
        # 捕获 load_config_from_dict 或 DrcomCore.__init__ 抛出的错误
        logger.critical(f"启动失败: {config_err}")
        logger.critical(
            "请确保你的 .env 文件 包含所有必要的键 (USERNAME, PASSWORD, HOST_IP, MAC, SERVER_IP)。"
        )
        sys.exit(1)
    except KeyboardInterrupt:
        logger.info("收到用户中断信号 (Ctrl+C)，准备退出...")
        # atexit 钩子将在这里执行
    except SystemExit as e:
        logger.info(f"程序因调用 sys.exit() 而退出: {e}")
    except Exception:
        # 使用 logger.exception 自动记录完整的堆栈信息
        logger.exception("主程序发生意外错误，即将退出。")
    finally:
        logger.info("Dr.COM 客户端 (run.py) 已停止。")


# 程序入口
if __name__ == "__main__":
    main()
