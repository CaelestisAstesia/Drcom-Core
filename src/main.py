# src/main.py

import atexit
import logging
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, Optional

from dotenv import load_dotenv

# 日志配置开始
log_formatter = logging.Formatter(
    "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logging.basicConfig(
    level=logging.DEBUG, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
console_handler = logging.StreamHandler()
console_handler.setFormatter(log_formatter)
logger = logging.getLogger("DrcomCLI")  # CLI 日志记录器
# 日志配置结束

try:
    # (相对导入，因为 main.py 仍在 src 包中)
    from .drcom_core.core import DrcomCore

    logger.info("成功导入 DrcomCore。")
except ImportError as ie:
    logger.critical(f"导入 DrcomCore 失败: {ie}")
    sys.exit(1)
except Exception as e:
    logger.critical(f"导入过程中发生意外错误: {e}", exc_info=True)
    sys.exit(1)


def load_cli_config() -> Dict[str, Any]:
    """
    为 CLI 工具加载配置。
    它会查找 .env 文件并将其内容加载到字典中。
    """
    logger.info("CLI: 正在加载配置...")

    # 优先从当前工作目录加载 .env
    env_path = Path.cwd() / ".env"

    if not env_path.exists():
        # 如果CWD没有，尝试从脚本的父目录（项目根目录）加载
        # 这主要用于 `python -m src.main` 调试
        dev_env_path = Path(__file__).resolve().parent.parent / ".env"
        if dev_env_path.exists():
            env_path = dev_env_path
            logger.debug(f"未在 CWD 找到 .env，使用开发路径: {env_path}")
        else:
            logger.warning(f"在 {Path.cwd()} 或 {dev_env_path} 均未找到 .env 文件。")
            # 即使文件不存在，也继续，以便从环境变量加载

    if env_path.exists():
        load_dotenv(dotenv_path=env_path, override=True)
        logger.debug(f"已加载配置文件: {env_path}")

    # 从环境变量中收集配置
    # 注意：这里的键必须与 DrcomCore.__init__ 中 _parse_config 所需的键一致
    config = {
        "SERVER_IP": os.getenv("SERVER_IP"),
        "DRCOM_PORT": os.getenv("DRCOM_PORT"),
        "USERNAME": os.getenv("USERNAME"),
        "PASSWORD": os.getenv("PASSWORD"),
        "HOST_IP": os.getenv("HOST_IP"),
        "BIND_IP": os.getenv("BIND_IP", "0.0.0.0"),  # BIND_IP 在 .env 中是可选的
        "MAC": os.getenv("MAC"),
        "HOST_NAME": os.getenv("HOST_NAME"),
        "HOST_OS": os.getenv("HOST_OS"),
        "PRIMARY_DNS": os.getenv("PRIMARY_DNS"),
        "DHCP_SERVER": os.getenv("DHCP_SERVER"),
        "ADAPTERNUM": os.getenv("ADAPTERNUM"),
        "IPDOG": os.getenv("IPDOG"),
        "AUTH_VERSION": os.getenv("AUTH_VERSION"),
        "CONTROL_CHECK_STATUS": os.getenv("CONTROL_CHECK_STATUS"),
        "KEEP_ALIVE_VERSION": os.getenv("KEEP_ALIVE_VERSION"),
        "ROR_STATUS": os.getenv("ROR_STATUS"),
    }

    # 过滤掉值为 None 的项，以便 Core 内部可以使用默认值
    loaded_config = {k: v for k, v in config.items() if v is not None}
    logger.info(f"CLI: 成功加载 {len(loaded_config)} 项配置。")
    return loaded_config


def main() -> None:
    """
    程序主入口点。
    使用 DrcomCore API 启动认证并维持心跳。
    """
    logger.info("启动 Dr.COM 客户端 (CLI 模式)...")
    core_instance: Optional[DrcomCore] = None

    try:
        # 1. 加载配置
        cli_config = load_cli_config()

        # 2. 实例化 Core，注入配置
        core_instance = DrcomCore(config=cli_config)

        # 3. 注册退出钩子
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
        # 捕获 DrcomCore.__init__ 抛出的配置错误
        logger.critical(f"启动失败: {config_err}")
        logger.critical(
            "请确保你的 .env 文件包含所有必要的键 (USERNAME, PASSWORD, HOST_IP, MAC, SERVER_IP)。"
        )
        sys.exit(1)
    except KeyboardInterrupt:
        logger.info("收到用户中断信号 (Ctrl+C)，准备退出...")
    except SystemExit as e:
        logger.info(f"程序因调用 sys.exit() 而退出: {e}")
    except Exception:
        logger.critical("主程序发生意外错误。", exc_info=True)
    finally:
        logger.info("Dr.COM 客户端已停止。")


# 程序入口
if __name__ == "__main__":
    main()
