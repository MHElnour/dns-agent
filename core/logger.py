"""
Centralized logging configuration for DNS Agent
"""
from loguru import logger
from pathlib import Path
import sys
from core.platform_utils import get_data_dir


def setup_logger(log_dir=None, console_level="INFO", file_level="DEBUG"):
    """
    Configure loguru logger with both console and file output

    Args:
        log_dir: Directory to store log files (None = use platform-specific data dir)
        console_level: Logging level for console output (INFO, DEBUG, etc.)
        file_level: Logging level for file output
    """
    # Remove default logger
    logger.remove()

    # Use platform-specific data directory if not specified
    if log_dir is None:
        log_path = get_data_dir()
    else:
        log_path = Path(log_dir)

    # Ensure log directory exists
    log_path.mkdir(parents=True, exist_ok=True)

    # Console output (colorized and formatted)
    logger.add(
        sink=sys.stdout,
        format="<green>{time:HH:mm:ss}</green> | <level>{level: <8}</level> | <level>{message}</level>",
        colorize=True,
        level=console_level
    )

    # File output for DNS queries (detailed logs with rotation)
    logger.add(
        sink=log_path / "dns_queries.log",
        format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {message}",
        rotation="10 MB",  # Rotate when file reaches 10MB
        retention="7 days",  # Keep logs for 7 days
        compression="zip",  # Compress rotated logs
        level=file_level,
        enqueue=True  # Thread-safe logging
    )

    # Separate file for errors only
    logger.add(
        sink=log_path / "errors.log",
        format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {message}\n{exception}",
        rotation="5 MB",
        retention="30 days",  # Keep error logs longer
        compression="zip",
        level="ERROR",
        enqueue=True
    )

    logger.info("Logger initialized")
    return logger


def get_logger():
    """Get the configured logger instance"""
    return logger
