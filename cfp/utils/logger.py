"""
Centralized logging configuration for CFP.

Provides structured logging with color output and separate loggers
for different subsystems (DAG, State, Prover, Intent, Storage).
"""

import logging
import sys
from pathlib import Path
from typing import Optional

import colorlog


class CFPLogger:
    """Centralized logger for CFP components"""

    _initialized = False
    _log_dir: Optional[Path] = None

    @classmethod
    def setup(
        cls,
        level: int = logging.INFO,
        log_dir: Optional[str] = None,
        log_to_file: bool = True,
    ):
        """
        Setup logging configuration.

        Args:
            level: Logging level (DEBUG, INFO, WARNING, ERROR)
            log_dir: Directory for log files. If None, uses ./logs
            log_to_file: Whether to write logs to file
        """
        if cls._initialized:
            return

        # Create log directory
        if log_to_file:
            cls._log_dir = Path(log_dir) if log_dir else Path("logs")
            cls._log_dir.mkdir(exist_ok=True)

        # Configure root logger
        root_logger = logging.getLogger("cfp")
        root_logger.setLevel(level)
        root_logger.handlers.clear()

        # Console handler with colors
        console_handler = colorlog.StreamHandler(sys.stdout)
        console_handler.setLevel(level)
        console_formatter = colorlog.ColoredFormatter(
            "%(log_color)s%(asctime)s [%(name)s] %(levelname)-8s%(reset)s %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
            log_colors={
                "DEBUG": "cyan",
                "INFO": "green",
                "WARNING": "yellow",
                "ERROR": "red",
                "CRITICAL": "red,bg_white",
            },
        )
        console_handler.setFormatter(console_formatter)
        root_logger.addHandler(console_handler)

        # File handler (if enabled)
        if log_to_file and cls._log_dir:
            file_handler = logging.FileHandler(cls._log_dir / "cfp.log")
            file_handler.setLevel(level)
            file_formatter = logging.Formatter(
                "%(asctime)s [%(name)s] %(levelname)-8s %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
            file_handler.setFormatter(file_formatter)
            root_logger.addHandler(file_handler)

        cls._initialized = True

    @classmethod
    def get_logger(cls, name: str) -> logging.Logger:
        """
        Get a logger for a specific subsystem.

        Args:
            name: Subsystem name (e.g., 'dag', 'state', 'prover')

        Returns:
            Logger instance
        """
        if not cls._initialized:
            cls.setup()

        return logging.getLogger(f"cfp.{name}")


# Convenience functions
def get_logger(name: str) -> logging.Logger:
    """Get a logger for a specific subsystem"""
    return CFPLogger.get_logger(name)


def setup_logging(level: int = logging.INFO, log_dir: Optional[str] = None):
    """Setup logging configuration"""
    CFPLogger.setup(level=level, log_dir=log_dir)
