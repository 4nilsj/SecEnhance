"""
Logging utility for API Security Scanner
"""

import logging
import logging.handlers
import os
from datetime import datetime
from pathlib import Path


def setup_logging(verbose=False, log_file=None, max_size=10*1024*1024, backup_count=5):
    """
    Setup logging configuration for the application.
    
    Args:
        verbose (bool): Enable verbose logging
        log_file (str): Path to log file
        max_size (int): Maximum size of log file in bytes
        backup_count (int): Number of backup files to keep
    """
    # Resolve log file path to absolute path if it's relative
    if log_file:
        log_path = Path(log_file)
        if not log_path.is_absolute():
            # Assume relative to project root (3 levels up from src/utils/)
            project_root = Path(__file__).parent.parent.parent
            log_path = project_root / log_file
        
        # Create logs directory if it doesn't exist
        log_dir = log_path.parent
        if log_dir and not log_dir.exists():
            log_dir.mkdir(parents=True, exist_ok=True)
        
        log_file = str(log_path)
    
    # Set log level
    level = logging.DEBUG if verbose else logging.INFO
    
    # Configure root logger
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Get root logger
    logger = logging.getLogger()
    
    # Clear existing handlers
    logger.handlers.clear()
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(level)
    console_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)
    
    # File handler (if log_file is specified)
    if log_file:
        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=max_size,
            backupCount=backup_count
        )
        file_handler.setLevel(logging.DEBUG)
        file_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
        )
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)
    
    return logger


def get_logger(name):
    """
    Get a logger instance with the specified name.
    
    Args:
        name (str): Logger name
        
    Returns:
        logging.Logger: Logger instance
    """
    return logging.getLogger(name)


class LoggerMixin:
    """Mixin class to add logging capabilities to any class."""
    
    @property
    def logger(self):
        """Get logger for this class."""
        return get_logger(self.__class__.__name__)


def resolve_log_path(relative_path: str) -> Path:
    """Resolve a relative log path to absolute path from project root"""
    project_root = Path(__file__).parent.parent.parent
    return project_root / relative_path 