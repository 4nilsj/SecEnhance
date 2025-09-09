"""
Centralized logging configuration for the API Security Scanner.
Provides structured logging with multiple levels and file output.
"""

import logging
import logging.handlers
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional


class ColoredFormatter(logging.Formatter):
    """Custom formatter with colors for console output."""
    
    # Color codes
    COLORS = {
        'DEBUG': '\033[36m',     # Cyan
        'INFO': '\033[32m',      # Green
        'WARNING': '\033[33m',   # Yellow
        'ERROR': '\033[31m',     # Red
        'CRITICAL': '\033[35m',  # Magenta
        'RESET': '\033[0m'       # Reset
    }
    
    def __init__(self, fmt=None, datefmt=None, suppress_output=False):
        super().__init__(fmt, datefmt)
        self.suppress_output = suppress_output
    
    def format(self, record):
        if self.suppress_output:
            return ""  # Return empty string to suppress output
        
        # Add color to the level name
        if record.levelname in self.COLORS:
            record.levelname = f"{self.COLORS[record.levelname]}{record.levelname}{self.COLORS['RESET']}"
        
        return super().format(record)


class NullFormatter(logging.Formatter):
    """Formatter that outputs nothing."""
    
    def format(self, record):
        return ""


class APISecurityLogger:
    """Centralized logger for the API Security Scanner."""
    
    def __init__(self, name: str = "api_security_scanner", log_dir: str = "logs", enable_console: bool = False):
        self.name = name
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(exist_ok=True)
        
        # Create logger
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.DEBUG)  # Set to lowest level, handlers will filter
        
        # Clear any existing handlers
        self.logger.handlers.clear()
        
        # Setup handlers
        if enable_console:
            self._setup_console_handler()
        else:
            self.console_handler = None
        self._setup_file_handler()
        self._setup_error_handler()
    
    def _setup_console_handler(self, suppress_output=False):
        """Setup console handler with colored output."""
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)  # Default to INFO level
        
        # Create formatter based on whether output should be suppressed
        if suppress_output:
            console_format = NullFormatter()
        else:
            console_format = ColoredFormatter(
                '%(asctime)s | %(levelname)-8s | %(name)s | %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
        console_handler.setFormatter(console_format)
        
        self.logger.addHandler(console_handler)
        self.console_handler = console_handler
    
    def _setup_file_handler(self):
        """Setup file handler for all logs."""
        log_file = self.log_dir / "scan_logs.log"
        
        # Use RotatingFileHandler to prevent huge log files
        file_handler = logging.handlers.RotatingFileHandler(
            log_file, maxBytes=10*1024*1024, backupCount=5  # 10MB per file, keep 5 backups
        )
        file_handler.setLevel(logging.DEBUG)
        
        # Create detailed formatter for file
        file_format = logging.Formatter(
            '%(asctime)s | %(levelname)-8s | %(name)s | %(funcName)s:%(lineno)d | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(file_format)
        
        self.logger.addHandler(file_handler)
        self.file_handler = file_handler
    
    def _setup_error_handler(self):
        """Setup separate handler for errors and critical messages."""
        error_file = self.log_dir / "error_logs.log"
        
        error_handler = logging.handlers.RotatingFileHandler(
            error_file, maxBytes=5*1024*1024, backupCount=3  # 5MB per file, keep 3 backups
        )
        error_handler.setLevel(logging.ERROR)
        
        error_format = logging.Formatter(
            '%(asctime)s | %(levelname)-8s | %(name)s | %(funcName)s:%(lineno)d | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        error_handler.setFormatter(error_format)
        
        self.logger.addHandler(error_handler)
        self.error_handler = error_handler
    
    def set_verbosity(self, verbose: int = 0):
        """Set logging verbosity based on -v flags.
        
        Args:
            verbose: Number of -v flags (0=WARNING, 1=INFO, 2=DEBUG)
        """
        if verbose == 0:
            # No console output for non-verbose mode
            if self.console_handler:
                # Remove existing console handler
                if self.console_handler in self.logger.handlers:
                    self.logger.removeHandler(self.console_handler)
                # Create new console handler with suppressed output
                self._setup_console_handler(suppress_output=True)
        elif verbose >= 1:
            # Enable console output for verbose mode
            if self.console_handler:
                # Remove existing console handler
                if self.console_handler in self.logger.handlers:
                    self.logger.removeHandler(self.console_handler)
            # Create new console handler with normal output
            self._setup_console_handler(suppress_output=False)
            
            if verbose == 1:
                level = logging.INFO
            else:  # verbose >= 2
                level = logging.DEBUG
            
            self.console_handler.setLevel(level)
            
            # Only log the level change if verbose mode is enabled
            self.logger.info(f"Logging level set to {logging.getLevelName(level)}")
    
    def get_logger(self) -> logging.Logger:
        """Get the configured logger instance."""
        return self.logger
    
    def log_scan_start(self, scan_id: str, target: str):
        """Log the start of a scan."""
        self.logger.info(f"Starting scan {scan_id} for target: {target}")
    
    def log_scan_end(self, scan_id: str, duration: float, status: str):
        """Log the end of a scan."""
        self.logger.info(f"Completed scan {scan_id} in {duration:.2f}s with status: {status}")
    
    def log_performance(self, phase: str, duration: float, details: Optional[str] = None):
        """Log performance metrics for a scan phase."""
        message = f"Performance | {phase}: {duration:.2f}s"
        if details:
            message += f" | {details}"
        self.logger.info(message)
    
    def log_error(self, error: Exception, context: Optional[str] = None):
        """Log an error with context."""
        message = f"Error: {type(error).__name__}: {str(error)}"
        if context:
            message = f"{context} | {message}"
        self.logger.error(message, exc_info=True)
    
    def log_plugin_result(self, plugin_name: str, result: str, details: Optional[str] = None):
        """Log plugin execution results."""
        message = f"Plugin {plugin_name}: {result}"
        if details:
            message += f" | {details}"
        self.logger.info(message)


# Global logger instance
_logger_instance: Optional[APISecurityLogger] = None


def get_logger(name: str = "api_security_scanner") -> logging.Logger:
    """Get a logger instance. Creates global instance if not exists."""
    global _logger_instance
    
    if _logger_instance is None:
        _logger_instance = APISecurityLogger(name)
    
    return _logger_instance.get_logger()


def setup_logging(verbose: Optional[int] = None, log_dir: Optional[str] = None) -> APISecurityLogger:
    """Setup and configure logging for the application.
    
    Args:
        verbose: Verbosity level (0=WARNING, 1=INFO, 2=DEBUG). If None, uses config.
        log_dir: Directory to store log files. If None, uses config.
        
    Returns:
        Configured APISecurityLogger instance
    """
    global _logger_instance
    
    # Import here to avoid circular imports
    try:
        from ..core.config import get_config
        config = get_config()
        
        # Use provided values or fall back to configuration
        if log_dir is None:
            log_dir = config.logging.log_dir
        if verbose is None:
            # Convert log level to verbose level
            level_map = {
                'DEBUG': 2,
                'INFO': 1,
                'WARNING': 0,
                'ERROR': 0,
                'CRITICAL': 0
            }
            verbose = level_map.get(config.logging.level, 1)
    except ImportError:
        # Fallback if config is not available
        log_dir = log_dir or "logs"
        verbose = verbose or 1
    
    # Enable console only if verbose mode is enabled
    enable_console = verbose > 0
    _logger_instance = APISecurityLogger(log_dir=log_dir, enable_console=enable_console)
    _logger_instance.set_verbosity(verbose)
    
    return _logger_instance


def log_exception(logger: logging.Logger, exception: Exception, context: str = ""):
    """Helper function to log exceptions with proper formatting."""
    logger.error(f"{context}: {type(exception).__name__}: {str(exception)}", exc_info=True)


def log_performance_metric(logger: logging.Logger, metric_name: str, value: float, unit: str = "s"):
    """Helper function to log performance metrics."""
    logger.info(f"PERF | {metric_name}: {value:.3f}{unit}")


# Context manager for timing operations
class LoggedTimer:
    """Context manager for timing operations with automatic logging."""
    
    def __init__(self, logger: logging.Logger, operation_name: str):
        self.logger = logger
        self.operation_name = operation_name
        self.start_time = None
    
    def __enter__(self):
        self.start_time = datetime.now()
        self.logger.debug(f"Starting {self.operation_name}")
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.start_time:
            duration = (datetime.now() - self.start_time).total_seconds()
            if exc_type is None:
                self.logger.info(f"Completed {self.operation_name} in {duration:.2f}s")
            else:
                self.logger.error(f"Failed {self.operation_name} after {duration:.2f}s: {exc_val}")
            log_performance_metric(self.logger, self.operation_name, duration)
