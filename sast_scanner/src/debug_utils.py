"""
Debug utilities for SAST Scanner
Provides logging and debug functionality for the static analysis tool.
"""

import logging
import sys
import os
from datetime import datetime
from typing import Optional, Any
from pathlib import Path

# Global debug flag
DEBUG_MODE = False

def setup_debug_logging(debug: bool = False, log_file: Optional[str] = None) -> None:
    """Setup debug logging for the SAST scanner."""
    global DEBUG_MODE
    DEBUG_MODE = debug
    
    if not debug:
        return
    
    # Create logs directory if it doesn't exist
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)
    
    # Default log file if none specified
    if not log_file:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file = log_dir / f"sast_scanner_{timestamp}.log"
    
    # Configure logging
    logging.basicConfig(
        level=logging.DEBUG if debug else logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler(sys.stdout) if debug else logging.NullHandler()
        ]
    )
    
    # Log startup message
    debug_log("debug_utils", f"Debug logging initialized. Log file: {log_file}")

def debug_print(message: str, level: str = "INFO", module: str = "main") -> None:
    """Print debug message with formatting."""
    if not DEBUG_MODE:
        return
    
    timestamp = datetime.now().strftime("%H:%M:%S")
    level_colors = {
        "DEBUG": "\033[36m",    # Cyan
        "INFO": "\033[32m",     # Green
        "WARNING": "\033[33m",  # Yellow
        "ERROR": "\033[31m",    # Red
        "CRITICAL": "\033[35m"  # Magenta
    }
    
    color = level_colors.get(level, "\033[0m")
    reset = "\033[0m"
    
    print(f"{color}[{timestamp}] [{level}] [{module}] {message}{reset}")

def debug_log(module: str, message: str, level: str = "INFO", data: Optional[Any] = None) -> None:
    """Log debug message with optional data."""
    if not DEBUG_MODE:
        return
    
    logger = logging.getLogger(module)
    
    # Format message with data if provided
    if data is not None:
        if isinstance(data, (dict, list)):
            import json
            message = f"{message} | Data: {json.dumps(data, indent=2, default=str)}"
        else:
            message = f"{message} | Data: {data}"
    
    # Log based on level
    if level == "DEBUG":
        logger.debug(message)
    elif level == "INFO":
        logger.info(message)
    elif level == "WARNING":
        logger.warning(message)
    elif level == "ERROR":
        logger.error(message)
    elif level == "CRITICAL":
        logger.critical(message)
    
    # Also print to console in debug mode
    debug_print(message, level, module)

def get_debug_info() -> dict:
    """Get debug information about the current environment."""
    return {
        "debug_mode": DEBUG_MODE,
        "python_version": sys.version,
        "platform": sys.platform,
        "working_directory": os.getcwd(),
        "timestamp": datetime.now().isoformat()
    }

def debug_function_call(func_name: str, args: tuple = None, kwargs: dict = None) -> None:
    """Debug decorator helper for function calls."""
    if not DEBUG_MODE:
        return
    
    args_str = str(args) if args else "()"
    kwargs_str = str(kwargs) if kwargs else "{}"
    debug_print(f"Calling {func_name}{args_str} {kwargs_str}", "DEBUG", "function_call")

def debug_performance(start_time: datetime, operation: str, module: str = "main") -> None:
    """Debug performance timing."""
    if not DEBUG_MODE:
        return
    
    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()
    debug_print(f"{operation} completed in {duration:.3f} seconds", "DEBUG", module) 