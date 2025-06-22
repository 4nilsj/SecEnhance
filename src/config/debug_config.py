#!/usr/bin/env python3
"""
Debug Configuration and Logging Setup
Comprehensive debugging framework for the API Security Scanner
"""

import logging
import os
import sys
import traceback
import time
from datetime import datetime
from functools import wraps
import json
from typing import Any, Dict, List, Optional, Callable
import inspect

# Debug configuration
DEBUG_CONFIG = {
    'log_level': 'DEBUG',  # DEBUG, INFO, WARNING, ERROR, CRITICAL
    'log_file': 'logs/api_scanner.log',
    'max_log_size': 10 * 1024 * 1024,  # 10MB
    'backup_count': 5,
    'console_output': True,
    'file_output': True,
    'performance_tracking': True,
    'request_tracking': True,
    'error_tracking': True,
    'scan_tracking': True,
    'auth_tracking': True,
    'api_tracking': True
}

class DebugLogger:
    """Centralized logging and debugging system"""
    
    def __init__(self, name: str = 'api_scanner', config: Dict = None):
        self.name = name
        self.config = config or DEBUG_CONFIG
        self.logger = self._setup_logger()
        self.performance_data = {}
        self.request_data = {}
        self.error_data = {}
        
    def _setup_logger(self) -> logging.Logger:
        """Setup logger with file and console handlers"""
        # Create logs directory
        os.makedirs('logs', exist_ok=True)
        
        # Create logger
        logger = logging.getLogger(self.name)
        logger.setLevel(getattr(logging, self.config['log_level']))
        
        # Clear existing handlers
        logger.handlers.clear()
        
        # Create formatters
        detailed_formatter = logging.Formatter(
            '%(asctime)s | %(name)s | %(levelname)s | %(filename)s:%(lineno)d | %(funcName)s | %(message)s'
        )
        simple_formatter = logging.Formatter(
            '%(asctime)s | %(levelname)s | %(message)s'
        )
        
        # Console handler
        if self.config['console_output']:
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setLevel(logging.INFO)
            console_handler.setFormatter(simple_formatter)
            logger.addHandler(console_handler)
        
        # File handler with rotation
        if self.config['file_output']:
            from logging.handlers import RotatingFileHandler
            file_handler = RotatingFileHandler(
                self.config['log_file'],
                maxBytes=self.config['max_log_size'],
                backupCount=self.config['backup_count']
            )
            file_handler.setLevel(logging.DEBUG)
            file_handler.setFormatter(detailed_formatter)
            logger.addHandler(file_handler)
        
        return logger
    
    def debug(self, message: str, **kwargs):
        """Log debug message with additional context"""
        context = self._format_context(**kwargs)
        self.logger.debug(f"{message} {context}")
    
    def info(self, message: str, **kwargs):
        """Log info message with additional context"""
        context = self._format_context(**kwargs)
        self.logger.info(f"{message} {context}")
    
    def warning(self, message: str, **kwargs):
        """Log warning message with additional context"""
        context = self._format_context(**kwargs)
        self.logger.warning(f"{message} {context}")
    
    def error(self, message: str, exception: Exception = None, **kwargs):
        """Log error message with exception details"""
        context = self._format_context(**kwargs)
        if exception:
            error_details = f"\nException: {type(exception).__name__}: {str(exception)}"
            error_details += f"\nTraceback: {traceback.format_exc()}"
            self.logger.error(f"{message} {context}{error_details}")
        else:
            self.logger.error(f"{message} {context}")
    
    def critical(self, message: str, exception: Exception = None, **kwargs):
        """Log critical error message"""
        context = self._format_context(**kwargs)
        if exception:
            error_details = f"\nException: {type(exception).__name__}: {str(exception)}"
            error_details += f"\nTraceback: {traceback.format_exc()}"
            self.logger.critical(f"{message} {context}{error_details}")
        else:
            self.logger.critical(f"{message} {context}")
    
    def _format_context(self, **kwargs) -> str:
        """Format additional context for logging"""
        if not kwargs:
            return ""
        
        context_parts = []
        for key, value in kwargs.items():
            if isinstance(value, (dict, list)):
                context_parts.append(f"{key}={json.dumps(value, default=str)}")
            else:
                context_parts.append(f"{key}={value}")
        
        return f"[{', '.join(context_parts)}]"
    
    def track_performance(self, func_name: str, start_time: float, end_time: float, **kwargs):
        """Track function performance"""
        if not self.config['performance_tracking']:
            return
        
        duration = end_time - start_time
        self.performance_data[func_name] = {
            'duration': duration,
            'start_time': start_time,
            'end_time': end_time,
            'context': kwargs
        }
        
        self.debug(f"Performance: {func_name} took {duration:.4f}s", 
                  duration=duration, **kwargs)
    
    def track_request(self, method: str, url: str, status_code: int, 
                     duration: float, **kwargs):
        """Track HTTP request details"""
        if not self.config['request_tracking']:
            return
        
        request_id = f"req_{int(time.time() * 1000)}"
        self.request_data[request_id] = {
            'method': method,
            'url': url,
            'status_code': status_code,
            'duration': duration,
            'timestamp': datetime.now().isoformat(),
            'context': kwargs
        }
        
        self.debug(f"Request: {method} {url} -> {status_code} ({duration:.4f}s)",
                  request_id=request_id, **kwargs)
    
    def track_error(self, error_type: str, error_message: str, 
                   context: Dict = None, **kwargs):
        """Track error occurrences"""
        if not self.config['error_tracking']:
            return
        
        error_id = f"err_{int(time.time() * 1000)}"
        self.error_data[error_id] = {
            'type': error_type,
            'message': error_message,
            'context': context or {},
            'timestamp': datetime.now().isoformat(),
            'traceback': traceback.format_exc()
        }
        
        self.error(f"Error tracked: {error_type} - {error_message}",
                  error_id=error_id, context=context, **kwargs)
    
    def track_scan(self, scan_id: str, scan_type: str, status: str, **kwargs):
        """Track scan operations"""
        if not self.config['scan_tracking']:
            return
        
        self.info(f"Scan {scan_id}: {scan_type} -> {status}",
                 scan_id=scan_id, scan_type=scan_type, status=status, **kwargs)
    
    def track_auth(self, auth_type: str, success: bool, **kwargs):
        """Track authentication attempts"""
        if not self.config['auth_tracking']:
            return
        
        status = "SUCCESS" if success else "FAILED"
        self.info(f"Auth {auth_type}: {status}", 
                 auth_type=auth_type, success=success, **kwargs)
    
    def track_api(self, endpoint: str, method: str, status_code: int, **kwargs):
        """Track API endpoint calls"""
        if not self.config['api_tracking']:
            return
        
        self.debug(f"API {method} {endpoint} -> {status_code}",
                  endpoint=endpoint, method=method, status_code=status_code, **kwargs)
    
    def get_performance_summary(self) -> Dict:
        """Get performance summary"""
        if not self.performance_data:
            return {}
        
        summary = {}
        for func_name, data in self.performance_data.items():
            if func_name not in summary:
                summary[func_name] = {
                    'count': 0,
                    'total_duration': 0,
                    'avg_duration': 0,
                    'min_duration': float('inf'),
                    'max_duration': 0
                }
            
            summary[func_name]['count'] += 1
            summary[func_name]['total_duration'] += data['duration']
            summary[func_name]['min_duration'] = min(
                summary[func_name]['min_duration'], data['duration']
            )
            summary[func_name]['max_duration'] = max(
                summary[func_name]['max_duration'], data['duration']
            )
        
        # Calculate averages
        for func_name in summary:
            summary[func_name]['avg_duration'] = (
                summary[func_name]['total_duration'] / summary[func_name]['count']
            )
            if summary[func_name]['min_duration'] == float('inf'):
                summary[func_name]['min_duration'] = 0
        
        return summary
    
    def export_debug_data(self, filename: str = None) -> str:
        """Export all debug data to JSON file"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"logs/debug_export_{timestamp}.json"
        
        debug_data = {
            'timestamp': datetime.now().isoformat(),
            'performance_data': self.performance_data,
            'performance_summary': self.get_performance_summary(),
            'request_data': self.request_data,
            'error_data': self.error_data,
            'config': self.config
        }
        
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        with open(filename, 'w') as f:
            json.dump(debug_data, f, indent=2, default=str)
        
        self.info(f"Debug data exported to {filename}")
        return filename

# Global debug logger instance
debug_logger = DebugLogger()

def debug_decorator(func: Callable) -> Callable:
    """Decorator to add debugging to functions"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        start_time = time.time()
        func_name = f"{func.__module__}.{func.__name__}"
        
        try:
            debug_logger.debug(f"Entering {func_name}", 
                             args_count=len(args), kwargs_count=len(kwargs))
            
            result = func(*args, **kwargs)
            
            end_time = time.time()
            debug_logger.track_performance(func_name, start_time, end_time)
            debug_logger.debug(f"Exiting {func_name} successfully")
            
            return result
            
        except Exception as e:
            end_time = time.time()
            debug_logger.track_performance(func_name, start_time, end_time)
            debug_logger.track_error(type(e).__name__, str(e), 
                                   func_name=func_name)
            debug_logger.error(f"Error in {func_name}", exception=e)
            raise
    
    return wrapper

def debug_class(cls: type) -> type:
    """Class decorator to add debugging to all methods"""
    for name, method in inspect.getmembers(cls, inspect.isfunction):
        if not name.startswith('_'):
            setattr(cls, name, debug_decorator(method))
    return cls

def debug_method(func: Callable) -> Callable:
    """Method decorator for class methods"""
    @wraps(func)
    def wrapper(self, *args, **kwargs):
        start_time = time.time()
        func_name = f"{self.__class__.__name__}.{func.__name__}"
        
        try:
            debug_logger.debug(f"Entering {func_name}", 
                             args_count=len(args), kwargs_count=len(kwargs))
            
            result = func(self, *args, **kwargs)
            
            end_time = time.time()
            debug_logger.track_performance(func_name, start_time, end_time)
            debug_logger.debug(f"Exiting {func_name} successfully")
            
            return result
            
        except Exception as e:
            end_time = time.time()
            debug_logger.track_performance(func_name, start_time, end_time)
            debug_logger.track_error(type(e).__name__, str(e), 
                                   func_name=func_name)
            debug_logger.error(f"Error in {func_name}", exception=e)
            raise
    
    return wrapper

class DebugContext:
    """Context manager for debugging specific operations"""
    
    def __init__(self, operation_name: str, **context):
        self.operation_name = operation_name
        self.context = context
        self.start_time = None
    
    def __enter__(self):
        self.start_time = time.time()
        debug_logger.debug(f"Starting {self.operation_name}", **self.context)
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        end_time = time.time()
        duration = end_time - self.start_time
        
        if exc_type:
            debug_logger.error(f"Error in {self.operation_name}", 
                             exception=exc_val, duration=duration, **self.context)
        else:
            debug_logger.debug(f"Completed {self.operation_name}", 
                             duration=duration, **self.context)

def debug_config(config: Dict) -> None:
    """Update debug configuration"""
    global DEBUG_CONFIG
    DEBUG_CONFIG.update(config)
    debug_logger.config = DEBUG_CONFIG
    debug_logger.logger = debug_logger._setup_logger()
    debug_logger.info("Debug configuration updated", config=config)

def get_debug_stats() -> Dict:
    """Get current debugging statistics"""
    return {
        'performance_summary': debug_logger.get_performance_summary(),
        'request_count': len(debug_logger.request_data),
        'error_count': len(debug_logger.error_data),
        'config': debug_logger.config
    }

# Convenience functions
def debug_log(message: str, **kwargs):
    """Quick debug logging"""
    debug_logger.debug(message, **kwargs)

def info_log(message: str, **kwargs):
    """Quick info logging"""
    debug_logger.info(message, **kwargs)

def error_log(message: str, exception: Exception = None, **kwargs):
    """Quick error logging"""
    debug_logger.error(message, exception=exception, **kwargs)

def track_request(method: str, url: str, status_code: int, duration: float, **kwargs):
    """Quick request tracking"""
    debug_logger.track_request(method, url, status_code, duration, **kwargs)

def track_scan(scan_id: str, scan_type: str, status: str, **kwargs):
    """Quick scan tracking"""
    debug_logger.track_scan(scan_id, scan_type, status, **kwargs)

def track_auth(auth_type: str, success: bool, **kwargs):
    """Quick auth tracking"""
    debug_logger.track_auth(auth_type, success, **kwargs)

def track_api(endpoint: str, method: str, status_code: int, **kwargs):
    """Quick API tracking"""
    debug_logger.track_api(endpoint, method, status_code, **kwargs) 