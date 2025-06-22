#!/usr/bin/env python3
"""
Error Handling System for API Security Scanner
Categorizes and handles different types of scanning issues
"""

import requests
import socket
import os
import sys
from typing import Dict, List, Optional, Any, Tuple
from enum import Enum
from datetime import datetime

class ErrorSeverity(Enum):
    """Error severity levels"""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"
    FATAL = "fatal"

class ErrorCategory(Enum):
    """Error categories"""
    NETWORK = "network"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    CONFIGURATION = "configuration"
    INFRASTRUCTURE = "infrastructure"
    SECURITY = "security"
    RESOURCE = "resource"
    DATA = "data"
    UNKNOWN = "unknown"

class ScanError:
    """Represents a scan error with metadata"""
    
    def __init__(self, message: str, category: ErrorCategory, severity: ErrorSeverity, 
                 error_code: str = None, details: Dict[str, Any] = None, 
                 should_fail_scan: bool = False):
        self.message = message
        self.category = category
        self.severity = severity
        self.error_code = error_code
        self.details = details or {}
        self.should_fail_scan = should_fail_scan
        self.timestamp = datetime.now().isoformat()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert error to dictionary"""
        return {
            'message': self.message,
            'category': self.category.value,
            'severity': self.severity.value,
            'error_code': self.error_code,
            'details': self.details,
            'should_fail_scan': self.should_fail_scan,
            'timestamp': self.timestamp
        }

class ErrorHandler:
    """Handles and categorizes scanning errors"""
    
    def __init__(self):
        self.errors: List[ScanError] = []
        self.fatal_errors: List[ScanError] = []
    
    def handle_request_exception(self, exception: Exception, url: str, method: str) -> ScanError:
        """Handle requests library exceptions"""
        
        if isinstance(exception, requests.exceptions.ConnectionError):
            if "Name or service not known" in str(exception):
                return ScanError(
                    message=f"DNS resolution failed for {url}",
                    category=ErrorCategory.NETWORK,
                    severity=ErrorSeverity.ERROR,
                    error_code="DNS_RESOLUTION_FAILED",
                    details={'url': url, 'method': method},
                    should_fail_scan=False
                )
            elif "Connection refused" in str(exception):
                return ScanError(
                    message=f"Connection refused to {url}",
                    category=ErrorCategory.NETWORK,
                    severity=ErrorSeverity.WARNING,
                    error_code="CONNECTION_REFUSED",
                    details={'url': url, 'method': method},
                    should_fail_scan=False
                )
            else:
                return ScanError(
                    message=f"Network connection error: {str(exception)}",
                    category=ErrorCategory.NETWORK,
                    severity=ErrorSeverity.ERROR,
                    error_code="NETWORK_ERROR",
                    details={'url': url, 'method': method},
                    should_fail_scan=False
                )
        
        elif isinstance(exception, requests.exceptions.Timeout):
            return ScanError(
                message=f"Request timeout for {url}",
                category=ErrorCategory.NETWORK,
                severity=ErrorSeverity.WARNING,
                error_code="REQUEST_TIMEOUT",
                details={'url': url, 'method': method},
                should_fail_scan=False
            )
        
        elif isinstance(exception, requests.exceptions.SSLError):
            return ScanError(
                message=f"SSL/TLS error for {url}: {str(exception)}",
                category=ErrorCategory.SECURITY,
                severity=ErrorSeverity.ERROR,
                error_code="SSL_ERROR",
                details={'url': url, 'method': method},
                should_fail_scan=False
            )
        
        elif isinstance(exception, requests.exceptions.HTTPError):
            return ScanError(
                message=f"HTTP error {exception.response.status_code} for {url}",
                category=ErrorCategory.NETWORK,
                severity=ErrorSeverity.INFO,
                error_code="HTTP_ERROR",
                details={'url': url, 'method': method, 'status_code': exception.response.status_code},
                should_fail_scan=False
            )
        
        else:
            return ScanError(
                message=f"Unknown request error: {str(exception)}",
                category=ErrorCategory.UNKNOWN,
                severity=ErrorSeverity.ERROR,
                error_code="UNKNOWN_REQUEST_ERROR",
                details={'url': url, 'method': method},
                should_fail_scan=False
            )
    
    def handle_http_status_code(self, status_code: int, url: str, method: str) -> Optional[ScanError]:
        """Handle HTTP status codes"""
        
        if status_code == 401:
            return ScanError(
                message=f"Authentication required for {url}",
                category=ErrorCategory.AUTHENTICATION,
                severity=ErrorSeverity.WARNING,
                error_code="AUTHENTICATION_REQUIRED",
                details={'url': url, 'method': method, 'status_code': status_code},
                should_fail_scan=False
            )
        
        elif status_code == 403:
            return ScanError(
                message=f"Access forbidden for {url}",
                category=ErrorCategory.AUTHORIZATION,
                severity=ErrorSeverity.WARNING,
                error_code="ACCESS_FORBIDDEN",
                details={'url': url, 'method': method, 'status_code': status_code},
                should_fail_scan=False
            )
        
        elif status_code == 404:
            return ScanError(
                message=f"Endpoint not found: {url}",
                category=ErrorCategory.CONFIGURATION,
                severity=ErrorSeverity.INFO,
                error_code="ENDPOINT_NOT_FOUND",
                details={'url': url, 'method': method, 'status_code': status_code},
                should_fail_scan=False
            )
        
        elif status_code == 405:
            return ScanError(
                message=f"Method {method} not allowed for {url}",
                category=ErrorCategory.CONFIGURATION,
                severity=ErrorSeverity.INFO,
                error_code="METHOD_NOT_ALLOWED",
                details={'url': url, 'method': method, 'status_code': status_code},
                should_fail_scan=False
            )
        
        elif status_code == 429:
            return ScanError(
                message=f"Rate limited for {url}",
                category=ErrorCategory.SECURITY,
                severity=ErrorSeverity.WARNING,
                error_code="RATE_LIMITED",
                details={'url': url, 'method': method, 'status_code': status_code},
                should_fail_scan=False
            )
        
        elif status_code >= 500:
            return ScanError(
                message=f"Server error {status_code} for {url}",
                category=ErrorCategory.INFRASTRUCTURE,
                severity=ErrorSeverity.ERROR,
                error_code="SERVER_ERROR",
                details={'url': url, 'method': method, 'status_code': status_code},
                should_fail_scan=False
            )
        
        return None
    
    def check_infrastructure_issues(self) -> List[ScanError]:
        """Check for infrastructure issues that should fail the scan"""
        errors = []
        
        # Check internet connectivity
        try:
            socket.create_connection(("8.8.8.8", 53), timeout=5)
        except OSError:
            errors.append(ScanError(
                message="No internet connectivity detected",
                category=ErrorCategory.INFRASTRUCTURE,
                severity=ErrorSeverity.FATAL,
                error_code="NO_INTERNET",
                should_fail_scan=True
            ))
        
        # Check disk space
        try:
            statvfs = os.statvfs('.')
            free_space = statvfs.f_frsize * statvfs.f_bavail
            if free_space < 100 * 1024 * 1024:  # Less than 100MB
                errors.append(ScanError(
                    message="Insufficient disk space for scan results",
                    category=ErrorCategory.RESOURCE,
                    severity=ErrorSeverity.FATAL,
                    error_code="INSUFFICIENT_DISK_SPACE",
                    details={'free_space_mb': free_space / (1024 * 1024)},
                    should_fail_scan=True
                ))
        except Exception:
            pass
        
        # Check write permissions
        try:
            test_file = "test_write_permission.tmp"
            with open(test_file, 'w') as f:
                f.write("test")
            os.remove(test_file)
        except (OSError, PermissionError):
            errors.append(ScanError(
                message="No write permission in current directory",
                category=ErrorCategory.RESOURCE,
                severity=ErrorSeverity.FATAL,
                error_code="NO_WRITE_PERMISSION",
                should_fail_scan=True
            ))
        
        return errors
    
    def validate_configuration(self, config: Dict[str, Any]) -> List[ScanError]:
        """Validate scanner configuration"""
        errors = []
        
        # Check base URL format
        base_url = config.get('base_url')
        if base_url:
            if not base_url.startswith(('http://', 'https://')):
                errors.append(ScanError(
                    message=f"Invalid base URL format: {base_url}",
                    category=ErrorCategory.CONFIGURATION,
                    severity=ErrorSeverity.FATAL,
                    error_code="INVALID_BASE_URL",
                    details={'base_url': base_url},
                    should_fail_scan=True
                ))
        
        # Check authentication configuration
        auth_config = config.get('auth_config', {})
        if auth_config:
            auth_type = auth_config.get('type')
            if auth_type == 'bearer' and not auth_config.get('token'):
                errors.append(ScanError(
                    message="Bearer token authentication configured but no token provided",
                    category=ErrorCategory.AUTHENTICATION,
                    severity=ErrorSeverity.FATAL,
                    error_code="MISSING_BEARER_TOKEN",
                    should_fail_scan=True
                ))
            elif auth_type == 'apikey' and not auth_config.get('value'):
                errors.append(ScanError(
                    message="API key authentication configured but no key value provided",
                    category=ErrorCategory.AUTHENTICATION,
                    severity=ErrorSeverity.FATAL,
                    error_code="MISSING_API_KEY",
                    should_fail_scan=True
                ))
            elif auth_type == 'basic' and (not auth_config.get('username') or not auth_config.get('password')):
                errors.append(ScanError(
                    message="Basic authentication configured but username or password missing",
                    category=ErrorCategory.AUTHENTICATION,
                    severity=ErrorSeverity.FATAL,
                    error_code="MISSING_BASIC_CREDENTIALS",
                    should_fail_scan=True
                ))
        
        return errors
    
    def add_error(self, error: ScanError):
        """Add an error to the handler"""
        self.errors.append(error)
        if error.should_fail_scan:
            self.fatal_errors.append(error)
    
    def has_fatal_errors(self) -> bool:
        """Check if there are any fatal errors"""
        return len(self.fatal_errors) > 0
    
    def get_fatal_errors(self) -> List[ScanError]:
        """Get all fatal errors"""
        return self.fatal_errors
    
    def get_errors_by_category(self, category: ErrorCategory) -> List[ScanError]:
        """Get errors by category"""
        return [error for error in self.errors if error.category == category]
    
    def get_errors_by_severity(self, severity: ErrorSeverity) -> List[ScanError]:
        """Get errors by severity"""
        return [error for error in self.errors if error.severity == severity]
    
    def clear_errors(self):
        """Clear all errors"""
        self.errors.clear()
        self.fatal_errors.clear()
    
    def get_error_summary(self) -> Dict[str, Any]:
        """Get error summary"""
        return {
            'total_errors': len(self.errors),
            'fatal_errors': len(self.fatal_errors),
            'errors_by_category': {
                category.value: len(self.get_errors_by_category(category))
                for category in ErrorCategory
            },
            'errors_by_severity': {
                severity.value: len(self.get_errors_by_severity(severity))
                for severity in ErrorSeverity
            },
            'fatal_error_messages': [error.message for error in self.fatal_errors]
        }
    
    def should_continue_scan(self) -> Tuple[bool, str]:
        """Determine if scan should continue and provide reason"""
        if self.has_fatal_errors():
            fatal_messages = [error.message for error in self.fatal_errors]
            return False, f"Scan cannot continue due to fatal errors: {'; '.join(fatal_messages)}"
        
        return True, "Scan can continue" 