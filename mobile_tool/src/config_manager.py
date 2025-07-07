#!/usr/bin/env python3
"""
Configuration Manager for Mobile Security Testing Tool
Handles configuration loading from multiple sources with priority order.
"""

import os
import json
import logging
from pathlib import Path
from typing import Dict, Any, Optional
from .utils.debug_utils import debug_print

class ConfigManager:
    """Configuration manager for mobile security testing."""
    
    def __init__(self, config_file: str = None):
        """Initialize configuration manager."""
        self.config_file = config_file
        self.config = {}
        self._load_config()
    
    def _load_config(self):
        """Load configuration from multiple sources with priority order."""
        # Priority order: CLI args > env vars > config file > defaults
        
        # 1. Load default configuration
        self.config = self._get_default_config()
        
        # 2. Load from config file
        if self.config_file and os.path.exists(self.config_file):
            self._load_from_file(self.config_file)
        else:
            # Try to load from default locations
            default_config_paths = [
                "config/default_config.json",
                "mobile_config.json",
                "config/mobile_config.json"
            ]
            
            for config_path in default_config_paths:
                if os.path.exists(config_path):
                    self._load_from_file(config_path)
                    break
        
        # 3. Load from environment variables
        self._load_from_env()
        
        debug_print("Configuration loaded:", self.config)
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default configuration."""
        return {
            "api": {
                "host": "0.0.0.0",
                "port": 5001,
                "debug": False,
                "max_file_size": 100 * 1024 * 1024,  # 100MB
                "allowed_extensions": [".apk", ".ipa", ".aab"]
            },
            "analysis": {
                "default_tests": ["static", "network", "storage", "code"],
                "comprehensive_tests": ["static", "dynamic", "network", "storage", "code"],
                "timeout": 300,  # 5 minutes
                "max_concurrent_scans": 5
            },
            "reports": {
                "default_format": "html",
                "output_directory": "reports",
                "include_proof": True,
                "include_reproduction": True,
                "template_path": "templates/mobile_report_template.html"
            },
            "logging": {
                "level": "INFO",
                "file": "mobile_security.log",
                "max_size": 10 * 1024 * 1024,  # 10MB
                "backup_count": 5
            },
            "security": {
                "enable_rate_limiting": True,
                "max_requests_per_minute": 60,
                "allowed_origins": ["*"],
                "enable_cors": True
            },
            "tools": {
                "jadx_path": "jadx",
                "apktool_path": "apktool",
                "androguard_path": "androguard",
                "mobsf_path": "mobsf"
            }
        }
    
    def _load_from_file(self, config_file: str):
        """Load configuration from JSON file."""
        try:
            with open(config_file, 'r') as f:
                file_config = json.load(f)
            
            # Merge configuration
            self._merge_config(self.config, file_config)
            debug_print(f"Configuration loaded from file: {config_file}")
            
        except Exception as e:
            debug_print(f"Error loading config file {config_file}: {str(e)}")
    
    def _load_from_env(self):
        """Load configuration from environment variables."""
        env_mappings = {
            "MOBILE_API_HOST": ("api", "host"),
            "MOBILE_API_PORT": ("api", "port"),
            "MOBILE_API_DEBUG": ("api", "debug"),
            "MOBILE_MAX_FILE_SIZE": ("api", "max_file_size"),
            "MOBILE_DEFAULT_TESTS": ("analysis", "default_tests"),
            "MOBILE_TIMEOUT": ("analysis", "timeout"),
            "MOBILE_REPORT_FORMAT": ("reports", "default_format"),
            "MOBILE_LOG_LEVEL": ("logging", "level"),
            "MOBILE_LOG_FILE": ("logging", "file"),
            "MOBILE_RATE_LIMIT": ("security", "enable_rate_limiting"),
            "MOBILE_MAX_REQUESTS": ("security", "max_requests_per_minute"),
            "MOBILE_JADX_PATH": ("tools", "jadx_path"),
            "MOBILE_APKTOOL_PATH": ("tools", "apktool_path")
        }
        
        for env_var, config_path in env_mappings.items():
            value = os.getenv(env_var)
            if value is not None:
                # Convert value to appropriate type
                if env_var == "MOBILE_API_PORT":
                    value = int(value)
                elif env_var == "MOBILE_API_DEBUG":
                    value = value.lower() in ("true", "1", "yes")
                elif env_var == "MOBILE_MAX_FILE_SIZE":
                    value = int(value)
                elif env_var == "MOBILE_TIMEOUT":
                    value = int(value)
                elif env_var == "MOBILE_DEFAULT_TESTS":
                    value = value.split(",")
                elif env_var == "MOBILE_RATE_LIMIT":
                    value = value.lower() in ("true", "1", "yes")
                elif env_var == "MOBILE_MAX_REQUESTS":
                    value = int(value)
                
                # Set nested config value
                self._set_nested_config(self.config, config_path, value)
        
        debug_print("Configuration loaded from environment variables")
    
    def _merge_config(self, base: Dict[str, Any], update: Dict[str, Any]):
        """Recursively merge configuration dictionaries."""
        for key, value in update.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._merge_config(base[key], value)
            else:
                base[key] = value
    
    def _set_nested_config(self, config: Dict[str, Any], path: tuple, value: Any):
        """Set nested configuration value."""
        current = config
        for key in path[:-1]:
            if key not in current:
                current[key] = {}
            current = current[key]
        current[path[-1]] = value
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value using dot notation."""
        keys = key.split('.')
        value = self.config
        
        try:
            for k in keys:
                value = value[k]
            return value
        except (KeyError, TypeError):
            return default
    
    def set(self, key: str, value: Any):
        """Set configuration value using dot notation."""
        keys = key.split('.')
        current = self.config
        
        for k in keys[:-1]:
            if k not in current:
                current[k] = {}
            current = current[k]
        
        current[keys[-1]] = value
    
    def save(self, config_file: str = None):
        """Save configuration to file."""
        if config_file is None:
            config_file = self.config_file or "config/mobile_config.json"
        
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(config_file), exist_ok=True)
        
        try:
            with open(config_file, 'w') as f:
                json.dump(self.config, f, indent=2)
            debug_print(f"Configuration saved to: {config_file}")
        except Exception as e:
            debug_print(f"Error saving configuration: {str(e)}")
    
    def get_api_config(self) -> Dict[str, Any]:
        """Get API-specific configuration."""
        return self.config.get("api", {})
    
    def get_analysis_config(self) -> Dict[str, Any]:
        """Get analysis-specific configuration."""
        return self.config.get("analysis", {})
    
    def get_reports_config(self) -> Dict[str, Any]:
        """Get reports-specific configuration."""
        return self.config.get("reports", {})
    
    def get_logging_config(self) -> Dict[str, Any]:
        """Get logging-specific configuration."""
        return self.config.get("logging", {})
    
    def get_security_config(self) -> Dict[str, Any]:
        """Get security-specific configuration."""
        return self.config.get("security", {})
    
    def get_tools_config(self) -> Dict[str, Any]:
        """Get tools-specific configuration."""
        return self.config.get("tools", {})
    
    def validate(self) -> bool:
        """Validate configuration."""
        required_sections = ["api", "analysis", "reports", "logging", "security", "tools"]
        
        for section in required_sections:
            if section not in self.config:
                debug_print(f"Missing required configuration section: {section}")
                return False
        
        # Validate specific values
        if not isinstance(self.get("api.port"), int):
            debug_print("API port must be an integer")
            return False
        
        if not isinstance(self.get("analysis.timeout"), int):
            debug_print("Analysis timeout must be an integer")
            return False
        
        return True 