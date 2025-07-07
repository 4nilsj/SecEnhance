#!/usr/bin/env python3
"""
Configuration Manager for Mobile Security Testing
Manages tool configuration and settings.
"""

import os
import json
import logging
from typing import Dict, List, Any, Optional
from pathlib import Path

class ConfigManager:
    """Manage configuration for mobile security testing tool."""
    
    def __init__(self, config_file: str = None):
        """Initialize configuration manager."""
        self.logger = logging.getLogger(__name__)
        self.config_file = config_file
        self.config = self._load_config()
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from file or use defaults."""
        config = self._get_default_config()
        
        if self.config_file and os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    file_config = json.load(f)
                    config.update(file_config)
                    self.logger.info(f"Loaded configuration from {self.config_file}")
            except Exception as e:
                self.logger.error(f"Error loading configuration file: {str(e)}")
        
        # Load from environment variables
        config = self._load_from_environment(config)
        
        return config
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default configuration."""
        return {
            "scanning": {
                "timeout": 300,
                "max_threads": 4,
                "enable_dynamic": True,
                "enable_network": True,
                "enable_storage": True,
                "enable_code": True
            },
            "reporting": {
                "format": ["html", "json"],
                "include_evidence": True,
                "risk_threshold": "medium",
                "output_directory": "reports"
            },
            "tools": {
                "apktool_path": "apktool",
                "jadx_path": "jadx",
                "dex2jar_path": "d2j-dex2jar",
                "aapt_path": "aapt"
            },
            "security": {
                "enable_exploitation": False,
                "enable_fuzzing": False,
                "max_fuzz_iterations": 100,
                "enable_brute_force": False
            },
            "logging": {
                "level": "INFO",
                "file": "mobile_security.log",
                "max_size": "10MB",
                "backup_count": 5
            },
            "network": {
                "proxy_host": None,
                "proxy_port": None,
                "proxy_username": None,
                "proxy_password": None,
                "timeout": 30,
                "verify_ssl": True
            },
            "storage": {
                "temp_directory": None,
                "cleanup_temp": True,
                "max_temp_size": "1GB"
            }
        }
    
    def _load_from_environment(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Load configuration from environment variables."""
        env_mappings = {
            "MOBILE_SCAN_TIMEOUT": ("scanning", "timeout", int),
            "MOBILE_SCAN_THREADS": ("scanning", "max_threads", int),
            "MOBILE_ENABLE_DYNAMIC": ("scanning", "enable_dynamic", bool),
            "MOBILE_ENABLE_NETWORK": ("scanning", "enable_network", bool),
            "MOBILE_ENABLE_STORAGE": ("scanning", "enable_storage", bool),
            "MOBILE_ENABLE_CODE": ("scanning", "enable_code", bool),
            "MOBILE_REPORT_FORMAT": ("reporting", "format", str),
            "MOBILE_RISK_THRESHOLD": ("reporting", "risk_threshold", str),
            "MOBILE_OUTPUT_DIR": ("reporting", "output_directory", str),
            "MOBILE_APKTOOL_PATH": ("tools", "apktool_path", str),
            "MOBILE_JADX_PATH": ("tools", "jadx_path", str),
            "MOBILE_DEX2JAR_PATH": ("tools", "dex2jar_path", str),
            "MOBILE_AAPT_PATH": ("tools", "aapt_path", str),
            "MOBILE_ENABLE_EXPLOITATION": ("security", "enable_exploitation", bool),
            "MOBILE_ENABLE_FUZZING": ("security", "enable_fuzzing", bool),
            "MOBILE_MAX_FUZZ_ITERATIONS": ("security", "max_fuzz_iterations", int),
            "MOBILE_ENABLE_BRUTE_FORCE": ("security", "enable_brute_force", bool),
            "MOBILE_LOG_LEVEL": ("logging", "level", str),
            "MOBILE_LOG_FILE": ("logging", "file", str),
            "MOBILE_PROXY_HOST": ("network", "proxy_host", str),
            "MOBILE_PROXY_PORT": ("network", "proxy_port", int),
            "MOBILE_PROXY_USERNAME": ("network", "proxy_username", str),
            "MOBILE_PROXY_PASSWORD": ("network", "proxy_password", str),
            "MOBILE_NETWORK_TIMEOUT": ("network", "timeout", int),
            "MOBILE_VERIFY_SSL": ("network", "verify_ssl", bool),
            "MOBILE_TEMP_DIR": ("storage", "temp_directory", str),
            "MOBILE_CLEANUP_TEMP": ("storage", "cleanup_temp", bool)
        }
        
        for env_var, (section, key, value_type) in env_mappings.items():
            env_value = os.environ.get(env_var)
            if env_value is not None:
                try:
                    if value_type == bool:
                        # Handle boolean values
                        if env_value.lower() in ('true', '1', 'yes', 'on'):
                            config[section][key] = True
                        elif env_value.lower() in ('false', '0', 'no', 'off'):
                            config[section][key] = False
                    elif value_type == int:
                        config[section][key] = int(env_value)
                    elif value_type == str:
                        if key == "format":
                            # Handle comma-separated formats
                            config[section][key] = [fmt.strip() for fmt in env_value.split(",")]
                        else:
                            config[section][key] = env_value
                except (ValueError, TypeError) as e:
                    self.logger.warning(f"Invalid environment variable {env_var}: {env_value} ({str(e)})")
        
        return config
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value using dot notation."""
        try:
            keys = key.split('.')
            value = self.config
            
            for k in keys:
                if isinstance(value, dict) and k in value:
                    value = value[k]
                else:
                    return default
            
            return value
        except Exception as e:
            self.logger.error(f"Error getting config value {key}: {str(e)}")
            return default
    
    def set(self, key: str, value: Any) -> bool:
        """Set configuration value using dot notation."""
        try:
            keys = key.split('.')
            config = self.config
            
            # Navigate to the parent of the target key
            for k in keys[:-1]:
                if k not in config:
                    config[k] = {}
                config = config[k]
            
            # Set the value
            config[keys[-1]] = value
            return True
        except Exception as e:
            self.logger.error(f"Error setting config value {key}: {str(e)}")
            return False
    
    def save_config(self, config_file: str = None) -> bool:
        """Save configuration to file."""
        try:
            if config_file is None:
                config_file = self.config_file
            
            if config_file is None:
                config_file = "config.json"
            
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(config_file), exist_ok=True)
            
            with open(config_file, 'w', encoding='utf-8') as f:
                json.dump(self.config, f, indent=2, ensure_ascii=False)
            
            self.logger.info(f"Configuration saved to {config_file}")
            return True
        except Exception as e:
            self.logger.error(f"Error saving configuration: {str(e)}")
            return False
    
    def get_scanning_config(self) -> Dict[str, Any]:
        """Get scanning configuration."""
        return self.config.get("scanning", {})
    
    def get_reporting_config(self) -> Dict[str, Any]:
        """Get reporting configuration."""
        return self.config.get("reporting", {})
    
    def get_tools_config(self) -> Dict[str, Any]:
        """Get tools configuration."""
        return self.config.get("tools", {})
    
    def get_security_config(self) -> Dict[str, Any]:
        """Get security configuration."""
        return self.config.get("security", {})
    
    def get_logging_config(self) -> Dict[str, Any]:
        """Get logging configuration."""
        return self.config.get("logging", {})
    
    def get_network_config(self) -> Dict[str, Any]:
        """Get network configuration."""
        return self.config.get("network", {})
    
    def get_storage_config(self) -> Dict[str, Any]:
        """Get storage configuration."""
        return self.config.get("storage", {})
    
    def validate_tools(self) -> Dict[str, bool]:
        """Validate that required tools are available."""
        tools_config = self.get_tools_config()
        validation = {}
        
        for tool_name, tool_path in tools_config.items():
            try:
                # Check if tool is available in PATH
                import subprocess
                result = subprocess.run([tool_path, "--version"], 
                                      capture_output=True, 
                                      text=True, 
                                      timeout=10)
                validation[tool_name] = result.returncode == 0
            except Exception:
                validation[tool_name] = False
        
        return validation
    
    def get_output_directory(self) -> str:
        """Get output directory, creating it if necessary."""
        output_dir = self.get("reporting.output_directory", "reports")
        
        if not os.path.exists(output_dir):
            try:
                os.makedirs(output_dir, exist_ok=True)
                self.logger.info(f"Created output directory: {output_dir}")
            except Exception as e:
                self.logger.error(f"Error creating output directory: {str(e)}")
                output_dir = "."
        
        return output_dir
    
    def get_temp_directory(self) -> str:
        """Get temporary directory."""
        temp_dir = self.get("storage.temp_directory")
        
        if temp_dir is None:
            import tempfile
            temp_dir = tempfile.mkdtemp(prefix="mobile_security_")
        
        if not os.path.exists(temp_dir):
            try:
                os.makedirs(temp_dir, exist_ok=True)
            except Exception as e:
                self.logger.error(f"Error creating temp directory: {str(e)}")
                import tempfile
                temp_dir = tempfile.mkdtemp(prefix="mobile_security_")
        
        return temp_dir
    
    def should_cleanup_temp(self) -> bool:
        """Check if temporary files should be cleaned up."""
        return self.get("storage.cleanup_temp", True)
    
    def get_risk_threshold(self) -> str:
        """Get risk threshold for reporting."""
        return self.get("reporting.risk_threshold", "medium")
    
    def get_report_formats(self) -> List[str]:
        """Get report formats."""
        formats = self.get("reporting.format", ["html"])
        if isinstance(formats, str):
            formats = [formats]
        return formats
    
    def is_dynamic_enabled(self) -> bool:
        """Check if dynamic analysis is enabled."""
        return self.get("scanning.enable_dynamic", True)
    
    def is_network_enabled(self) -> bool:
        """Check if network analysis is enabled."""
        return self.get("scanning.enable_network", True)
    
    def is_storage_enabled(self) -> bool:
        """Check if storage analysis is enabled."""
        return self.get("scanning.enable_storage", True)
    
    def is_code_enabled(self) -> bool:
        """Check if code analysis is enabled."""
        return self.get("scanning.enable_code", True)
    
    def get_scan_timeout(self) -> int:
        """Get scan timeout in seconds."""
        return self.get("scanning.timeout", 300)
    
    def get_max_threads(self) -> int:
        """Get maximum number of threads."""
        return self.get("scanning.max_threads", 4)
    
    def get_network_timeout(self) -> int:
        """Get network timeout in seconds."""
        return self.get("network.timeout", 30)
    
    def get_proxy_config(self) -> Dict[str, Any]:
        """Get proxy configuration."""
        network_config = self.get_network_config()
        proxy_config = {}
        
        if network_config.get("proxy_host"):
            proxy_config["host"] = network_config["proxy_host"]
            proxy_config["port"] = network_config.get("proxy_port", 8080)
            proxy_config["username"] = network_config.get("proxy_username")
            proxy_config["password"] = network_config.get("proxy_password")
        
        return proxy_config
    
    def should_verify_ssl(self) -> bool:
        """Check if SSL verification is enabled."""
        return self.get("network.verify_ssl", True)
    
    def is_exploitation_enabled(self) -> bool:
        """Check if exploitation is enabled."""
        return self.get("security.enable_exploitation", False)
    
    def is_fuzzing_enabled(self) -> bool:
        """Check if fuzzing is enabled."""
        return self.get("security.enable_fuzzing", False)
    
    def get_max_fuzz_iterations(self) -> int:
        """Get maximum fuzzing iterations."""
        return self.get("security.max_fuzz_iterations", 100)
    
    def is_brute_force_enabled(self) -> bool:
        """Check if brute force is enabled."""
        return self.get("security.enable_brute_force", False)
    
    def get_log_level(self) -> str:
        """Get logging level."""
        return self.get("logging.level", "INFO")
    
    def get_log_file(self) -> str:
        """Get log file path."""
        return self.get("logging.file", "mobile_security.log")
    
    def should_include_evidence(self) -> bool:
        """Check if evidence should be included in reports."""
        return self.get("reporting.include_evidence", True)
    
    def create_sample_config(self, output_file: str = "config_sample.json") -> bool:
        """Create a sample configuration file."""
        try:
            sample_config = self._get_default_config()
            
            # Add comments and descriptions
            sample_config["_comments"] = {
                "scanning": "Scanning configuration options",
                "reporting": "Report generation options",
                "tools": "External tool paths",
                "security": "Security testing options",
                "logging": "Logging configuration",
                "network": "Network analysis options",
                "storage": "Storage and temporary file options"
            }
            
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(sample_config, f, indent=2, ensure_ascii=False)
            
            self.logger.info(f"Sample configuration created: {output_file}")
            return True
        except Exception as e:
            self.logger.error(f"Error creating sample config: {str(e)}")
            return False 