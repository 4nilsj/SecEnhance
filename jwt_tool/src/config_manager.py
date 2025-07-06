import json
import os
from typing import Dict, Any, Optional
from pathlib import Path

class ConfigManager:
    def __init__(self, config_file: str = "config/default_config.json"):
        self.config_file = config_file
        self.config = self._load_config()
        self._load_environment_overrides()
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from JSON file."""
        try:
            config_path = Path(self.config_file)
            if config_path.exists():
                with open(config_path, 'r') as f:
                    return json.load(f)
            else:
                print(f"Warning: Config file {self.config_file} not found, using defaults")
                return self._get_default_config()
        except Exception as e:
            print(f"Warning: Failed to load config file: {e}, using defaults")
            return self._get_default_config()
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Return default configuration if file is not found."""
        return {
            "defaults": {
                "debug": False,
                "output_format": "html",
                "max_attempts": 1000,
                "workers": 4,
                "timeout": 30
            },
            "api": {
                "host": "0.0.0.0",
                "port": 5000,
                "debug": False,
                "cors_enabled": True
            },
            "testing": {
                "enable_cve_tests": True,
                "enable_dictionary_attack": True,
                "enable_claim_fuzzing": True,
                "enable_timestamp_tampering": True,
                "enable_jwks_validation": True
            },
            "reporting": {
                "include_poc": False,
                "include_reproduction_steps": True,
                "color_output": True,
                "progress_bars": True,
                "save_reports": True,
                "reports_directory": "reports"
            },
            "security": {
                "common_secrets_file": "config/common_secrets.txt",
                "max_token_size": 8192,
                "allowed_algorithms": ["HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "ES256", "ES384", "ES512"],
                "forbidden_algorithms": ["none"]
            }
        }
    
    def _load_environment_overrides(self):
        """Load configuration overrides from environment variables."""
        env_mappings = {
            "JWT_DEBUG": ("defaults", "debug", bool),
            "JWT_OUTPUT_FORMAT": ("defaults", "output_format", str),
            "JWT_MAX_ATTEMPTS": ("defaults", "max_attempts", int),
            "JWT_WORKERS": ("defaults", "workers", int),
            "JWT_TIMEOUT": ("defaults", "timeout", int),
            "JWT_API_HOST": ("api", "host", str),
            "JWT_API_PORT": ("api", "port", int),
            "JWT_API_DEBUG": ("api", "debug", bool),
            "JWT_ENABLE_CVE_TESTS": ("testing", "enable_cve_tests", bool),
            "JWT_ENABLE_DICT_ATTACK": ("testing", "enable_dictionary_attack", bool),
            "JWT_COLOR_OUTPUT": ("reporting", "color_output", bool),
            "JWT_PROGRESS_BARS": ("reporting", "progress_bars", bool),
            "JWT_SAVE_REPORTS": ("reporting", "save_reports", bool)
        }
        
        for env_var, (section, key, value_type) in env_mappings.items():
            if env_var in os.environ:
                try:
                    value = os.environ[env_var]
                    if value_type == bool:
                        value = value.lower() in ('true', '1', 'yes', 'on')
                    elif value_type == int:
                        value = int(value)
                    self.config[section][key] = value
                except (ValueError, TypeError):
                    print(f"Warning: Invalid value for {env_var}")
    
    def get(self, section: str, key: str, default: Any = None) -> Any:
        """Get a configuration value."""
        try:
            return self.config[section][key]
        except KeyError:
            return default
    
    def get_default(self, key: str, default: Any = None) -> Any:
        """Get a value from the defaults section."""
        return self.get("defaults", key, default)
    
    def get_api(self, key: str, default: Any = None) -> Any:
        """Get a value from the api section."""
        return self.get("api", key, default)
    
    def get_testing(self, key: str, default: Any = None) -> Any:
        """Get a value from the testing section."""
        return self.get("testing", key, default)
    
    def get_reporting(self, key: str, default: Any = None) -> Any:
        """Get a value from the reporting section."""
        return self.get("reporting", key, default)
    
    def get_security(self, key: str, default: Any = None) -> Any:
        """Get a value from the security section."""
        return self.get("security", key, default)
    
    def set(self, section: str, key: str, value: Any):
        """Set a configuration value."""
        if section not in self.config:
            self.config[section] = {}
        self.config[section][key] = value
    
    def update_from_args(self, args):
        """Update configuration from command line arguments."""
        if hasattr(args, 'debug') and args.debug is not None:
            self.set("defaults", "debug", args.debug)
        if hasattr(args, 'output') and args.output:
            self.set("defaults", "output_format", args.output)
        if hasattr(args, 'max_attempts') and args.max_attempts:
            self.set("defaults", "max_attempts", args.max_attempts)
        if hasattr(args, 'workers') and args.workers:
            self.set("defaults", "workers", args.workers)
        if hasattr(args, 'timeout') and args.timeout:
            self.set("defaults", "timeout", args.timeout)
    
    def save_config(self, file_path: str = None):
        """Save current configuration to file."""
        if file_path is None:
            file_path = self.config_file
        
        try:
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            with open(file_path, 'w') as f:
                json.dump(self.config, f, indent=4)
        except Exception as e:
            print(f"Warning: Failed to save config: {e}")
    
    def print_config(self):
        """Print current configuration."""
        print("Current Configuration:")
        print(json.dumps(self.config, indent=2)) 