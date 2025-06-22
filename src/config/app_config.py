#!/usr/bin/env python3
"""
Application Configuration Management
Centralized configuration for the API Security Scanner
"""

import os
import json
from pathlib import Path
from typing import Dict, Any, Optional

class AppConfig:
    """Application configuration manager"""
    
    def __init__(self, config_file: Optional[str] = None):
        self.config_file = config_file or 'src/config/default_config.json'
        self.config = self._load_default_config()
        self._load_environment_overrides()
        self._load_file_config()
    
    def _load_default_config(self) -> Dict[str, Any]:
        """Load default configuration"""
        # Get project root directory (2 levels up from src/config/)
        project_root = Path(__file__).parent.parent.parent
        
        return {
            # Web server configuration
            'web': {
                'host': '0.0.0.0',
                'port': 5000,
                'debug': True,
                'secret_key': 'dev-secret-key-change-in-production',
                'max_content_length': 16 * 1024 * 1024,  # 16MB
                'threaded': True
            },
            
            # Scanner configuration
            'scanner': {
                'max_workers': 10,
                'timeout': 30,
                'max_connections': 100,
                'cache_size': 1000,
                'max_requests_per_second': 10,
                'enable_optimization': True,
                'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            },
            
            # File paths (absolute paths from project root)
            'paths': {
                'reports_dir': str(project_root / 'reports'),
                'uploads_dir': str(project_root / 'uploads'),
                'logs_dir': str(project_root / 'logs'),
                'data_dir': str(project_root / 'data')
            },
            
            # Security settings
            'security': {
                'allowed_file_extensions': ['.json', '.yaml', '.yml'],
                'max_file_size': 16 * 1024 * 1024,  # 16MB
                'enable_rate_limiting': True,
                'rate_limit_requests': 100,
                'rate_limit_window': 3600  # 1 hour
            },
            
            # Logging configuration
            'logging': {
                'level': 'INFO',
                'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                'file': str(project_root / 'logs' / 'app.log'),
                'max_file_size': 10 * 1024 * 1024,  # 10MB
                'backup_count': 5
            },
            
            # Report configuration
            'reports': {
                'include_timestamps': True,
                'include_headers': True,
                'include_request_body': True,
                'include_response_body': False,
                'max_response_size': 1024 * 1024,  # 1MB
                'generate_html': True,
                'generate_json': True,
                'generate_owasp': True
            }
        }
    
    def _load_environment_overrides(self):
        """Load configuration overrides from environment variables"""
        # Web server overrides
        if os.environ.get('FLASK_HOST'):
            self.config['web']['host'] = os.environ['FLASK_HOST']
        if os.environ.get('FLASK_PORT'):
            self.config['web']['port'] = int(os.environ['FLASK_PORT'])
        if os.environ.get('FLASK_DEBUG'):
            self.config['web']['debug'] = os.environ['FLASK_DEBUG'].lower() == 'true'
        if os.environ.get('SECRET_KEY'):
            self.config['web']['secret_key'] = os.environ['SECRET_KEY']
        
        # Scanner overrides
        if os.environ.get('SCANNER_MAX_WORKERS'):
            self.config['scanner']['max_workers'] = int(os.environ['SCANNER_MAX_WORKERS'])
        if os.environ.get('SCANNER_TIMEOUT'):
            self.config['scanner']['timeout'] = int(os.environ['SCANNER_TIMEOUT'])
        if os.environ.get('SCANNER_ENABLE_OPTIMIZATION'):
            self.config['scanner']['enable_optimization'] = os.environ['SCANNER_ENABLE_OPTIMIZATION'].lower() == 'true'
        
        # Path overrides
        if os.environ.get('REPORTS_DIR'):
            self.config['paths']['reports_dir'] = os.environ['REPORTS_DIR']
        if os.environ.get('UPLOADS_DIR'):
            self.config['paths']['uploads_dir'] = os.environ['UPLOADS_DIR']
        if os.environ.get('LOGS_DIR'):
            self.config['paths']['logs_dir'] = os.environ['LOGS_DIR']
    
    def _load_file_config(self):
        """Load configuration from file if it exists"""
        try:
            config_path = Path(self.config_file)
            if config_path.exists():
                with open(config_path, 'r', encoding='utf-8') as f:
                    file_config = json.load(f)
                self._merge_config(file_config)
        except Exception as e:
            print(f"⚠️  Warning: Could not load config file {self.config_file}: {e}")
    
    def _merge_config(self, new_config: Dict[str, Any]):
        """Merge new configuration with existing config"""
        def merge_dicts(base: Dict[str, Any], update: Dict[str, Any]):
            for key, value in update.items():
                if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                    merge_dicts(base[key], value)
                else:
                    base[key] = value
        
        merge_dicts(self.config, new_config)
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value using dot notation (e.g., 'web.port')"""
        keys = key.split('.')
        value = self.config
        
        try:
            for k in keys:
                value = value[k]
            return value
        except (KeyError, TypeError):
            return default
    
    def set(self, key: str, value: Any):
        """Set configuration value using dot notation"""
        keys = key.split('.')
        config = self.config
        
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
        
        config[keys[-1]] = value
    
    def save(self, config_file: Optional[str] = None):
        """Save current configuration to file"""
        file_path = config_file or self.config_file
        try:
            config_path = Path(file_path)
            config_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(config_path, 'w', encoding='utf-8') as f:
                json.dump(self.config, f, indent=2, ensure_ascii=False)
            
            print(f"✅ Configuration saved to {file_path}")
        except Exception as e:
            print(f"❌ Error saving configuration: {e}")
    
    def get_web_config(self) -> Dict[str, Any]:
        """Get web server configuration"""
        return self.config['web']
    
    def get_scanner_config(self) -> Dict[str, Any]:
        """Get scanner configuration"""
        return self.config['scanner']
    
    def get_paths_config(self) -> Dict[str, Any]:
        """Get paths configuration"""
        return self.config['paths']
    
    def get_security_config(self) -> Dict[str, Any]:
        """Get security configuration"""
        return self.config['security']
    
    def get_logging_config(self) -> Dict[str, Any]:
        """Get logging configuration"""
        return self.config['logging']
    
    def get_reports_config(self) -> Dict[str, Any]:
        """Get reports configuration"""
        return self.config['reports']
    
    def ensure_directories(self):
        """Ensure all required directories exist"""
        paths = self.get_paths_config()
        
        for path_name, path_value in paths.items():
            path_obj = Path(path_value)
            if not path_obj.exists():
                path_obj.mkdir(parents=True, exist_ok=True)
                print(f"📁 Created directory: {path_obj}")
    
    def resolve_path(self, relative_path: str) -> Path:
        """Resolve a relative path to absolute path from project root"""
        project_root = Path(__file__).parent.parent.parent
        return project_root / relative_path
    
    def get_absolute_path(self, path_key: str) -> Path:
        """Get absolute path for a configuration path key"""
        paths = self.get_paths_config()
        if path_key in paths:
            return Path(paths[path_key])
        else:
            # Fallback to project root
            return self.resolve_path(path_key)
    
    def validate(self) -> bool:
        """Validate configuration"""
        try:
            # Validate web configuration
            web_config = self.get_web_config()
            assert isinstance(web_config['port'], int) and 1 <= web_config['port'] <= 65535
            assert isinstance(web_config['debug'], bool)
            
            # Validate scanner configuration
            scanner_config = self.get_scanner_config()
            assert isinstance(scanner_config['max_workers'], int) and scanner_config['max_workers'] > 0
            assert isinstance(scanner_config['timeout'], int) and scanner_config['timeout'] > 0
            
            # Validate paths
            paths_config = self.get_paths_config()
            for path_name, path_value in paths_config.items():
                assert isinstance(path_value, str) and path_value.strip()
            
            return True
            
        except (AssertionError, KeyError, TypeError) as e:
            print(f"❌ Configuration validation failed: {e}")
            return False

# Global configuration instance
config = AppConfig()

def get_config() -> AppConfig:
    """Get the global configuration instance"""
    return config 