#!/usr/bin/env python3
"""
Enhanced Configuration Manager
Provides advanced configuration management with validation, encryption, and dynamic updates
"""

import os
import yaml
import json
import logging
from pathlib import Path
from typing import Dict, Any, Optional, Union
from cryptography.fernet import Fernet
import hashlib
import secrets
import time

class ConfigManager:
    """Enhanced configuration manager with validation and encryption support"""
    
    def __init__(self, config_path: Optional[str] = None, auto_create: bool = True):
        self.config_path = config_path or "config/burp_config.yaml"
        self.config_data = {}
        self.encryption_key = None
        self.logger = logging.getLogger(__name__)
        
        # Default configuration
        self.default_config = {
            'burp': {
                'timeout': 30,
                'max_requests': 1000,
                'retry_attempts': 3,
                'concurrent_scans': 5
            },
            'paths': {
                'bchecks_dir': 'bchecks/vulnerability_checks',
                'bambdas_dir': 'bambdas/request_bambdas',
                'extensions_dir': 'extensions/python_extensions',
                'reports_dir': 'reports',
                'logs_dir': 'logs',
                'temp_dir': 'temp'
            },
            'logging': {
                'level': 'INFO',
                'file': 'logs/automation.log',
                'max_size': '10MB',
                'backup_count': 5,
                'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            },
            'security': {
                'encrypt_sensitive': False,
                'allowed_hosts': ['localhost', '127.0.0.1'],
                'blocked_patterns': ['admin', 'internal', 'secret'],
                'rate_limit': {
                    'requests_per_minute': 60,
                    'burst_size': 10
                }
            },
            'scanning': {
                'default_timeout': 30,
                'max_depth': 10,
                'exclude_paths': ['/admin', '/internal', '/api/v1/admin'],
                'include_paths': ['/api', '/public'],
                'custom_headers': {},
                'authentication': {
                    'enabled': False,
                    'type': 'bearer',  # bearer, basic, api_key
                    'credentials': {}
                }
            },
            'reporting': {
                'format': 'html',  # html, json, xml, pdf
                'include_evidence': True,
                'include_recommendations': True,
                'severity_levels': ['low', 'medium', 'high', 'critical'],
                'custom_templates': []
            }
        }
        
        if auto_create:
            self.load_or_create_config()
    
    def load_or_create_config(self) -> bool:
        """Load existing config or create default config"""
        try:
            if os.path.exists(self.config_path):
                return self.load_config()
            else:
                return self.create_default_config()
        except Exception as e:
            self.logger.error(f"Error in load_or_create_config: {e}")
            return False
    
    def load_config(self) -> bool:
        """Load configuration from file"""
        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                self.config_data = yaml.safe_load(f)
            
            # Merge with defaults for missing keys
            self._merge_with_defaults()
            self.logger.info(f"Configuration loaded from {self.config_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error loading config: {e}")
            return False
    
    def create_default_config(self) -> bool:
        """Create default configuration file"""
        try:
            # Ensure directory exists
            os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
            
            # Create default config
            self.config_data = self.default_config.copy()
            
            # Save to file
            self.save_config()
            
            self.logger.info(f"Default configuration created at {self.config_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error creating default config: {e}")
            return False
    
    def save_config(self) -> bool:
        """Save current configuration to file"""
        try:
            with open(self.config_path, 'w', encoding='utf-8') as f:
                yaml.dump(self.config_data, f, default_flow_style=False, indent=2)
            
            self.logger.info(f"Configuration saved to {self.config_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error saving config: {e}")
            return False
    
    def _merge_with_defaults(self):
        """Merge loaded config with defaults for missing keys"""
        def merge_dicts(default, loaded):
            for key, value in default.items():
                if key not in loaded:
                    loaded[key] = value
                elif isinstance(value, dict) and isinstance(loaded[key], dict):
                    merge_dicts(value, loaded[key])
        
        merge_dicts(self.default_config, self.config_data)
    
    def get(self, key_path: str, default: Any = None) -> Any:
        """Get configuration value using dot notation (e.g., 'burp.timeout')"""
        try:
            keys = key_path.split('.')
            value = self.config_data
            
            for key in keys:
                if isinstance(value, dict) and key in value:
                    value = value[key]
                else:
                    return default
            
            return value
            
        except Exception as e:
            self.logger.debug(f"Error getting config key {key_path}: {e}")
            return default
    
    def set(self, key_path: str, value: Any) -> bool:
        """Set configuration value using dot notation"""
        try:
            keys = key_path.split('.')
            config = self.config_data
            
            # Navigate to parent of target key
            for key in keys[:-1]:
                if key not in config:
                    config[key] = {}
                config = config[key]
            
            # Set the value
            config[keys[-1]] = value
            
            self.logger.info(f"Configuration updated: {key_path} = {value}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error setting config key {key_path}: {e}")
            return False
    
    def validate_config(self) -> Dict[str, Any]:
        """Validate current configuration and return validation results"""
        validation_results = {
            'valid': True,
            'errors': [],
            'warnings': [],
            'recommendations': []
        }
        
        try:
            # Validate required paths
            paths = self.get('paths', {})
            for path_key, path_value in paths.items():
                if path_key.endswith('_dir'):
                    full_path = os.path.join(os.getcwd(), path_value)
                    if not os.path.exists(full_path):
                        validation_results['warnings'].append(f"Directory {path_key} does not exist: {full_path}")
                        validation_results['recommendations'].append(f"Create directory: {full_path}")
            
            # Validate logging configuration
            logging_config = self.get('logging', {})
            if logging_config.get('level') not in ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']:
                validation_results['errors'].append("Invalid logging level")
                validation_results['valid'] = False
            
            # Validate security settings
            security_config = self.get('security', {})
            if security_config.get('encrypt_sensitive') and not self.encryption_key:
                validation_results['warnings'].append("Encryption enabled but no key provided")
            
            # Validate scanning configuration
            scanning_config = self.get('scanning', {})
            if scanning_config.get('default_timeout', 0) <= 0:
                validation_results['errors'].append("Invalid scanning timeout")
                validation_results['valid'] = False
            
        except Exception as e:
            validation_results['errors'].append(f"Validation error: {e}")
            validation_results['valid'] = False
        
        return validation_results
    
    def setup_encryption(self, key_file: Optional[str] = None) -> bool:
        """Setup encryption for sensitive configuration values"""
        try:
            if key_file and os.path.exists(key_file):
                with open(key_file, 'rb') as f:
                    self.encryption_key = f.read()
            else:
                # Generate new key
                self.encryption_key = Fernet.generate_key()
                if key_file:
                    os.makedirs(os.path.dirname(key_file), exist_ok=True)
                    with open(key_file, 'wb') as f:
                        f.write(self.encryption_key)
            
            self.logger.info("Encryption setup completed")
            return True
            
        except Exception as e:
            self.logger.error(f"Error setting up encryption: {e}")
            return False
    
    def encrypt_value(self, value: str) -> str:
        """Encrypt a sensitive configuration value"""
        if not self.encryption_key:
            return value
        
        try:
            fernet = Fernet(self.encryption_key)
            encrypted = fernet.encrypt(value.encode())
            return encrypted.decode()
        except Exception as e:
            self.logger.error(f"Error encrypting value: {e}")
            return value
    
    def decrypt_value(self, encrypted_value: str) -> str:
        """Decrypt an encrypted configuration value"""
        if not self.encryption_key:
            return encrypted_value
        
        try:
            fernet = Fernet(self.encryption_key)
            decrypted = fernet.decrypt(encrypted_value.encode())
            return decrypted.decode()
        except Exception as e:
            self.logger.error(f"Error decrypting value: {e}")
            return encrypted_value
    
    def export_config(self, format: str = 'yaml', filepath: Optional[str] = None) -> str:
        """Export configuration in specified format"""
        try:
            if format.lower() == 'json':
                content = json.dumps(self.config_data, indent=2)
                extension = '.json'
            else:
                content = yaml.dump(self.config_data, default_flow_style=False, indent=2)
                extension = '.yaml'
            
            if not filepath:
                filepath = f"config_export{extension}"
            
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(content)
            
            self.logger.info(f"Configuration exported to {filepath}")
            return filepath
            
        except Exception as e:
            self.logger.error(f"Error exporting config: {e}")
            return ""
    
    def import_config(self, filepath: str, merge: bool = True) -> bool:
        """Import configuration from file"""
        try:
            if filepath.endswith('.json'):
                with open(filepath, 'r', encoding='utf-8') as f:
                    imported_config = json.load(f)
            else:
                with open(filepath, 'r', encoding='utf-8') as f:
                    imported_config = yaml.safe_load(f)
            
            if merge:
                self._merge_configs(imported_config)
            else:
                self.config_data = imported_config
            
            self.logger.info(f"Configuration imported from {filepath}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error importing config: {e}")
            return False
    
    def _merge_configs(self, imported_config: Dict[str, Any]):
        """Merge imported configuration with current config"""
        def merge_dicts(current, imported):
            for key, value in imported.items():
                if key in current and isinstance(current[key], dict) and isinstance(value, dict):
                    merge_dicts(current[key], value)
                else:
                    current[key] = value
        
        merge_dicts(self.config_data, imported_config)
    
    def get_environment_overrides(self) -> Dict[str, Any]:
        """Get configuration overrides from environment variables"""
        overrides = {}
        
        # Common environment variable patterns
        env_patterns = {
            'BURP_TIMEOUT': 'burp.timeout',
            'BURP_MAX_REQUESTS': 'burp.max_requests',
            'BURP_LOG_LEVEL': 'logging.level',
            'BURP_LOG_FILE': 'logging.file',
            'BURP_BCHECKS_DIR': 'paths.bchecks_dir',
            'BURP_BAMBDAS_DIR': 'paths.bambdas_dir'
        }
        
        for env_var, config_path in env_patterns.items():
            value = os.environ.get(env_var)
            if value is not None:
                overrides[config_path] = value
        
        return overrides
    
    def apply_environment_overrides(self) -> bool:
        """Apply environment variable overrides to configuration"""
        try:
            overrides = self.get_environment_overrides()
            
            for config_path, value in overrides.items():
                # Convert string values to appropriate types
                if config_path.endswith('.timeout') or config_path.endswith('.max_requests'):
                    try:
                        value = int(value)
                    except ValueError:
                        self.logger.warning(f"Invalid integer value for {config_path}: {value}")
                        continue
                
                self.set(config_path, value)
            
            if overrides:
                self.logger.info(f"Applied {len(overrides)} environment overrides")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error applying environment overrides: {e}")
            return False
    
    def create_backup(self) -> str:
        """Create a backup of current configuration"""
        try:
            backup_path = f"{self.config_path}.backup.{int(time.time())}"
            with open(backup_path, 'w', encoding='utf-8') as f:
                yaml.dump(self.config_data, f, default_flow_style=False, indent=2)
            
            self.logger.info(f"Configuration backup created: {backup_path}")
            return backup_path
            
        except Exception as e:
            self.logger.error(f"Error creating backup: {e}")
            return ""
    
    def restore_backup(self, backup_path: str) -> bool:
        """Restore configuration from backup"""
        try:
            if not os.path.exists(backup_path):
                self.logger.error(f"Backup file not found: {backup_path}")
                return False
            
            with open(backup_path, 'r', encoding='utf-8') as f:
                backup_config = yaml.safe_load(f)
            
            self.config_data = backup_config
            self.save_config()
            
            self.logger.info(f"Configuration restored from backup: {backup_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error restoring backup: {e}")
            return False

# Example usage
if __name__ == "__main__":
    # Initialize config manager
    config_manager = ConfigManager()
    
    # Get configuration values
    timeout = config_manager.get('burp.timeout')
    log_level = config_manager.get('logging.level')
    
    print(f"Burp timeout: {timeout}")
    print(f"Log level: {log_level}")
    
    # Set configuration values
    config_manager.set('burp.timeout', 60)
    config_manager.set('logging.level', 'DEBUG')
    
    # Validate configuration
    validation = config_manager.validate_config()
    print(f"Configuration valid: {validation['valid']}")
    
    # Export configuration
    export_file = config_manager.export_config('json')
    print(f"Configuration exported to: {export_file}")
