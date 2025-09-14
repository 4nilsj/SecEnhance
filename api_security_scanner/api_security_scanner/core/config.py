"""
Configuration management for API Security Scanner.
Handles environment variables, .env files, and default configurations.
"""

import os
import logging
from pathlib import Path
from typing import Dict, Any, Optional, Union
from dataclasses import dataclass, field
from dotenv import load_dotenv


@dataclass
class DatabaseConfig:
    """Database configuration settings."""
    path: str = "scan_results.db"
    backup_enabled: bool = True
    backup_interval: int = 24  # hours
    max_backups: int = 7
    connection_timeout: int = 30


@dataclass
class ZAPConfig:
    """ZAP (OWASP Zed Attack Proxy) configuration settings."""
    path: Optional[str] = None
    host: str = "localhost"
    port: int = 8080
    api_key: Optional[str] = None
    timeout: int = 300  # seconds
    max_scan_time: int = 3600  # seconds
    spider_depth: int = 5
    max_children: int = 10
    thread_count: int = 2
    external_zap: bool = False
    zap_daemon: bool = True


@dataclass
class LoggingConfig:
    """Logging configuration settings."""
    level: str = "INFO"
    format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    file_enabled: bool = True
    console_enabled: bool = True
    max_file_size: int = 10 * 1024 * 1024  # 10MB
    backup_count: int = 5
    log_dir: str = "logs"


@dataclass
class AIDetectionConfig:
    """AI-powered detection configuration settings."""
    enabled: bool = True
    models: Dict[str, Any] = field(default_factory=lambda: {
        'anomaly_detection': {
            'enabled': True,
            'threshold': 0.7,
            'contamination': 0.1
        },
        'vulnerability_classification': {
            'enabled': True,
            'threshold': 0.8,
            'min_samples': 10
        },
        'risk_scoring': {
            'enabled': True,
            'weights': {
                'endpoint_complexity': 0.3,
                'parameter_count': 0.2,
                'authentication': 0.3,
                'data_sensitivity': 0.2
            }
        },
        'intelligent_fuzzing': {
            'enabled': True,
            'max_suggestions': 50,
            'confidence_threshold': 0.6
        }
    })
    learning: Dict[str, Any] = field(default_factory=lambda: {
        'enabled': True,
        'auto_retrain': True,
        'retrain_interval': 100,  # scans
        'min_training_samples': 50
    })
    fallback_to_rules: bool = True
    model_storage_path: str = "models"


@dataclass
class ReportConfig:
    """Report generation configuration settings."""
    output_dir: str = "reports"
    template_dir: str = "templates"
    include_screenshots: bool = True
    include_poc: bool = True
    max_report_size: int = 50 * 1024 * 1024  # 50MB
    auto_open: bool = False


@dataclass
class SecurityConfig:
    """Security-related configuration settings."""
    max_requests_per_second: int = 10
    request_timeout: int = 30
    verify_ssl: bool = True
    follow_redirects: bool = True
    max_redirects: int = 5
    user_agent: str = "API-Security-Scanner/1.0.0"


@dataclass
class PluginConfig:
    """Plugin system configuration settings."""
    enabled_plugins: list = field(default_factory=lambda: [
        "CORSChecker",
        "RateLimitingChecker", 
        "SecurityHeadersChecker",
        "EnhancedSecurityChecker"
    ])
    plugin_timeout: int = 60  # seconds
    max_concurrent_plugins: int = 3
    custom_plugin_dir: str = "custom_plugins"


@dataclass
class ContainerConfig:
    """Container-specific configuration settings."""
    is_container: bool = False
    data_dir: str = "/app/data"
    logs_dir: str = "/app/logs"
    reports_dir: str = "/app/reports"
    workspace_dir: str = "/workspace"
    zap_container_name: str = "zap"
    network_mode: str = "bridge"


@dataclass
class AppConfig:
    """Main application configuration."""
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    zap: ZAPConfig = field(default_factory=ZAPConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    report: ReportConfig = field(default_factory=ReportConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    plugin: PluginConfig = field(default_factory=PluginConfig)
    container: ContainerConfig = field(default_factory=ContainerConfig)
    ai_detection: AIDetectionConfig = field(default_factory=AIDetectionConfig)
    
    # Application settings
    app_name: str = "API Security Scanner"
    version: str = "1.0.0"
    debug: bool = False
    verbose: bool = False
    config_file: Optional[str] = None


class ConfigManager:
    """Manages application configuration from environment variables and .env files."""
    
    def __init__(self, env_file: Optional[str] = None):
        self.env_file = env_file or ".env"
        self.config = AppConfig()
        self._load_environment()
        self._load_env_file()
        self._apply_environment_overrides()
    
    def _load_environment(self):
        """Load configuration from environment variables."""
        # Detect if running in container
        self.config.container.is_container = self._detect_container()
        
        # Set container-specific paths if in container
        if self.config.container.is_container:
            self.config.database.path = os.path.join(
                self.config.container.data_dir, 
                "scan_results.db"
            )
            self.config.logging.log_dir = self.config.container.logs_dir
            self.config.report.output_dir = self.config.container.reports_dir
    
    def _detect_container(self) -> bool:
        """Detect if running inside a container."""
        container_indicators = [
            os.path.exists("/.dockerenv"),
            os.path.exists("/.containerenv"),
            os.environ.get("CONTAINER") == "true",
            os.environ.get("DOCKER_CONTAINER") == "true",
            os.environ.get("KUBERNETES_SERVICE_HOST") is not None,
        ]
        return any(container_indicators)
    
    def _load_env_file(self):
        """Load configuration from .env file if it exists."""
        env_path = Path(self.env_file)
        if env_path.exists():
            load_dotenv(env_path)
            logging.info(f"Loaded configuration from {env_path}")
        else:
            logging.debug(f"No .env file found at {env_path}")
    
    def _apply_environment_overrides(self):
        """Apply environment variable overrides to configuration."""
        # Database configuration
        if os.getenv("DB_PATH"):
            self.config.database.path = os.getenv("DB_PATH")
        if os.getenv("DB_BACKUP_ENABLED"):
            self.config.database.backup_enabled = os.getenv("DB_BACKUP_ENABLED").lower() == "true"
        if os.getenv("DB_BACKUP_INTERVAL"):
            self.config.database.backup_interval = int(os.getenv("DB_BACKUP_INTERVAL"))
        
        # ZAP configuration
        if os.getenv("ZAP_PATH"):
            self.config.zap.path = os.getenv("ZAP_PATH")
        if os.getenv("ZAP_HOST"):
            self.config.zap.host = os.getenv("ZAP_HOST")
        if os.getenv("ZAP_PORT"):
            self.config.zap.port = int(os.getenv("ZAP_PORT"))
        if os.getenv("ZAP_API_KEY"):
            self.config.zap.api_key = os.getenv("ZAP_API_KEY")
        if os.getenv("ZAP_TIMEOUT"):
            self.config.zap.timeout = int(os.getenv("ZAP_TIMEOUT"))
        if os.getenv("ZAP_EXTERNAL"):
            self.config.zap.external_zap = os.getenv("ZAP_EXTERNAL").lower() == "true"
        if os.getenv("ZAP_DAEMON"):
            self.config.zap.daemon = os.getenv("ZAP_DAEMON").lower() == "true"
        
        # Logging configuration
        if os.getenv("LOG_LEVEL"):
            self.config.logging.level = os.getenv("LOG_LEVEL").upper()
        if os.getenv("LOG_DIR"):
            self.config.logging.log_dir = os.getenv("LOG_DIR")
        if os.getenv("LOG_FILE_ENABLED"):
            self.config.logging.file_enabled = os.getenv("LOG_FILE_ENABLED").lower() == "true"
        if os.getenv("LOG_CONSOLE_ENABLED"):
            self.config.logging.console_enabled = os.getenv("LOG_CONSOLE_ENABLED").lower() == "true"
        
        # Report configuration
        if os.getenv("REPORT_DIR"):
            self.config.report.output_dir = os.getenv("REPORT_DIR")
        if os.getenv("REPORT_TEMPLATE_DIR"):
            self.config.report.template_dir = os.getenv("REPORT_TEMPLATE_DIR")
        if os.getenv("REPORT_INCLUDE_SCREENSHOTS"):
            self.config.report.include_screenshots = os.getenv("REPORT_INCLUDE_SCREENSHOTS").lower() == "true"
        if os.getenv("REPORT_AUTO_OPEN"):
            self.config.report.auto_open = os.getenv("REPORT_AUTO_OPEN").lower() == "true"
        
        # Security configuration
        if os.getenv("MAX_REQUESTS_PER_SECOND"):
            self.config.security.max_requests_per_second = int(os.getenv("MAX_REQUESTS_PER_SECOND"))
        if os.getenv("REQUEST_TIMEOUT"):
            self.config.security.request_timeout = int(os.getenv("REQUEST_TIMEOUT"))
        if os.getenv("VERIFY_SSL"):
            self.config.security.verify_ssl = os.getenv("VERIFY_SSL").lower() == "true"
        if os.getenv("USER_AGENT"):
            self.config.security.user_agent = os.getenv("USER_AGENT")
        
        # Plugin configuration
        if os.getenv("ENABLED_PLUGINS"):
            plugins = os.getenv("ENABLED_PLUGINS").split(",")
            self.config.plugin.enabled_plugins = [p.strip() for p in plugins if p.strip()]
        if os.getenv("PLUGIN_TIMEOUT"):
            self.config.plugin.plugin_timeout = int(os.getenv("PLUGIN_TIMEOUT"))
        if os.getenv("CUSTOM_PLUGIN_DIR"):
            self.config.plugin.custom_plugin_dir = os.getenv("CUSTOM_PLUGIN_DIR")
        
        # Container configuration
        if os.getenv("CONTAINER_DATA_DIR"):
            self.config.container.data_dir = os.getenv("CONTAINER_DATA_DIR")
        if os.getenv("CONTAINER_LOGS_DIR"):
            self.config.container.logs_dir = os.getenv("CONTAINER_LOGS_DIR")
        if os.getenv("CONTAINER_REPORTS_DIR"):
            self.config.container.reports_dir = os.getenv("CONTAINER_REPORTS_DIR")
        if os.getenv("ZAP_CONTAINER_NAME"):
            self.config.container.zap_container_name = os.getenv("ZAP_CONTAINER_NAME")
        
        # AI Detection configuration
        if os.getenv("AI_DETECTION_ENABLED"):
            self.config.ai_detection.enabled = os.getenv("AI_DETECTION_ENABLED").lower() == "true"
        if os.getenv("AI_ANOMALY_DETECTION_ENABLED"):
            self.config.ai_detection.models['anomaly_detection']['enabled'] = os.getenv("AI_ANOMALY_DETECTION_ENABLED").lower() == "true"
        if os.getenv("AI_VULNERABILITY_CLASSIFICATION_ENABLED"):
            self.config.ai_detection.models['vulnerability_classification']['enabled'] = os.getenv("AI_VULNERABILITY_CLASSIFICATION_ENABLED").lower() == "true"
        if os.getenv("AI_RISK_SCORING_ENABLED"):
            self.config.ai_detection.models['risk_scoring']['enabled'] = os.getenv("AI_RISK_SCORING_ENABLED").lower() == "true"
        if os.getenv("AI_INTELLIGENT_FUZZING_ENABLED"):
            self.config.ai_detection.models['intelligent_fuzzing']['enabled'] = os.getenv("AI_INTELLIGENT_FUZZING_ENABLED").lower() == "true"
        if os.getenv("AI_LEARNING_ENABLED"):
            self.config.ai_detection.learning['enabled'] = os.getenv("AI_LEARNING_ENABLED").lower() == "true"
        if os.getenv("AI_MODEL_STORAGE_PATH"):
            self.config.ai_detection.model_storage_path = os.getenv("AI_MODEL_STORAGE_PATH")
        
        # Application settings
        if os.getenv("DEBUG"):
            self.config.debug = os.getenv("DEBUG").lower() == "true"
        if os.getenv("VERBOSE"):
            self.config.verbose = os.getenv("VERBOSE").lower() == "true"
        if os.getenv("APP_NAME"):
            self.config.app_name = os.getenv("APP_NAME")
    
    def get_config(self) -> AppConfig:
        """Get the current configuration."""
        return self.config
    
    def update_config(self, **kwargs):
        """Update configuration with provided values."""
        for key, value in kwargs.items():
            if hasattr(self.config, key):
                setattr(self.config, key, value)
    
    def save_to_env(self, env_file: str = ".env"):
        """Save current configuration to .env file."""
        env_content = []
        env_content.append("# API Security Scanner Configuration")
        env_content.append("# Generated automatically - modify as needed")
        env_content.append("")
        
        # Database settings
        env_content.append("# Database Configuration")
        env_content.append(f"DB_PATH={self.config.database.path}")
        env_content.append(f"DB_BACKUP_ENABLED={str(self.config.database.backup_enabled).lower()}")
        env_content.append(f"DB_BACKUP_INTERVAL={self.config.database.backup_interval}")
        env_content.append("")
        
        # ZAP settings
        env_content.append("# ZAP Configuration")
        if self.config.zap.path:
            env_content.append(f"ZAP_PATH={self.config.zap.path}")
        env_content.append(f"ZAP_HOST={self.config.zap.host}")
        env_content.append(f"ZAP_PORT={self.config.zap.port}")
        if self.config.zap.api_key:
            env_content.append(f"ZAP_API_KEY={self.config.zap.api_key}")
        env_content.append(f"ZAP_TIMEOUT={self.config.zap.timeout}")
        env_content.append(f"ZAP_EXTERNAL={str(self.config.zap.external_zap).lower()}")
        env_content.append("")
        
        # Logging settings
        env_content.append("# Logging Configuration")
        env_content.append(f"LOG_LEVEL={self.config.logging.level}")
        env_content.append(f"LOG_DIR={self.config.logging.log_dir}")
        env_content.append(f"LOG_FILE_ENABLED={str(self.config.logging.file_enabled).lower()}")
        env_content.append(f"LOG_CONSOLE_ENABLED={str(self.config.logging.console_enabled).lower()}")
        env_content.append("")
        
        # Report settings
        env_content.append("# Report Configuration")
        env_content.append(f"REPORT_DIR={self.config.report.output_dir}")
        env_content.append(f"REPORT_TEMPLATE_DIR={self.config.report.template_dir}")
        env_content.append(f"REPORT_INCLUDE_SCREENSHOTS={str(self.config.report.include_screenshots).lower()}")
        env_content.append(f"REPORT_AUTO_OPEN={str(self.config.report.auto_open).lower()}")
        env_content.append("")
        
        # Security settings
        env_content.append("# Security Configuration")
        env_content.append(f"MAX_REQUESTS_PER_SECOND={self.config.security.max_requests_per_second}")
        env_content.append(f"REQUEST_TIMEOUT={self.config.security.request_timeout}")
        env_content.append(f"VERIFY_SSL={str(self.config.security.verify_ssl).lower()}")
        env_content.append(f"USER_AGENT={self.config.security.user_agent}")
        env_content.append("")
        
        # Plugin settings
        env_content.append("# Plugin Configuration")
        env_content.append(f"ENABLED_PLUGINS={','.join(self.config.plugin.enabled_plugins)}")
        env_content.append(f"PLUGIN_TIMEOUT={self.config.plugin.plugin_timeout}")
        env_content.append(f"CUSTOM_PLUGIN_DIR={self.config.plugin.custom_plugin_dir}")
        env_content.append("")
        
        # Container settings
        env_content.append("# Container Configuration")
        env_content.append(f"CONTAINER_DATA_DIR={self.config.container.data_dir}")
        env_content.append(f"CONTAINER_LOGS_DIR={self.config.container.logs_dir}")
        env_content.append(f"CONTAINER_REPORTS_DIR={self.config.container.reports_dir}")
        env_content.append(f"ZAP_CONTAINER_NAME={self.config.container.zap_container_name}")
        env_content.append("")
        
        # Application settings
        env_content.append("# Application Configuration")
        env_content.append(f"DEBUG={str(self.config.debug).lower()}")
        env_content.append(f"VERBOSE={str(self.config.verbose).lower()}")
        env_content.append(f"APP_NAME={self.config.app_name}")
        
        with open(env_file, 'w') as f:
            f.write('\n'.join(env_content))
        
        logging.info(f"Configuration saved to {env_file}")
    
    def validate_config(self) -> Dict[str, Any]:
        """Validate the current configuration and return any issues."""
        issues = []
        
        # Validate database path
        db_dir = Path(self.config.database.path).parent
        if not db_dir.exists():
            try:
                db_dir.mkdir(parents=True, exist_ok=True)
            except Exception as e:
                issues.append(f"Cannot create database directory {db_dir}: {e}")
        
        # Validate log directory
        log_dir = Path(self.config.logging.log_dir)
        if not log_dir.exists():
            try:
                log_dir.mkdir(parents=True, exist_ok=True)
            except Exception as e:
                issues.append(f"Cannot create log directory {log_dir}: {e}")
        
        # Validate report directory
        report_dir = Path(self.config.report.output_dir)
        if not report_dir.exists():
            try:
                report_dir.mkdir(parents=True, exist_ok=True)
            except Exception as e:
                issues.append(f"Cannot create report directory {report_dir}: {e}")
        
        # Validate ZAP configuration
        if not self.config.zap.external_zap and not self.config.zap.path:
            issues.append("ZAP path must be specified when not using external ZAP")
        
        # Validate plugin configuration
        if not self.config.plugin.enabled_plugins:
            issues.append("At least one plugin must be enabled")
        
        return {
            "valid": len(issues) == 0,
            "issues": issues
        }


# Global configuration instance
_config_manager: Optional[ConfigManager] = None


def get_config_manager(env_file: Optional[str] = None) -> ConfigManager:
    """Get the global configuration manager instance."""
    global _config_manager
    if _config_manager is None:
        _config_manager = ConfigManager(env_file)
    return _config_manager


def get_config() -> AppConfig:
    """Get the current application configuration."""
    return get_config_manager().get_config()


def reload_config(env_file: Optional[str] = None):
    """Reload configuration from environment and .env file."""
    global _config_manager
    _config_manager = ConfigManager(env_file)
    return _config_manager
