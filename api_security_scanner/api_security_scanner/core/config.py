"""
Configuration management for API Security Scanner.
Handles environment variables, .env files, and default configurations.
"""

import os
import logging
from pathlib import Path
from typing import Dict, Any, Optional, Union
from dataclasses import dataclass, field
from dotenv import load_dotenv  # type: ignore


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
class ScanModeConfig:
    """ZAP scan mode configuration settings."""
    mode: str = "safe"  # safe, attack, spidering, comprehensive, stealth, aggressive
    zap_enabled: bool = True
    spider_depth: int = 5
    spider_children: int = 10
    max_scan_time: int = 3600  # seconds
    request_delay: float = 0.1  # seconds between requests
    concurrent_requests: int = 2
    aggressive_scanning: bool = False
    stealth_mode: bool = False
    custom_user_agent: Optional[str] = None
    follow_redirects: bool = True
    max_redirects: int = 5
    verify_ssl: bool = True
    timeout: int = 30
    retry_attempts: int = 3
    fuzzing_enabled: bool = False
    injection_tests: bool = False
    authentication_tests: bool = True
    rate_limiting_tests: bool = True
    headers_analysis: bool = True
    cors_analysis: bool = True
    jwt_analysis: bool = True
    graphql_analysis: bool = True
    grpc_analysis: bool = True
    ai_detection_enabled: bool = True


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
    scan_mode: ScanModeConfig = field(default_factory=ScanModeConfig)
    
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
        db_path = os.getenv("DB_PATH")
        if db_path:
            self.config.database.path = db_path
        db_backup_enabled = os.getenv("DB_BACKUP_ENABLED")
        if db_backup_enabled:
            self.config.database.backup_enabled = db_backup_enabled.lower() == "true"
        db_backup_interval = os.getenv("DB_BACKUP_INTERVAL")
        if db_backup_interval:
            self.config.database.backup_interval = int(db_backup_interval)
        
        # ZAP configuration
        zap_path = os.getenv("ZAP_PATH")
        if zap_path:
            self.config.zap.path = zap_path
        zap_host = os.getenv("ZAP_HOST")
        if zap_host:
            self.config.zap.host = zap_host
        zap_port = os.getenv("ZAP_PORT")
        if zap_port:
            self.config.zap.port = int(zap_port)
        zap_api_key = os.getenv("ZAP_API_KEY")
        if zap_api_key:
            self.config.zap.api_key = zap_api_key
        zap_timeout = os.getenv("ZAP_TIMEOUT")
        if zap_timeout:
            self.config.zap.timeout = int(zap_timeout)
        zap_external = os.getenv("ZAP_EXTERNAL")
        if zap_external:
            self.config.zap.external_zap = zap_external.lower() == "true"
        zap_daemon = os.getenv("ZAP_DAEMON")
        if zap_daemon:
            self.config.zap.zap_daemon = zap_daemon.lower() == "true"
        
        # Logging configuration
        log_level = os.getenv("LOG_LEVEL")
        if log_level:
            self.config.logging.level = log_level.upper()
        log_dir = os.getenv("LOG_DIR")
        if log_dir:
            self.config.logging.log_dir = log_dir
        log_file_enabled = os.getenv("LOG_FILE_ENABLED")
        if log_file_enabled:
            self.config.logging.file_enabled = log_file_enabled.lower() == "true"
        log_console_enabled = os.getenv("LOG_CONSOLE_ENABLED")
        if log_console_enabled:
            self.config.logging.console_enabled = log_console_enabled.lower() == "true"
        
        # Report configuration
        report_dir = os.getenv("REPORT_DIR")
        if report_dir:
            self.config.report.output_dir = report_dir
        report_template_dir = os.getenv("REPORT_TEMPLATE_DIR")
        if report_template_dir:
            self.config.report.template_dir = report_template_dir
        report_include_screenshots = os.getenv("REPORT_INCLUDE_SCREENSHOTS")
        if report_include_screenshots:
            self.config.report.include_screenshots = report_include_screenshots.lower() == "true"
        report_auto_open = os.getenv("REPORT_AUTO_OPEN")
        if report_auto_open:
            self.config.report.auto_open = report_auto_open.lower() == "true"
        
        # Security configuration
        max_requests_per_second = os.getenv("MAX_REQUESTS_PER_SECOND")
        if max_requests_per_second:
            self.config.security.max_requests_per_second = int(max_requests_per_second)
        request_timeout = os.getenv("REQUEST_TIMEOUT")
        if request_timeout:
            self.config.security.request_timeout = int(request_timeout)
        verify_ssl = os.getenv("VERIFY_SSL")
        if verify_ssl:
            self.config.security.verify_ssl = verify_ssl.lower() == "true"
        user_agent = os.getenv("USER_AGENT")
        if user_agent:
            self.config.security.user_agent = user_agent
        
        # Plugin configuration
        enabled_plugins = os.getenv("ENABLED_PLUGINS")
        if enabled_plugins:
            plugins = enabled_plugins.split(",")
            self.config.plugin.enabled_plugins = [p.strip() for p in plugins if p.strip()]
        plugin_timeout = os.getenv("PLUGIN_TIMEOUT")
        if plugin_timeout:
            self.config.plugin.plugin_timeout = int(plugin_timeout)
        custom_plugin_dir = os.getenv("CUSTOM_PLUGIN_DIR")
        if custom_plugin_dir:
            self.config.plugin.custom_plugin_dir = custom_plugin_dir
        
        # Container configuration
        container_data_dir = os.getenv("CONTAINER_DATA_DIR")
        if container_data_dir:
            self.config.container.data_dir = container_data_dir
        container_logs_dir = os.getenv("CONTAINER_LOGS_DIR")
        if container_logs_dir:
            self.config.container.logs_dir = container_logs_dir
        container_reports_dir = os.getenv("CONTAINER_REPORTS_DIR")
        if container_reports_dir:
            self.config.container.reports_dir = container_reports_dir
        zap_container_name = os.getenv("ZAP_CONTAINER_NAME")
        if zap_container_name:
            self.config.container.zap_container_name = zap_container_name
        
        # AI Detection configuration
        ai_detection_enabled = os.getenv("AI_DETECTION_ENABLED")
        if ai_detection_enabled:
            self.config.ai_detection.enabled = ai_detection_enabled.lower() == "true"
        ai_anomaly_detection_enabled = os.getenv("AI_ANOMALY_DETECTION_ENABLED")
        if ai_anomaly_detection_enabled:
            self.config.ai_detection.models['anomaly_detection']['enabled'] = ai_anomaly_detection_enabled.lower() == "true"
        ai_vulnerability_classification_enabled = os.getenv("AI_VULNERABILITY_CLASSIFICATION_ENABLED")
        if ai_vulnerability_classification_enabled:
            self.config.ai_detection.models['vulnerability_classification']['enabled'] = ai_vulnerability_classification_enabled.lower() == "true"
        ai_risk_scoring_enabled = os.getenv("AI_RISK_SCORING_ENABLED")
        if ai_risk_scoring_enabled:
            self.config.ai_detection.models['risk_scoring']['enabled'] = ai_risk_scoring_enabled.lower() == "true"
        ai_intelligent_fuzzing_enabled = os.getenv("AI_INTELLIGENT_FUZZING_ENABLED")
        if ai_intelligent_fuzzing_enabled:
            self.config.ai_detection.models['intelligent_fuzzing']['enabled'] = ai_intelligent_fuzzing_enabled.lower() == "true"
        ai_learning_enabled = os.getenv("AI_LEARNING_ENABLED")
        if ai_learning_enabled:
            self.config.ai_detection.learning['enabled'] = ai_learning_enabled.lower() == "true"
        ai_model_storage_path = os.getenv("AI_MODEL_STORAGE_PATH")
        if ai_model_storage_path:
            self.config.ai_detection.model_storage_path = ai_model_storage_path
        
        # Scan Mode configuration
        scan_mode = os.getenv("SCAN_MODE")
        if scan_mode:
            self.config.scan_mode.mode = scan_mode.lower()
        scan_mode_zap_enabled = os.getenv("SCAN_MODE_ZAP_ENABLED")
        if scan_mode_zap_enabled:
            self.config.scan_mode.zap_enabled = scan_mode_zap_enabled.lower() == "true"
        scan_mode_spider_depth = os.getenv("SCAN_MODE_SPIDER_DEPTH")
        if scan_mode_spider_depth:
            self.config.scan_mode.spider_depth = int(scan_mode_spider_depth)
        scan_mode_spider_children = os.getenv("SCAN_MODE_SPIDER_CHILDREN")
        if scan_mode_spider_children:
            self.config.scan_mode.spider_children = int(scan_mode_spider_children)
        scan_mode_max_scan_time = os.getenv("SCAN_MODE_MAX_SCAN_TIME")
        if scan_mode_max_scan_time:
            self.config.scan_mode.max_scan_time = int(scan_mode_max_scan_time)
        scan_mode_request_delay = os.getenv("SCAN_MODE_REQUEST_DELAY")
        if scan_mode_request_delay:
            self.config.scan_mode.request_delay = float(scan_mode_request_delay)
        scan_mode_concurrent_requests = os.getenv("SCAN_MODE_CONCURRENT_REQUESTS")
        if scan_mode_concurrent_requests:
            self.config.scan_mode.concurrent_requests = int(scan_mode_concurrent_requests)
        scan_mode_aggressive = os.getenv("SCAN_MODE_AGGRESSIVE")
        if scan_mode_aggressive:
            self.config.scan_mode.aggressive_scanning = scan_mode_aggressive.lower() == "true"
        scan_mode_stealth = os.getenv("SCAN_MODE_STEALTH")
        if scan_mode_stealth:
            self.config.scan_mode.stealth_mode = scan_mode_stealth.lower() == "true"
        scan_mode_custom_user_agent = os.getenv("SCAN_MODE_CUSTOM_USER_AGENT")
        if scan_mode_custom_user_agent:
            self.config.scan_mode.custom_user_agent = scan_mode_custom_user_agent
        scan_mode_follow_redirects = os.getenv("SCAN_MODE_FOLLOW_REDIRECTS")
        if scan_mode_follow_redirects:
            self.config.scan_mode.follow_redirects = scan_mode_follow_redirects.lower() == "true"
        scan_mode_max_redirects = os.getenv("SCAN_MODE_MAX_REDIRECTS")
        if scan_mode_max_redirects:
            self.config.scan_mode.max_redirects = int(scan_mode_max_redirects)
        scan_mode_verify_ssl = os.getenv("SCAN_MODE_VERIFY_SSL")
        if scan_mode_verify_ssl:
            self.config.scan_mode.verify_ssl = scan_mode_verify_ssl.lower() == "true"
        scan_mode_timeout = os.getenv("SCAN_MODE_TIMEOUT")
        if scan_mode_timeout:
            self.config.scan_mode.timeout = int(scan_mode_timeout)
        scan_mode_retry_attempts = os.getenv("SCAN_MODE_RETRY_ATTEMPTS")
        if scan_mode_retry_attempts:
            self.config.scan_mode.retry_attempts = int(scan_mode_retry_attempts)
        scan_mode_fuzzing_enabled = os.getenv("SCAN_MODE_FUZZING_ENABLED")
        if scan_mode_fuzzing_enabled:
            self.config.scan_mode.fuzzing_enabled = scan_mode_fuzzing_enabled.lower() == "true"
        scan_mode_injection_tests = os.getenv("SCAN_MODE_INJECTION_TESTS")
        if scan_mode_injection_tests:
            self.config.scan_mode.injection_tests = scan_mode_injection_tests.lower() == "true"
        scan_mode_authentication_tests = os.getenv("SCAN_MODE_AUTHENTICATION_TESTS")
        if scan_mode_authentication_tests:
            self.config.scan_mode.authentication_tests = scan_mode_authentication_tests.lower() == "true"
        scan_mode_rate_limiting_tests = os.getenv("SCAN_MODE_RATE_LIMITING_TESTS")
        if scan_mode_rate_limiting_tests:
            self.config.scan_mode.rate_limiting_tests = scan_mode_rate_limiting_tests.lower() == "true"
        scan_mode_headers_analysis = os.getenv("SCAN_MODE_HEADERS_ANALYSIS")
        if scan_mode_headers_analysis:
            self.config.scan_mode.headers_analysis = scan_mode_headers_analysis.lower() == "true"
        scan_mode_cors_analysis = os.getenv("SCAN_MODE_CORS_ANALYSIS")
        if scan_mode_cors_analysis:
            self.config.scan_mode.cors_analysis = scan_mode_cors_analysis.lower() == "true"
        scan_mode_jwt_analysis = os.getenv("SCAN_MODE_JWT_ANALYSIS")
        if scan_mode_jwt_analysis:
            self.config.scan_mode.jwt_analysis = scan_mode_jwt_analysis.lower() == "true"
        scan_mode_graphql_analysis = os.getenv("SCAN_MODE_GRAPHQL_ANALYSIS")
        if scan_mode_graphql_analysis:
            self.config.scan_mode.graphql_analysis = scan_mode_graphql_analysis.lower() == "true"
        scan_mode_grpc_analysis = os.getenv("SCAN_MODE_GRPC_ANALYSIS")
        if scan_mode_grpc_analysis:
            self.config.scan_mode.grpc_analysis = scan_mode_grpc_analysis.lower() == "true"
        scan_mode_ai_detection_enabled = os.getenv("SCAN_MODE_AI_DETECTION_ENABLED")
        if scan_mode_ai_detection_enabled:
            self.config.scan_mode.ai_detection_enabled = scan_mode_ai_detection_enabled.lower() == "true"
        
        # Application settings
        debug = os.getenv("DEBUG")
        if debug:
            self.config.debug = debug.lower() == "true"
        verbose = os.getenv("VERBOSE")
        if verbose:
            self.config.verbose = verbose.lower() == "true"
        app_name = os.getenv("APP_NAME")
        if app_name:
            self.config.app_name = app_name
    
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
        
        # Scan Mode settings
        env_content.append("# Scan Mode Configuration")
        env_content.append(f"SCAN_MODE={self.config.scan_mode.mode}")
        env_content.append(f"SCAN_MODE_ZAP_ENABLED={str(self.config.scan_mode.zap_enabled).lower()}")
        env_content.append(f"SCAN_MODE_SPIDER_DEPTH={self.config.scan_mode.spider_depth}")
        env_content.append(f"SCAN_MODE_SPIDER_CHILDREN={self.config.scan_mode.spider_children}")
        env_content.append(f"SCAN_MODE_MAX_SCAN_TIME={self.config.scan_mode.max_scan_time}")
        env_content.append(f"SCAN_MODE_REQUEST_DELAY={self.config.scan_mode.request_delay}")
        env_content.append(f"SCAN_MODE_CONCURRENT_REQUESTS={self.config.scan_mode.concurrent_requests}")
        env_content.append(f"SCAN_MODE_AGGRESSIVE={str(self.config.scan_mode.aggressive_scanning).lower()}")
        env_content.append(f"SCAN_MODE_STEALTH={str(self.config.scan_mode.stealth_mode).lower()}")
        if self.config.scan_mode.custom_user_agent:
            env_content.append(f"SCAN_MODE_CUSTOM_USER_AGENT={self.config.scan_mode.custom_user_agent}")
        env_content.append(f"SCAN_MODE_FOLLOW_REDIRECTS={str(self.config.scan_mode.follow_redirects).lower()}")
        env_content.append(f"SCAN_MODE_MAX_REDIRECTS={self.config.scan_mode.max_redirects}")
        env_content.append(f"SCAN_MODE_VERIFY_SSL={str(self.config.scan_mode.verify_ssl).lower()}")
        env_content.append(f"SCAN_MODE_TIMEOUT={self.config.scan_mode.timeout}")
        env_content.append(f"SCAN_MODE_RETRY_ATTEMPTS={self.config.scan_mode.retry_attempts}")
        env_content.append(f"SCAN_MODE_FUZZING_ENABLED={str(self.config.scan_mode.fuzzing_enabled).lower()}")
        env_content.append(f"SCAN_MODE_INJECTION_TESTS={str(self.config.scan_mode.injection_tests).lower()}")
        env_content.append(f"SCAN_MODE_AUTHENTICATION_TESTS={str(self.config.scan_mode.authentication_tests).lower()}")
        env_content.append(f"SCAN_MODE_RATE_LIMITING_TESTS={str(self.config.scan_mode.rate_limiting_tests).lower()}")
        env_content.append(f"SCAN_MODE_HEADERS_ANALYSIS={str(self.config.scan_mode.headers_analysis).lower()}")
        env_content.append(f"SCAN_MODE_CORS_ANALYSIS={str(self.config.scan_mode.cors_analysis).lower()}")
        env_content.append(f"SCAN_MODE_JWT_ANALYSIS={str(self.config.scan_mode.jwt_analysis).lower()}")
        env_content.append(f"SCAN_MODE_GRAPHQL_ANALYSIS={str(self.config.scan_mode.graphql_analysis).lower()}")
        env_content.append(f"SCAN_MODE_GRPC_ANALYSIS={str(self.config.scan_mode.grpc_analysis).lower()}")
        env_content.append(f"SCAN_MODE_AI_DETECTION_ENABLED={str(self.config.scan_mode.ai_detection_enabled).lower()}")
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
