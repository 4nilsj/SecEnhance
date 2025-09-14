"""
Enhanced Configuration Wizard for the API Security Scanner.
Provides guided setup and configuration management.
"""

import os
import json
import yaml
from typing import Dict, Any, List, Optional, Tuple
from pathlib import Path
from datetime import datetime

import click
from click import echo, secho, prompt, confirm, style


class ConfigurationWizard:
    """Enhanced configuration wizard with guided setup."""
    
    def __init__(self):
        self.config = {}
        self.current_step = 0
        self.total_steps = 8
        self.wizard_history = []
    
    def run_wizard(self, config_file: str = ".env") -> Dict[str, Any]:
        """Run the complete configuration wizard."""
        self._show_welcome()
        
        try:
            # Step 1: Basic Configuration
            self._step_basic_config()
            
            # Step 2: ZAP Configuration
            self._step_zap_config()
            
            # Step 3: Database Configuration
            self._step_database_config()
            
            # Step 4: Plugin Configuration
            self._step_plugin_config()
            
            # Step 5: Authentication Configuration
            self._step_auth_config()
            
            # Step 6: Reporting Configuration
            self._step_reporting_config()
            
            # Step 7: Advanced Options
            self._step_advanced_config()
            
            # Step 8: Review and Save
            self._step_review_and_save(config_file)
            
            return self.config
            
        except KeyboardInterrupt:
            echo("\n\n❌ Configuration wizard cancelled by user.")
            return {}
        except Exception as e:
            secho(f"\n❌ Error in configuration wizard: {e}", fg='red')
            return {}
    
    def _show_welcome(self):
        """Display welcome message."""
        echo("\n" + "="*80)
        secho("🔧 API Security Scanner - Configuration Wizard", fg='cyan', bold=True)
        echo("="*80)
        echo("Welcome to the configuration wizard!")
        echo("This wizard will guide you through setting up the API Security Scanner.")
        echo("You can press Ctrl+C at any time to cancel.")
        echo("="*80 + "\n")
        
        if not confirm("Do you want to continue with the configuration wizard?"):
            echo("Configuration wizard cancelled.")
            return {}
    
    def _step_basic_config(self):
        """Step 1: Basic configuration."""
        self.current_step += 1
        echo(f"\n📋 Step {self.current_step}/{self.total_steps}: Basic Configuration")
        echo("-" * 50)
        
        # Project name
        project_name = prompt(
            "Enter project name (for identification)",
            default="API Security Project"
        )
        self.config['project_name'] = project_name
        
        # Environment
        environment = click.prompt(
            "Select environment",
            type=click.Choice(['development', 'staging', 'production', 'testing']),
            default='development'
        )
        self.config['environment'] = environment
        
        # Log level
        log_level = click.prompt(
            "Select log level",
            type=click.Choice(['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']),
            default='INFO'
        )
        self.config['log_level'] = log_level
        
        # Log directory
        log_dir = prompt(
            "Enter log directory path",
            default="logs"
        )
        self.config['log_dir'] = log_dir
        
        self._record_step("Basic Configuration", {
            'project_name': project_name,
            'environment': environment,
            'log_level': log_level,
            'log_dir': log_dir
        })
    
    def _step_zap_config(self):
        """Step 2: ZAP configuration."""
        self.current_step += 1
        echo(f"\n🕷️  Step {self.current_step}/{self.total_steps}: ZAP Configuration")
        echo("-" * 50)
        
        # ZAP usage
        use_zap = confirm("Do you want to use OWASP ZAP for scanning?", default=True)
        self.config['use_zap'] = use_zap
        
        if use_zap:
            # ZAP host
            zap_host = prompt(
                "Enter ZAP host",
                default="localhost"
            )
            self.config['zap_host'] = zap_host
            
            # ZAP port
            zap_port = int(prompt(
                "Enter ZAP port",
                default="8080"
            ))
            self.config['zap_port'] = zap_port
            
            # External ZAP
            external_zap = confirm(
                "Are you using an external ZAP instance?",
                default=False
            )
            self.config['external_zap'] = external_zap
            
            if not external_zap:
                # ZAP path
                zap_path = prompt(
                    "Enter path to ZAP executable (or press Enter for auto-detection)",
                    default=""
                )
                self.config['zap_path'] = zap_path if zap_path else None
            
            # Spider configuration
            spider_depth = int(prompt(
                "Enter maximum spider depth",
                default="5"
            ))
            self.config['spider_depth'] = spider_depth
            
            spider_children = int(prompt(
                "Enter maximum children per spider node",
                default="10"
            ))
            self.config['spider_children'] = spider_children
        
        self._record_step("ZAP Configuration", {
            'use_zap': use_zap,
            'zap_host': self.config.get('zap_host'),
            'zap_port': self.config.get('zap_port'),
            'external_zap': self.config.get('external_zap'),
            'spider_depth': self.config.get('spider_depth'),
            'spider_children': self.config.get('spider_children')
        })
    
    def _step_database_config(self):
        """Step 3: Database configuration."""
        self.current_step += 1
        echo(f"\n🗄️  Step {self.current_step}/{self.total_steps}: Database Configuration")
        echo("-" * 50)
        
        # Database path
        db_path = prompt(
            "Enter database file path",
            default="scan_results.db"
        )
        self.config['database_path'] = db_path
        
        # Database backup
        auto_backup = confirm(
            "Enable automatic database backups?",
            default=True
        )
        self.config['auto_backup'] = auto_backup
        
        if auto_backup:
            backup_interval = int(prompt(
                "Enter backup interval (in days)",
                default="7"
            ))
            self.config['backup_interval'] = backup_interval
            
            backup_retention = int(prompt(
                "Enter backup retention period (in days)",
                default="30"
            ))
            self.config['backup_retention'] = backup_retention
        
        # Data retention
        data_retention = int(prompt(
            "Enter data retention period (in days, 0 for unlimited)",
            default="90"
        ))
        self.config['data_retention'] = data_retention
        
        self._record_step("Database Configuration", {
            'database_path': db_path,
            'auto_backup': auto_backup,
            'backup_interval': self.config.get('backup_interval'),
            'backup_retention': self.config.get('backup_retention'),
            'data_retention': data_retention
        })
    
    def _step_plugin_config(self):
        """Step 4: Plugin configuration."""
        self.current_step += 1
        echo(f"\n🔌 Step {self.current_step}/{self.total_steps}: Plugin Configuration")
        echo("-" * 50)
        
        # Plugin directory
        plugin_dir = prompt(
            "Enter plugin directory path",
            default="api_security_scanner/plugins"
        )
        self.config['plugin_dir'] = plugin_dir
        
        # Available plugins
        available_plugins = self._get_available_plugins()
        if available_plugins:
            echo(f"\nAvailable plugins ({len(available_plugins)}):")
            for i, plugin in enumerate(available_plugins, 1):
                echo(f"  {i}. {plugin['name']} - {plugin['description']}")
            
            if confirm("Do you want to select specific plugins?"):
                selected_indices = prompt(
                    "Enter plugin numbers (comma-separated, e.g., 1,3,5) or press Enter for all"
                )
                
                if selected_indices.strip():
                    try:
                        indices = [int(x.strip()) - 1 for x in selected_indices.split(',')]
                        selected_plugins = [available_plugins[i]['name'] for i in indices if 0 <= i < len(available_plugins)]
                        self.config['enabled_plugins'] = selected_plugins
                    except (ValueError, IndexError):
                        secho("Invalid selection. Using all plugins.", fg='yellow')
                        self.config['enabled_plugins'] = [plugin['name'] for plugin in available_plugins]
                else:
                    self.config['enabled_plugins'] = [plugin['name'] for plugin in available_plugins]
            else:
                self.config['enabled_plugins'] = [plugin['name'] for plugin in available_plugins]
        else:
            echo("No plugins found. Using default plugins.")
            self.config['enabled_plugins'] = ['SecurityHeadersChecker', 'CORSChecker']
        
        # Plugin timeout
        plugin_timeout = int(prompt(
            "Enter plugin execution timeout (in seconds)",
            default="300"
        ))
        self.config['plugin_timeout'] = plugin_timeout
        
        self._record_step("Plugin Configuration", {
            'plugin_dir': plugin_dir,
            'enabled_plugins': self.config['enabled_plugins'],
            'plugin_timeout': plugin_timeout
        })
    
    def _step_auth_config(self):
        """Step 5: Authentication configuration."""
        self.current_step += 1
        echo(f"\n🔐 Step {self.current_step}/{self.total_steps}: Authentication Configuration")
        echo("-" * 50)
        
        # Default auth type
        default_auth_type = click.prompt(
            "Select default authentication type",
            type=click.Choice(['none', 'header', 'cookie', 'token']),
            default='none'
        )
        self.config['default_auth_type'] = default_auth_type
        
        if default_auth_type != 'none':
            # Default auth name
            default_auth_name = prompt(
                "Enter default authentication parameter name",
                default="Authorization" if default_auth_type == 'header' else "token"
            )
            self.config['default_auth_name'] = default_auth_name
            
            # Default auth value (optional)
            if confirm("Do you want to set a default authentication value?"):
                default_auth_value = prompt(
                    "Enter default authentication value",
                    hide_input=True
                )
                self.config['default_auth_value'] = default_auth_value
        
        # Auth validation
        validate_auth = confirm(
            "Enable authentication validation before scanning?",
            default=True
        )
        self.config['validate_auth'] = validate_auth
        
        self._record_step("Authentication Configuration", {
            'default_auth_type': default_auth_type,
            'default_auth_name': self.config.get('default_auth_name'),
            'validate_auth': validate_auth
        })
    
    def _step_reporting_config(self):
        """Step 6: Reporting configuration."""
        self.current_step += 1
        echo(f"\n📊 Step {self.current_step}/{self.total_steps}: Reporting Configuration")
        echo("-" * 50)
        
        # Report directory
        report_dir = prompt(
            "Enter report output directory",
            default="reports"
        )
        self.config['report_dir'] = report_dir
        
        # Default report formats
        echo("\nSelect default report formats:")
        formats = ['html', 'json', 'pdf', 'excel', 'xml']
        selected_formats = []
        
        for fmt in formats:
            if confirm(f"Generate {fmt.upper()} reports by default?", default=fmt in ['html', 'json']):
                selected_formats.append(fmt)
        
        self.config['default_report_formats'] = selected_formats
        
        # Report template
        use_custom_template = confirm(
            "Do you want to use a custom report template?",
            default=False
        )
        if use_custom_template:
            template_path = prompt(
                "Enter path to custom template file",
                default="templates/custom_report_template.html"
            )
            self.config['custom_template'] = template_path
        
        # Report retention
        report_retention = int(prompt(
            "Enter report retention period (in days, 0 for unlimited)",
            default="30"
        ))
        self.config['report_retention'] = report_retention
        
        self._record_step("Reporting Configuration", {
            'report_dir': report_dir,
            'default_report_formats': selected_formats,
            'custom_template': self.config.get('custom_template'),
            'report_retention': report_retention
        })
    
    def _step_advanced_config(self):
        """Step 7: Advanced configuration."""
        self.current_step += 1
        echo(f"\n⚙️  Step {self.current_step}/{self.total_steps}: Advanced Configuration")
        echo("-" * 50)
        
        # Performance settings
        max_concurrent_requests = int(prompt(
            "Enter maximum concurrent requests",
            default="10"
        ))
        self.config['max_concurrent_requests'] = max_concurrent_requests
        
        request_timeout = int(prompt(
            "Enter request timeout (in seconds)",
            default="30"
        ))
        self.config['request_timeout'] = request_timeout
        
        # Scan limits
        max_scan_time = int(prompt(
            "Enter maximum scan time (in minutes, 0 for unlimited)",
            default="60"
        ))
        self.config['max_scan_time'] = max_scan_time
        
        # Verbose mode
        verbose_by_default = confirm(
            "Enable verbose mode by default?",
            default=False
        )
        self.config['verbose_by_default'] = verbose_by_default
        
        # Debug mode
        debug_mode = confirm(
            "Enable debug mode?",
            default=False
        )
        self.config['debug_mode'] = debug_mode
        
        # Notifications
        enable_notifications = confirm(
            "Enable scan completion notifications?",
            default=False
        )
        if enable_notifications:
            notification_webhook = prompt(
                "Enter webhook URL for notifications (optional)",
                default=""
            )
            if notification_webhook:
                self.config['notification_webhook'] = notification_webhook
        
        self._record_step("Advanced Configuration", {
            'max_concurrent_requests': max_concurrent_requests,
            'request_timeout': request_timeout,
            'max_scan_time': max_scan_time,
            'verbose_by_default': verbose_by_default,
            'debug_mode': debug_mode,
            'enable_notifications': enable_notifications,
            'notification_webhook': self.config.get('notification_webhook')
        })
    
    def _step_review_and_save(self, config_file: str):
        """Step 8: Review and save configuration."""
        self.current_step += 1
        echo(f"\n📋 Step {self.current_step}/{self.total_steps}: Review and Save")
        echo("-" * 50)
        
        # Display configuration summary
        self._display_config_summary()
        
        # Confirm configuration
        if not confirm("\nDo you want to save this configuration?"):
            echo("Configuration not saved.")
            return
        
        # Save configuration
        try:
            self._save_configuration(config_file)
            secho(f"\n✅ Configuration saved successfully to {config_file}!", fg='green')
            
            # Generate additional config files
            self._generate_additional_configs()
            
            # Show next steps
            self._show_next_steps()
            
        except Exception as e:
            secho(f"\n❌ Error saving configuration: {e}", fg='red')
    
    def _get_available_plugins(self) -> List[Dict[str, str]]:
        """Get list of available plugins."""
        try:
            plugins_dir = Path(self.config.get('plugin_dir', 'api_security_scanner/plugins'))
            if not plugins_dir.exists():
                return []
            
            plugins = []
            for plugin_file in plugins_dir.glob("*.py"):
                if plugin_file.name == "__init__.py":
                    continue
                
                # Extract basic plugin info
                plugin_name = plugin_file.stem.replace("_", "").title() + "Checker"
                plugins.append({
                    'name': plugin_name,
                    'description': f"Security checker for {plugin_file.stem.replace('_', ' ')}",
                    'file': str(plugin_file)
                })
            
            return plugins
        except Exception:
            return []
    
    def _record_step(self, step_name: str, step_data: Dict[str, Any]):
        """Record wizard step for history."""
        self.wizard_history.append({
            'step': self.current_step,
            'name': step_name,
            'data': step_data,
            'timestamp': datetime.now().isoformat()
        })
    
    def _display_config_summary(self):
        """Display configuration summary."""
        echo("\n📋 CONFIGURATION SUMMARY")
        echo("=" * 60)
        
        for step in self.wizard_history:
            echo(f"\n🔹 {step['name']}:")
            for key, value in step['data'].items():
                if key == 'default_auth_value' and value:
                    echo(f"   {key}: {'*' * len(str(value))}")
                else:
                    echo(f"   {key}: {value}")
    
    def _save_configuration(self, config_file: str):
        """Save configuration to file."""
        # Create .env format
        env_content = []
        env_content.append("# API Security Scanner Configuration")
        env_content.append(f"# Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        env_content.append("")
        
        # Map config to environment variables
        env_mapping = {
            'project_name': 'PROJECT_NAME',
            'environment': 'ENVIRONMENT',
            'log_level': 'LOG_LEVEL',
            'log_dir': 'LOG_DIR',
            'use_zap': 'USE_ZAP',
            'zap_host': 'ZAP_HOST',
            'zap_port': 'ZAP_PORT',
            'external_zap': 'EXTERNAL_ZAP',
            'zap_path': 'ZAP_PATH',
            'spider_depth': 'SPIDER_DEPTH',
            'spider_children': 'SPIDER_CHILDREN',
            'database_path': 'DATABASE_PATH',
            'auto_backup': 'AUTO_BACKUP',
            'backup_interval': 'BACKUP_INTERVAL',
            'backup_retention': 'BACKUP_RETENTION',
            'data_retention': 'DATA_RETENTION',
            'plugin_dir': 'PLUGIN_DIR',
            'enabled_plugins': 'ENABLED_PLUGINS',
            'plugin_timeout': 'PLUGIN_TIMEOUT',
            'default_auth_type': 'DEFAULT_AUTH_TYPE',
            'default_auth_name': 'DEFAULT_AUTH_NAME',
            'default_auth_value': 'DEFAULT_AUTH_VALUE',
            'validate_auth': 'VALIDATE_AUTH',
            'report_dir': 'REPORT_DIR',
            'default_report_formats': 'DEFAULT_REPORT_FORMATS',
            'custom_template': 'CUSTOM_TEMPLATE',
            'report_retention': 'REPORT_RETENTION',
            'max_concurrent_requests': 'MAX_CONCURRENT_REQUESTS',
            'request_timeout': 'REQUEST_TIMEOUT',
            'max_scan_time': 'MAX_SCAN_TIME',
            'verbose_by_default': 'VERBOSE_BY_DEFAULT',
            'debug_mode': 'DEBUG_MODE',
            'enable_notifications': 'ENABLE_NOTIFICATIONS',
            'notification_webhook': 'NOTIFICATION_WEBHOOK'
        }
        
        for config_key, env_key in env_mapping.items():
            if config_key in self.config:
                value = self.config[config_key]
                if isinstance(value, list):
                    value = ','.join(str(v) for v in value)
                elif isinstance(value, bool):
                    value = 'true' if value else 'false'
                env_content.append(f"{env_key}={value}")
        
        # Write to file
        with open(config_file, 'w') as f:
            f.write('\n'.join(env_content))
    
    def _generate_additional_configs(self):
        """Generate additional configuration files."""
        # Generate YAML config
        yaml_config = {
            'api_security_scanner': self.config,
            'metadata': {
                'generated_by': 'Configuration Wizard',
                'generated_at': datetime.now().isoformat(),
                'version': '1.0.0'
            }
        }
        
        with open('config.yaml', 'w') as f:
            yaml.dump(yaml_config, f, default_flow_style=False, indent=2)
        
        # Generate JSON config
        json_config = {
            'api_security_scanner': self.config,
            'metadata': {
                'generated_by': 'Configuration Wizard',
                'generated_at': datetime.now().isoformat(),
                'version': '1.0.0'
            }
        }
        
        with open('config.json', 'w') as f:
            json.dump(json_config, f, indent=2)
        
        echo("📁 Additional configuration files generated:")
        echo("  - config.yaml (YAML format)")
        echo("  - config.json (JSON format)")
    
    def _show_next_steps(self):
        """Show next steps after configuration."""
        echo("\n🚀 NEXT STEPS")
        echo("=" * 40)
        echo("1. Test your configuration:")
        echo("   python main.py config --show-config")
        echo("")
        echo("2. Run a quick test scan:")
        echo("   python main.py scan -f examples/test_collection.json --template quick")
        echo("")
        echo("3. Check available plugins:")
        echo("   python main.py plugins")
        echo("")
        echo("4. View scan templates:")
        echo("   python main.py templates")
        echo("")
        echo("5. Get help:")
        echo("   python main.py --help")
        echo("")
        secho("🎉 Configuration complete! You're ready to start scanning.", fg='green', bold=True)


def run_configuration_wizard(config_file: str = ".env") -> Dict[str, Any]:
    """Run the configuration wizard."""
    wizard = ConfigurationWizard()
    return wizard.run_wizard(config_file)


if __name__ == "__main__":
    run_configuration_wizard()
