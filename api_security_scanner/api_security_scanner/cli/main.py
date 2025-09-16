"""
Command-line interface for the API Security Scanner.
Provides a comprehensive CLI using the click library with enhanced user experience.
"""

import sys
import uuid
import warnings
import logging
import json
import os
import signal
import threading
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any
import time

import click
from click import echo, secho, prompt, confirm, style
from tqdm import tqdm

# Suppress all warnings by default
warnings.filterwarnings('ignore')

# Suppress urllib3 warnings
try:
    from urllib3.exceptions import InsecureRequestWarning
    warnings.filterwarnings('ignore', category=InsecureRequestWarning)
except ImportError:
    pass

from ..utils.logger import setup_logging, get_logger
from ..utils.input_parsers import parse_input, InputParserError
from ..utils.auth_handler import create_auth_handler, AuthenticationError
from ..utils.autocomplete import AutocompleteManager, generate_autocomplete_files
from ..utils.config_wizard import run_configuration_wizard
from ..core.db_manager import DatabaseManager, ReportManager
from ..core.zap_manager import ZAPManager, ZAPManagerError
from ..core.scanner_plugins import PluginManager
from ..core.report_generator import ReportGenerator
from ..core.config import get_config_manager, get_config
from ..core.scan_mode_manager import ScanModeManager

# Global scan cancellation state
_scan_cancellation_requested = False
_scan_components = {}  # Store references to ZAPManager and PluginManager


def _signal_handler(signum, frame):
    """Handle SIGINT (Ctrl+C) for graceful scan cancellation."""
    global _scan_cancellation_requested
    
    echo("\n🛑 Scan cancellation requested...")
    _scan_cancellation_requested = True
    
    # Request cancellation from all scan components
    if 'zap_manager' in _scan_components:
        _scan_components['zap_manager'].request_cancellation()
    
    if 'plugin_manager' in _scan_components:
        _scan_components['plugin_manager'].request_cancellation()
    
    echo("⏳ Gracefully stopping scans... (Press Ctrl+C again to force exit)")


class UnifiedScanProgress:
    """Unified progress bar for entire scan operation."""
    
    def __init__(self, disable: bool = False):
        self.pbar = None
        self.disable = disable
        self.start_time = time.time()
        self.current_phase = 0
        self.total_phases = 6  # Total number of scan phases
        
        # Define scan phases
        self.phases = [
            "Initializing scan",
            "Parsing input data", 
            "Setting up authentication",
            "Initializing database",
            "Loading security plugins",
            "Executing security checks"
        ]
    
    def __enter__(self):
        if not self.disable:
            self.pbar = tqdm(
                total=self.total_phases,
                desc="API Security Scan",
                unit="phase",
                bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}] {desc}',
                disable=self.disable,
                ncols=80
            )
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.pbar:
            self.pbar.close()
    
    def start_phase(self, phase_name: Optional[str] = None):
        """Start a new phase of the scan."""
        if self.pbar and self.current_phase < self.total_phases:
            if phase_name:
                self.pbar.set_description(f"API Security Scan - {phase_name}")
            else:
                self.pbar.set_description(f"API Security Scan - {self.phases[self.current_phase]}")
            self.pbar.update(1)
            self.current_phase += 1
        elif self.disable and phase_name:
            print(f"→ {phase_name}")
    
    def update_plugin_progress(self, plugin_name: str, vulnerabilities_found: int):
        """Update progress during plugin execution."""
        if self.pbar:
            self.pbar.set_description(f"API Security Scan - {plugin_name}: {vulnerabilities_found} issues found")
        elif self.disable:
            print(f"  ✓ {plugin_name}: {vulnerabilities_found} vulnerabilities found")
    
    def finish(self):
        """Finish the progress bar."""
        if self.pbar:
            self.pbar.set_description("API Security Scan - Complete")
            self.pbar.close()
        elif self.disable:
            print("✓ Scan completed successfully")


@click.group()
@click.option('-v', '--verbose', count=True, help='Increase verbosity (use -v for INFO, -vv for DEBUG)')
@click.option('--log-dir', default='logs', help='Directory for log files')
@click.option('--interactive', '-i', is_flag=True, help='Enable interactive mode for guided setup')
@click.pass_context
def cli(ctx, verbose, log_dir, interactive):
    """🔒 API Security Scanner - Automated security testing for APIs.
    
    A comprehensive tool for testing API security using OWASP ZAP and custom plugins.
    
    Examples:
      # Quick scan with Postman collection
      python main.py scan -f collection.json
      
      # ZAP scan with specific mode
      python main.py scan -f collection.json --scan-mode safe
      
      # Plugin-only scan (no ZAP)
      python main.py scan -f collection.json --no-zap
      
      # Interactive guided scan
      python main.py --interactive scan
      
      # Scan with specific plugins only
      python main.py scan -f collection.json --plugins JWTSecurityChecker,SecurityHeadersChecker
      
      # Generate multiple report formats
      python main.py scan -f collection.json --export-pdf report.pdf --export-excel report.xlsx
    """
    # Ensure context object exists
    ctx.ensure_object(dict)
    
    # Suppress all logging output if not in verbose mode
    if verbose == 0:
        # Disable root logger completely
        logging.getLogger().setLevel(logging.CRITICAL + 1)
        # Disable specific loggers
        logging.getLogger('api_security_scanner').setLevel(logging.CRITICAL + 1)
        logging.getLogger('urllib3').setLevel(logging.CRITICAL + 1)
        logging.getLogger('requests').setLevel(logging.CRITICAL + 1)
    
    # Setup logging
    logger_instance = setup_logging(verbose=verbose, log_dir=log_dir)
    ctx.obj['logger'] = logger_instance.get_logger()
    ctx.obj['verbose'] = verbose
    ctx.obj['log_dir'] = log_dir
    ctx.obj['interactive'] = interactive
    
    # Show welcome message in interactive mode
    if interactive:
        _show_welcome_message()


@cli.command()
@click.option('--env-file', default='.env', help='Path to .env configuration file')
@click.option('--save-config', is_flag=True, help='Save current configuration to .env file')
@click.option('--show-config', is_flag=True, help='Show current configuration and exit')
@click.option('--wizard', is_flag=True, help='Run interactive configuration wizard')
@click.option('--validate', is_flag=True, help='Validate current configuration')
@click.pass_context
def config(ctx, env_file: str, save_config: bool, show_config: bool, wizard: bool, validate: bool):
    """⚙️ Configuration management commands."""
    config_manager = get_config_manager(env_file)
    config = config_manager.get_config()
    
    if wizard:
        # Use the new enhanced configuration wizard
        run_configuration_wizard(env_file)
        return
    
    if show_config:
        echo("Current Configuration:")
        echo(f"  Database Path: {config.database.path}")
        echo(f"  ZAP Host: {config.zap.host}")
        echo(f"  ZAP Port: {config.zap.port}")
        echo(f"  ZAP External: {config.zap.external_zap}")
        echo(f"  Log Level: {config.logging.level}")
        echo(f"  Log Directory: {config.logging.log_dir}")
        echo(f"  Report Directory: {config.report.output_dir}")
        echo(f"  Enabled Plugins: {', '.join(config.plugin.enabled_plugins)}")
        echo(f"  Debug Mode: {config.debug}")
        echo(f"  Verbose Mode: {config.verbose}")
        return
    
    if save_config:
        config_manager.save_to_env(env_file)
        echo(f"Configuration saved to {env_file}")
        return
    
    if validate:
        # Validate configuration
        validation = config_manager.validate_config()
        if validation['valid']:
            secho("✅ Configuration is valid", fg='green')
        else:
            secho("❌ Configuration issues found:", fg='red')
            for issue in validation['issues']:
                echo(f"  - {issue}")
        return
    
    # Default: validate configuration
    validation = config_manager.validate_config()
    if validation['valid']:
        echo("Configuration is valid")
    else:
        echo("Configuration issues found:")
        for issue in validation['issues']:
            echo(f"  - {issue}")


@cli.command()
@click.option('-f', '--file', 'input_file', help='Path to Postman Collection, OpenAPI spec, or HAR file')
@click.option('-u', '--curl', 'curl_command', help='Curl command string to parse')
@click.option('-a', '--auth-type', type=click.Choice(['header', 'cookie', 'token']), 
              help='Authentication type')
@click.option('-n', '--auth-name', help='Authentication parameter name (header name, cookie name, etc.)')
@click.option('-v', '--auth-value', help='Authentication parameter value')
@click.option('--zap-path', help='Path to ZAP executable (auto-detected if not specified)')
@click.option('--zap-port', default=8080, help='ZAP proxy port')
@click.option('--zap-host', default='localhost', help='ZAP proxy host')
@click.option('--db-path', default='scan_results.db', help='SQLite database path')
@click.option('--export', help='Export report to HTML file')
@click.option('--export-json', help='Export report to JSON file')
@click.option('--export-pdf', help='Export report to PDF file')
@click.option('--export-excel', help='Export report to Excel file')
@click.option('--export-xml', help='Export report to XML file')
@click.option('--performance-stats', is_flag=True, help='Show detailed performance statistics')
@click.option('--no-zap', is_flag=True, help='Skip ZAP scanning (custom plugins only)')
@click.option('--no-plugins', is_flag=True, help='Skip custom plugin scanning (ZAP only)')
@click.option('--plugins', help='Comma-separated list of specific plugins to run (e.g., "SecurityHeadersChecker,JWTSecurityChecker")')
@click.option('--spider-depth', default=5, help='Maximum spider depth')
@click.option('--spider-children', default=10, help='Maximum children per spider node')
@click.option('--max-scan-time', type=int, help='Maximum scan time in minutes (time-bound scanning)')
@click.option('--no-progress', is_flag=True, help='Disable progress bars (useful for verbose output)')
@click.option('--template', help='Use predefined scan template (quick, comprehensive, jwt-focused)')
@click.option('--scan-mode', type=click.Choice(['safe', 'attack', 'spidering', 'comprehensive', 'stealth', 'aggressive', 'quick', 'api-focused']), 
              help='Select scan mode for ZAP scanning only (optional)')
@click.option('--ai-detection/--no-ai-detection', default=True, help='Enable/disable AI-powered vulnerability detection')
@click.option('--ai-anomaly-detection/--no-ai-anomaly-detection', default=True, help='Enable/disable AI anomaly detection')
@click.option('--ai-vulnerability-classification/--no-ai-vulnerability-classification', default=True, help='Enable/disable AI vulnerability classification')
@click.option('--ai-risk-scoring/--no-ai-risk-scoring', default=True, help='Enable/disable AI risk scoring')
@click.option('--ai-intelligent-fuzzing/--no-ai-intelligent-fuzzing', default=True, help='Enable/disable AI intelligent fuzzing suggestions')
@click.option('--ai-learning/--no-ai-learning', default=True, help='Enable/disable AI learning from scan results')
@click.pass_context
def scan(ctx, input_file, curl_command, auth_type, auth_name, auth_value, 
         zap_path, zap_port, zap_host, db_path, export, export_json, export_pdf, 
         export_excel, export_xml, performance_stats, no_zap, no_plugins, plugins,
         spider_depth, spider_children, max_scan_time, no_progress, template,
         scan_mode, ai_detection, ai_anomaly_detection, ai_vulnerability_classification,
         ai_risk_scoring, ai_intelligent_fuzzing, ai_learning):
    """🔍 Perform security scan on API endpoints.
    
    This command performs comprehensive security testing on your API endpoints
    using OWASP ZAP and custom security plugins. Scan modes are optional and
    only apply to ZAP scanning.
    
    🛑 SCAN CANCELLATION:
      Press Ctrl+C to gracefully cancel a running scan. The scanner will:
      - Stop ZAP spider and active scans
      - Cancel custom plugin execution
      - Update database with 'cancelled' status
      - Clean up resources and exit gracefully
    
    Examples:
      # ZAP scan with safe mode for production environments
      python main.py scan -f collection.json --scan-mode safe
      
      # ZAP scan with aggressive penetration testing
      python main.py scan -f collection.json --scan-mode attack
      
      # Plugin-only scan (no ZAP, no scan mode)
      python main.py scan -f collection.json --no-zap
      
      # Interactive guided scan
      python main.py --interactive scan
      
      # Use predefined template
      python main.py scan -f collection.json --template quick
      
      # Scan with specific plugins only
      python main.py scan -f collection.json --plugins JWTSecurityChecker
      
      # List available scan modes
      python main.py scan-modes
    """
    logger = ctx.obj['logger']
    interactive_mode = ctx.obj.get('interactive', False)
    
    # Set up signal handling for graceful scan cancellation
    global _scan_cancellation_requested, _scan_components
    _scan_cancellation_requested = False
    _scan_components.clear()
    
    # Register signal handler for SIGINT (Ctrl+C)
    original_sigint = signal.signal(signal.SIGINT, _signal_handler)
    
    try:
        # Handle interactive mode
        if interactive_mode:
            interactive_config = _interactive_scan_setup()
            # Merge interactive config with command line options
            for key, value in interactive_config.items():
                if key not in locals() or locals()[key] is None:
                    locals()[key] = value
        
        # Handle scan templates
        if template:
            template_config = _get_scan_template(template)
            if template_config:
                # Apply template configuration
                for key, value in template_config.items():
                    if key not in locals() or locals()[key] is None:
                        locals()[key] = value
        
        # Handle scan mode configuration (ZAP only)
        scan_mode_manager = ScanModeManager()
        mode_config = None
        if scan_mode and not no_zap:
            mode_config = scan_mode_manager.get_scan_mode_config(scan_mode)
            if mode_config:
                # Apply scan mode configuration only to ZAP settings
                if spider_depth == 5:  # Only override if using default
                    spider_depth = mode_config.spider_depth
                if spider_children == 10:  # Only override if using default
                    spider_children = mode_config.spider_children
                if max_scan_time is None:
                    max_scan_time = mode_config.max_scan_time // 60  # Convert to minutes
                
                # Display scan mode information
                mode_info = scan_mode_manager.get_mode_info(scan_mode)
                if mode_info:
                    echo(f"\n🎯 ZAP Scan Mode: {mode_info.name}")
                    echo(f"   Description: {mode_info.description}")
                    echo(f"   Use Case: {mode_info.use_case}")
                    echo(f"   Duration: {mode_info.duration}")
                    echo(f"   Risk Level: {mode_info.risk_level}")
                    echo()
        elif scan_mode and no_zap:
            echo(f"\n⚠️  Warning: Scan mode '{scan_mode}' specified but ZAP scanning is disabled (--no-zap)")
            echo("   Scan modes only apply to ZAP scanning. Plugin scanning will use default settings.")
            echo()
        
        # Validate input
        if not input_file and not curl_command:
            _handle_error(
                "Either --file or --curl must be specified",
                "Input Required"
            )
        
        # Validate plugin selection
        selected_plugins = None
        if plugins:
            if no_plugins:
                _handle_error(
                    "Cannot use --plugins with --no-plugins",
                    "Conflicting Options"
                )
            selected_plugins = [p.strip() for p in plugins.split(',') if p.strip()]
            if not selected_plugins:
                _handle_error(
                    "--plugins must contain at least one plugin name",
                    "Invalid Plugin Selection"
                )
        
        if input_file and curl_command:
            _handle_error(
                "Cannot specify both --file and --curl",
                "Conflicting Input Options"
            )
        
        # Generate scan ID
        scan_id = str(uuid.uuid4())[:8]
        logger.info(f"Starting scan with ID: {scan_id}")
        
        # Use unified progress bar
        with UnifiedScanProgress(disable=no_progress or ctx.obj.get('verbose', 0) > 0) as progress:
            # Phase 1: Parse input
            progress.start_phase("Parsing input data")
            try:
                if input_file:
                    requests_data = parse_input(input_file)
                    input_type = "file"
                    input_source = input_file
                else:
                    requests_data = parse_input(curl_command)
                    input_type = "curl"
                    input_source = curl_command
            except InputParserError as e:
                _handle_error(
                    f"Input parsing error: {e}",
                    "Input Parsing Failed"
                )
            
            # Phase 2: Setup authentication
            progress.start_phase("Setting up authentication")
            auth_handler = None
            if auth_type and auth_name and auth_value:
                try:
                    auth_handler = create_auth_handler(auth_type, auth_name, auth_value)
                except AuthenticationError as e:
                    _handle_error(
                        f"Authentication error: {e}",
                        "Authentication Failed"
                    )
            
            # Apply authentication to requests
            if auth_handler:
                requests_data = auth_handler.apply_authentication(requests_data)
            
            # Phase 3: Initialize database
            progress.start_phase("Initializing database")
            db_manager = DatabaseManager(db_path)
            
            # Extract target URL from first request
            target_url = requests_data[0]['url'] if requests_data else 'unknown'
            
            # Display scan banner
            _display_scan_banner(scan_id, target_url, scan_mode, no_zap, no_plugins)
            
            # Create scan record
            plugins_used_str = ','.join(selected_plugins) if selected_plugins else None
            db_manager.create_scan(
                scan_id=scan_id,
                target_url=target_url,
                input_type=input_type,
                input_source=input_source,
                auth_type=auth_type,
                plugins_used=plugins_used_str,
                template_used=template,
                scan_mode=scan_mode
            )
            
            # Phase 4: Initialize components
            progress.start_phase("Loading security plugins")
            zap_manager = None
            plugin_manager = None
            
            if not no_zap:
                # Prepare scan mode configuration for ZAP
                scan_mode_config = None
                if mode_config:
                    scan_mode_config = {
                        'spider_depth': mode_config.spider_depth,
                        'spider_children': mode_config.spider_children,
                        'max_scan_time': mode_config.max_scan_time,
                        'request_delay': mode_config.request_delay,
                        'concurrent_requests': mode_config.concurrent_requests,
                        'aggressive_scanning': mode_config.aggressive_scanning,
                        'stealth_mode': mode_config.stealth_mode,
                        'custom_user_agent': mode_config.custom_user_agent,
                        'timeout': mode_config.timeout
                    }
                
                zap_manager = ZAPManager(zap_path, zap_port, zap_host, api_key=None, scan_mode_config=scan_mode_config)
                _scan_components['zap_manager'] = zap_manager
            
            if not no_plugins:
                # Configure AI detection settings
                ai_config = {
                    'enabled': ai_detection,
                    'models': {
                        'anomaly_detection': {
                            'enabled': ai_anomaly_detection,
                            'threshold': 0.7,
                            'contamination': 0.1
                        },
                        'vulnerability_classification': {
                            'enabled': ai_vulnerability_classification,
                            'threshold': 0.8,
                            'min_samples': 10
                        },
                        'risk_scoring': {
                            'enabled': ai_risk_scoring,
                            'weights': {
                                'endpoint_complexity': 0.3,
                                'parameter_count': 0.2,
                                'authentication': 0.3,
                                'data_sensitivity': 0.2
                            }
                        },
                        'intelligent_fuzzing': {
                            'enabled': ai_intelligent_fuzzing,
                            'max_suggestions': 50,
                            'confidence_threshold': 0.6
                        }
                    },
                    'learning': {
                        'enabled': ai_learning,
                        'auto_retrain': True,
                        'retrain_interval': 100,
                        'min_training_samples': 50
                    },
                    'fallback_to_rules': True
                }
                
                plugin_manager = PluginManager("api_security_scanner/plugins", selected_plugins=selected_plugins, ai_config=ai_config)
                _scan_components['plugin_manager'] = plugin_manager
            
            # Phase 5: Execute security checks
            progress.start_phase("Executing security checks")
            
            # Start ZAP scanning
            zap_alerts = []
            if zap_manager and not no_zap and not _scan_cancellation_requested:
                try:
                    with zap_manager:
                        # Spider target
                        spider_success, spider_id = zap_manager.spider_target(
                            target_url, spider_depth, spider_children
                        )
                        
                        if spider_success:
                            # Active scan
                            scan_success, scan_id_zap = zap_manager.active_scan_target(target_url)
                            
                            if scan_success:
                                # Get alerts
                                zap_alerts = zap_manager.get_alerts(target_url)
                                
                                # Store ZAP alerts in database
                                for alert in zap_alerts:
                                    db_manager.add_zap_alert(scan_id, alert)
                                
                        else:
                            logger.warning("ZAP spidering failed")
                            
                except ZAPManagerError as e:
                    secho(f"⚠️  ZAP error: {e}", fg='yellow')
                    logger.error(f"ZAP operation failed: {e}")
                    echo("Continuing with custom plugins only...")
            
            # Run custom plugins
            custom_alerts = []
            if plugin_manager and not no_plugins and not _scan_cancellation_requested:
                try:
                    plugin_results = plugin_manager.execute_all_plugins(
                        target_url, requests_data, 
                        auth_handler.get_auth_headers() if auth_handler else None
                    )
                    
                    for result in plugin_results:
                        if result.success:
                            for vulnerability in result.vulnerabilities:
                                # Store custom alert in database
                                db_manager.add_custom_alert(
                                    scan_id=scan_id,
                                    plugin_name=result.plugin_name,
                                    vulnerability_type=vulnerability.name,
                                    severity=vulnerability.risk,
                                    title=vulnerability.name,
                                    description=vulnerability.description,
                                    evidence=vulnerability.evidence or '',
                                    recommendation=vulnerability.solution or '',
                                    url=vulnerability.url,
                                    method='GET',  # Default method
                                    headers={},
                                    response_code=200,  # Default response code
                                    response_body=vulnerability.response
                                )
                                custom_alerts.append(vulnerability.__dict__)
                            
                            # Update progress with plugin results
                            progress.update_plugin_progress(result.plugin_name, len(result.vulnerabilities))
                        else:
                            logger.warning(f"Plugin {result.plugin_name} failed: {result.error}")
                    
                except Exception as e:
                    secho(f"⚠️  Plugin execution error: {e}", fg='yellow')
                    logger.error(f"Plugin execution failed: {e}")
                    echo("Continuing with remaining plugins...")
            
            # Update scan completion
            db_manager.update_scan_completion(scan_id, 'completed')
            
            # Get scan summary
            scan_summary = db_manager.get_scan_summary(scan_id)
            if not scan_summary:
                secho("Failed to retrieve scan summary", fg='red')
                sys.exit(1)
            
            # Finish progress bar
            progress.finish()
        
        # Display results
        # Display issues summary
        _display_issues_summary(zap_alerts, custom_alerts)
        
        # Display completion banner
        scan_duration = scan_summary['scan'].get('total_duration', 0)
        total_vulnerabilities = len(zap_alerts) + len(custom_alerts)
        _display_scan_completion_banner(
            scan_id, 
            total_vulnerabilities, 
            len(zap_alerts), 
            len(custom_alerts), 
            scan_duration, 
            True  # Reports will be generated next
        )
        
        # Show performance stats if requested
        if performance_stats and scan_summary.get('performance_stats'):
            echo("\nPERFORMANCE STATISTICS:")
            for stat in scan_summary['performance_stats']:
                echo(f"  {stat['phase_name']}: {stat['duration']:.2f}s")
        
        # Generate reports automatically
        progress.start_phase("Generating reports")
        
        # Create reports directory if it doesn't exist
        reports_dir = Path("reports")
        reports_dir.mkdir(exist_ok=True)
        
        # Generate default reports with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        default_html_report = reports_dir / f"scan_report_{scan_id}_{timestamp}.html"
        default_json_report = reports_dir / f"scan_report_{scan_id}_{timestamp}.json"
        
        report_generator = ReportGenerator()
        
        # Combine zap_alerts and custom_alerts into vulnerabilities list
        all_vulnerabilities = []
        
        # Add ZAP alerts
        for alert in zap_alerts:
            all_vulnerabilities.append(alert)
        
        # Add custom plugin alerts
        for alert in custom_alerts:
            all_vulnerabilities.append(alert)
        
        # Generate HTML report
        html_success = report_generator.generate_report(
            scan_summary['scan'],
            all_vulnerabilities,
            scan_summary.get('performance_stats', []),
            str(default_html_report),
            requests_data
        )
        
        # Generate JSON report
        json_success = report_generator.generate_json_report(
            scan_summary['scan'],
            all_vulnerabilities,
            scan_summary.get('performance_stats', []),
            str(default_json_report)
        )
        
        # Generate custom reports if specified
        if export or export_json or export_pdf or export_excel or export_xml:
            if export:
                # Ensure export path is in reports folder
                export_path = Path(export)
                if not export_path.is_absolute() and not str(export_path).startswith('reports/'):
                    export_path = reports_dir / export_path.name
                else:
                    export_path = Path(export)
                
                custom_html_success = report_generator.generate_report(
                    scan_summary['scan'],
                    all_vulnerabilities,
                    scan_summary.get('performance_stats', []),
                    str(export_path),
                    requests_data
                )
                if custom_html_success:
                    echo(f"Custom HTML report saved to: {export_path}")
                else:
                    secho("Failed to generate custom HTML report", fg='red')
            
            if export_json:
                # Ensure export path is in reports folder
                export_json_path = Path(export_json)
                if not export_json_path.is_absolute() and not str(export_json_path).startswith('reports/'):
                    export_json_path = reports_dir / export_json_path.name
                else:
                    export_json_path = Path(export_json)
                
                custom_json_success = report_generator.generate_json_report(
                    scan_summary['scan'],
                    all_vulnerabilities,
                    scan_summary.get('performance_stats', []),
                    str(export_json_path)
                )
                if custom_json_success:
                    echo(f"Custom JSON report saved to: {export_json_path}")
                else:
                    secho("Failed to generate custom JSON report", fg='red')
            
            # Generate PDF report if requested
            if export_pdf:
                export_pdf_path = Path(export_pdf)
                if not export_pdf_path.is_absolute() and not str(export_pdf_path).startswith('reports/'):
                    export_pdf_path = reports_dir / export_pdf_path.name
                else:
                    export_pdf_path = Path(export_pdf)
                
                pdf_success = report_generator.generate_pdf_report(
                    scan_summary['scan'],
                    all_vulnerabilities,
                    scan_summary.get('performance_stats', []),
                    str(export_pdf_path)
                )
                if pdf_success:
                    echo(f"PDF report saved to: {export_pdf_path}")
                else:
                    secho("Failed to generate PDF report", fg='red')
            
            # Generate Excel report if requested
            if export_excel:
                export_excel_path = Path(export_excel)
                if not export_excel_path.is_absolute() and not str(export_excel_path).startswith('reports/'):
                    export_excel_path = reports_dir / export_excel_path.name
                else:
                    export_excel_path = Path(export_excel)
                
                excel_success = report_generator.generate_excel_report(
                    scan_summary['scan'],
                    all_vulnerabilities,
                    scan_summary.get('performance_stats', []),
                    str(export_excel_path)
                )
                if excel_success:
                    echo(f"Excel report saved to: {export_excel_path}")
                else:
                    secho("Failed to generate Excel report", fg='red')
            
            # Generate XML report if requested
            if export_xml:
                export_xml_path = Path(export_xml)
                if not export_xml_path.is_absolute() and not str(export_xml_path).startswith('reports/'):
                    export_xml_path = reports_dir / export_xml_path.name
                else:
                    export_xml_path = Path(export_xml)
                
                xml_success = report_generator.generate_xml_report(
                    scan_summary['scan'],
                    all_vulnerabilities,
                    scan_summary.get('performance_stats', []),
                    str(export_xml_path)
                )
                if xml_success:
                    echo(f"XML report saved to: {export_xml_path}")
                else:
                    secho("Failed to generate XML report", fg='red')
        
        # Display report information
        if html_success and json_success:
            echo(f"\n📊 Reports generated successfully:")
            echo(f"  HTML Report: {default_html_report}")
            echo(f"  JSON Report: {default_json_report}")
        else:
            secho("⚠️  Some reports failed to generate", fg='yellow')
        
        echo("\nScan completed successfully!")
        
    except KeyboardInterrupt:
        echo("\nScan interrupted by user", err=True)
        if 'scan_id' in locals():
            # Try to get partial results for cancellation banner
            try:
                scan_summary = db_manager.get_scan_summary(scan_id)
                if scan_summary:
                    zap_alerts = scan_summary.get('zap_alerts', [])
                    custom_alerts = scan_summary.get('custom_alerts', [])
                    scan_duration = scan_summary['scan'].get('total_duration', 0)
                    total_vulnerabilities = len(zap_alerts) + len(custom_alerts)
                    
                    _display_scan_cancellation_banner(
                        scan_id, 
                        total_vulnerabilities, 
                        len(zap_alerts), 
                        len(custom_alerts), 
                        scan_duration
                    )
            except:
                # If we can't get partial results, just show basic cancellation
                echo(f"\n🛑 Scan {scan_id} cancelled by user")
            
            db_manager.update_scan_completion(scan_id, 'cancelled', 'Cancelled by user')
        sys.exit(0)
    except Exception as e:
        secho(f"Unexpected error: {e}", fg='red')
        logger.error(f"Unexpected error during scan: {e}", exc_info=True)
        if 'scan_id' in locals():
            db_manager.update_scan_completion(scan_id, 'failed', str(e))
        sys.exit(1)
    finally:
        # Restore original signal handler and cleanup
        signal.signal(signal.SIGINT, original_sigint)
        _scan_components.clear()
        
        # Handle scan cancellation
        if _scan_cancellation_requested:
            echo("\n🛑 Scan cancelled by user")
            if 'scan_id' in locals():
                db_manager.update_scan_completion(scan_id, 'cancelled', 'Cancelled by user')
            sys.exit(0)


@cli.command()
@click.option('--db-path', default='scan_results.db', help='SQLite database path')
@click.option('--limit', default=10, help='Number of scans to show')
@click.pass_context
def list_scans(ctx, db_path, limit):
    """List recent scans."""
    try:
        db_manager = DatabaseManager(db_path)
        scans = db_manager.get_all_scans(limit)
        
        if not scans:
            echo("No scans found")
            return
        
        echo(f"Recent scans (showing {len(scans)} of {limit}):")
        echo("-" * 80)
        echo(f"{'Scan ID':<10} {'Target':<30} {'Status':<12} {'Duration':<10} {'Start Time'}")
        echo("-" * 80)
        
        for scan in scans:
            duration = f"{scan['total_duration']:.1f}s" if scan['total_duration'] else 'N/A'
            start_time = scan['start_time'][:19] if scan['start_time'] else 'N/A'
            target = scan['target_url'][:28] + '..' if len(scan['target_url']) > 30 else scan['target_url']
            
            echo(f"{scan['scan_id']:<10} {target:<30} {scan['status']:<12} {duration:<10} {start_time}")
            
    except Exception as e:
        secho(f"Error listing scans: {e}", fg='red')
        sys.exit(1)


@cli.command()
@click.argument('scan_id')
@click.option('--db-path', default='scan_results.db', help='SQLite database path')
@click.option('--export', help='Export detailed report to HTML file')
@click.pass_context
def show_scan(ctx, scan_id, db_path, export):
    """Show details of a specific scan."""
    try:
        db_manager = DatabaseManager(db_path)
        scan_summary = db_manager.get_scan_summary(scan_id)
        
        if not scan_summary:
            secho(f"Scan {scan_id} not found", fg='red')
            sys.exit(1)
        
        scan_data = scan_summary['scan']
        
        echo("=" * 60)
        echo("SCAN DETAILS")
        echo("=" * 60)
        echo(f"Scan ID: {scan_data['scan_id']}")
        echo(f"Target: {scan_data['target_url']}")
        echo(f"Status: {scan_data['status']}")
        echo(f"Start Time: {scan_data['start_time']}")
        echo(f"End Time: {scan_data['end_time'] or 'N/A'}")
        echo(f"Duration: {scan_data['total_duration']:.2f}s" if scan_data['total_duration'] else 'N/A')
        echo(f"Input Type: {scan_data['input_type']}")
        echo(f"Input Source: {scan_data['input_source']}")
        
        if scan_data.get('auth_type'):
            echo(f"Authentication: {scan_data['auth_type']}")
        
        if scan_data.get('error_message'):
            echo(f"Error: {scan_data['error_message']}")
        
        # Show risk summary
        zap_alerts = scan_summary.get('zap_alerts', {})
        custom_alerts = scan_summary.get('custom_alerts', {})
        
        echo("\nRISK SUMMARY:")
        total_high = zap_alerts.get('High', 0) + custom_alerts.get('High', 0) + custom_alerts.get('Critical', 0)
        total_medium = zap_alerts.get('Medium', 0) + custom_alerts.get('Medium', 0)
        total_low = zap_alerts.get('Low', 0) + custom_alerts.get('Low', 0)
        total_info = zap_alerts.get('Informational', 0) + custom_alerts.get('Info', 0)
        
        echo(f"  High: {total_high}")
        echo(f"  Medium: {total_medium}")
        echo(f"  Low: {total_low}")
        echo(f"  Informational: {total_info}")
        
        # Show performance stats
        if scan_summary.get('performance_stats'):
            echo("\nPERFORMANCE STATISTICS:")
            for stat in scan_summary['performance_stats']:
                echo(f"  {stat['phase_name']}: {stat['duration']:.2f}s")
        
        # Generate detailed report if requested
        if export:
            # Ensure export path is in reports folder
            export_path = Path(export)
            if not export_path.is_absolute() and not str(export_path).startswith('reports/'):
                reports_dir = Path("reports")
                reports_dir.mkdir(exist_ok=True)
                export_path = reports_dir / export_path.name
            
            echo(f"\nGenerating detailed report: {export_path}")
            report_generator = ReportGenerator()
            
            # Get full alert data
            with db_manager.get_connection() as conn:
                cursor = conn.cursor()
                
                # Get ZAP alerts
                cursor.execute("SELECT * FROM zap_alerts WHERE scan_id = ?", (scan_id,))
                zap_alerts_data = [dict(row) for row in cursor.fetchall()]
                
                # Get custom alerts
                cursor.execute("SELECT * FROM custom_alerts WHERE scan_id = ?", (scan_id,))
                custom_alerts_data = [dict(row) for row in cursor.fetchall()]
                
                # Combine all vulnerabilities
                all_vulnerabilities = zap_alerts_data + custom_alerts_data
            
            success = report_generator.generate_report(
                scan_data,
                all_vulnerabilities,
                scan_summary.get('performance_stats', []),
                str(export_path),
                None  # parsed_requests not available in show_scan command
            )
            
            if success:
                echo(f"Detailed report saved to: {export_path}")
            else:
                secho("Failed to generate detailed report", fg='red')
        
    except Exception as e:
        secho(f"Error showing scan: {e}", fg='red')
        sys.exit(1)


@cli.command()
@click.option('--db-path', default='scan_results.db', help='SQLite database path')
@click.option('--days', default=30, help='Delete scans older than this many days')
@click.option('--confirm', is_flag=True, help='Skip confirmation prompt')
@click.pass_context
def cleanup(ctx, db_path, days, confirm):
    """Clean up old scan data."""
    try:
        if not confirm:
            if not click.confirm(f"Delete scans older than {days} days?"):
                echo("Cleanup cancelled")
                return
        
        db_manager = DatabaseManager(db_path)
        deleted_count = db_manager.cleanup_old_scans(days)
        
        echo(f"Cleaned up {deleted_count} old scans")
        
    except Exception as e:
        secho(f"Error during cleanup: {e}", fg='red')
        sys.exit(1)


@cli.command()
@click.option('--db-path', default='scan_results.db', help='SQLite database path')
@click.pass_context
def stats(ctx, db_path):
    """📊 Show database statistics."""
    try:
        db_manager = DatabaseManager(db_path)
        stats = db_manager.get_database_stats()
        info = db_manager.get_database_info()
        
        echo("\n📊 DATABASE STATISTICS")
        echo("=" * 50)
        
        echo(f"Database Path: {info.get('database_path', 'N/A')}")
        echo(f"Database Size: {info.get('database_size_mb', 0):.2f} MB")
        
        if stats.get('scans_by_status'):
            echo("\nScans by Status:")
            for status, count in stats['scans_by_status'].items():
                echo(f"  {status}: {count}")
        
        echo(f"\nTotal ZAP Alerts: {stats.get('total_zap_alerts', 0)}")
        echo(f"Total Custom Alerts: {stats.get('total_custom_alerts', 0)}")
        
        if info.get('tables'):
            echo("\nTable Record Counts:")
            for table, count in info['tables'].items():
                echo(f"  {table}: {count}")
        
    except Exception as e:
        secho(f"Error getting stats: {e}", fg='red')
        sys.exit(1)


@cli.command()
@click.option('--db-path', default='scan_results.db', help='SQLite database path')
@click.option('--no-backup', is_flag=True, help='Skip creating backup before reset')
@click.option('--confirm', is_flag=True, help='Skip confirmation prompt')
@click.pass_context
def reset_db(ctx, db_path, no_backup, confirm):
    """🗑️ Reset the entire database (drops all tables and recreates them)."""
    try:
        if not confirm:
            echo("\n⚠️  WARNING: This will completely reset the database!")
            echo("All scan data, alerts, and logs will be permanently deleted.")
            if not no_backup:
                echo("A backup will be created before reset.")
            echo()
            
            if not click.confirm("Are you sure you want to reset the database?"):
                echo("Database reset cancelled.")
                return
        
        db_manager = DatabaseManager(db_path)
        
        echo("\n🔄 Resetting database...")
        success = db_manager.reset_database(backup=not no_backup)
        
        if success:
            secho("✅ Database reset completed successfully!", fg='green')
            if not no_backup:
                echo("📁 Backup was created before reset.")
        else:
            secho("❌ Database reset failed!", fg='red')
            sys.exit(1)
        
    except Exception as e:
        secho(f"Error resetting database: {e}", fg='red')
        sys.exit(1)


@cli.command()
@click.option('--db-path', default='scan_results.db', help='SQLite database path')
@click.option('--confirm', is_flag=True, help='Skip confirmation prompt')
@click.pass_context
def clear_db(ctx, db_path, confirm):
    """🧹 Clear all data from database (keeps table structure)."""
    try:
        if not confirm:
            echo("\n⚠️  WARNING: This will clear all data from the database!")
            echo("All scan data, alerts, and logs will be permanently deleted.")
            echo("Table structure will be preserved.")
            echo()
            
            if not click.confirm("Are you sure you want to clear all data?"):
                echo("Database clear cancelled.")
                return
        
        db_manager = DatabaseManager(db_path)
        
        echo("\n🧹 Clearing database data...")
        success = db_manager.clear_all_data()
        
        if success:
            secho("✅ Database data cleared successfully!", fg='green')
        else:
            secho("❌ Database clear failed!", fg='red')
            sys.exit(1)
        
    except Exception as e:
        secho(f"Error clearing database: {e}", fg='red')
        sys.exit(1)


@cli.command()
@click.option('--db-path', default='scan_results.db', help='SQLite database path')
@click.pass_context
def db_info(ctx, db_path):
    """ℹ️ Show detailed database information."""
    try:
        db_manager = DatabaseManager(db_path)
        info = db_manager.get_database_info()
        
        echo("\nℹ️  DATABASE INFORMATION")
        echo("=" * 50)
        
        echo(f"Database Path: {info.get('database_path', 'N/A')}")
        echo(f"Database Size: {info.get('database_size_mb', 0):.2f} MB")
        
        if info.get('tables'):
            echo("\nTable Information:")
            echo("-" * 30)
            for table, count in info['tables'].items():
                echo(f"  {table:<20} {count:>8} records")
        
        # Show database file info
        db_path_obj = Path(db_path)
        if db_path_obj.exists():
            stat = db_path_obj.stat()
            echo(f"\nFile Information:")
            echo(f"  Created: {datetime.fromtimestamp(stat.st_ctime).strftime('%Y-%m-%d %H:%M:%S')}")
            echo(f"  Modified: {datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')}")
            echo(f"  Permissions: {oct(stat.st_mode)[-3:]}")
        
    except Exception as e:
        secho(f"Error getting database info: {e}", fg='red')
        sys.exit(1)


@cli.command()
@click.option('--reports-dir', default='reports', help='Reports directory path')
@click.pass_context
def reports_info(ctx, reports_dir):
    """📄 Show detailed reports directory information."""
    try:
        report_manager = ReportManager(reports_dir)
        info = report_manager.get_reports_info()
        
        echo("\n📄 REPORTS DIRECTORY INFORMATION")
        echo("=" * 60)
        
        echo(f"Reports Directory: {info.get('reports_dir', 'N/A')}")
        echo(f"Total Files: {info.get('total_files', 0)}")
        echo(f"Total Size: {info.get('total_size_mb', 0):.2f} MB")
        
        if info.get('file_types'):
            echo("\nFile Types:")
            echo("-" * 30)
            for ext, count in sorted(info['file_types'].items()):
                echo(f"  {ext:<15} {count:>8} files")
        
        if info.get('files'):
            echo(f"\nRecent Files (showing first 10):")
            echo("-" * 80)
            echo(f"{'Name':<40} {'Size (MB)':<10} {'Modified':<20}")
            echo("-" * 80)
            
            for file_info in info['files'][:10]:
                name = file_info['name'][:37] + "..." if len(file_info['name']) > 40 else file_info['name']
                size = f"{file_info['size_mb']:.2f}"
                modified = file_info['modified'][:19]  # Remove seconds
                echo(f"{name:<40} {size:<10} {modified:<20}")
        
    except Exception as e:
        secho(f"Error getting reports info: {e}", fg='red')
        sys.exit(1)


@cli.command()
@click.option('--reports-dir', default='reports', help='Reports directory path')
@click.option('--no-backup', is_flag=True, help='Skip creating backup before clearing')
@click.option('--confirm', is_flag=True, help='Skip confirmation prompt')
@click.pass_context
def clear_reports(ctx, reports_dir, no_backup, confirm):
    """🗑️ Clear all report files from the reports directory."""
    try:
        if not confirm:
            echo("\n⚠️  WARNING: This will delete ALL report files!")
            echo("All HTML, PDF, Excel, XML, and JSON reports will be permanently deleted.")
            if not no_backup:
                echo("A backup will be created before clearing.")
            echo()
            
            if not click.confirm("Are you sure you want to clear all reports?"):
                echo("Report clearing cancelled.")
                return
        
        report_manager = ReportManager(reports_dir)
        
        echo("\n🗑️ Clearing all reports...")
        success = report_manager.clear_all_reports(backup=not no_backup)
        
        if success:
            secho("✅ All reports cleared successfully!", fg='green')
            if not no_backup:
                echo("📁 Backup was created before clearing.")
        else:
            secho("❌ Report clearing failed!", fg='red')
            sys.exit(1)
        
    except Exception as e:
        secho(f"Error clearing reports: {e}", fg='red')
        sys.exit(1)


@cli.command()
@click.option('--reports-dir', default='reports', help='Reports directory path')
@click.option('--days', default=30, help='Delete reports older than this many days')
@click.option('--confirm', is_flag=True, help='Skip confirmation prompt')
@click.pass_context
def cleanup_reports(ctx, reports_dir, days, confirm):
    """🧹 Clean up old report files."""
    try:
        if not confirm:
            echo(f"\n⚠️  This will delete report files older than {days} days.")
            echo()
            
            if not click.confirm(f"Are you sure you want to clean up reports older than {days} days?"):
                echo("Report cleanup cancelled.")
                return
        
        report_manager = ReportManager(reports_dir)
        
        echo(f"\n🧹 Cleaning up reports older than {days} days...")
        deleted_count = report_manager.clear_old_reports(days)
        
        if deleted_count > 0:
            secho(f"✅ Cleaned up {deleted_count} old report files!", fg='green')
        else:
            echo("ℹ️  No old reports found to clean up.")
        
    except Exception as e:
        secho(f"Error cleaning up reports: {e}", fg='red')
        sys.exit(1)


@cli.command()
@click.option('--reports-dir', default='reports', help='Reports directory path')
@click.option('--types', help='Comma-separated list of file extensions (e.g., "html,pdf,xlsx")')
@click.option('--confirm', is_flag=True, help='Skip confirmation prompt')
@click.pass_context
def clear_reports_by_type(ctx, reports_dir, types, confirm):
    """🎯 Clear report files by file type."""
    try:
        if not types:
            secho("Error: --types must be specified", fg='red')
            echo("Example: --types html,pdf,xlsx")
            sys.exit(1)
        
        file_types = [t.strip() for t in types.split(',') if t.strip()]
        
        if not confirm:
            echo(f"\n⚠️  This will delete all {', '.join(file_types)} report files.")
            echo()
            
            if not click.confirm(f"Are you sure you want to delete {', '.join(file_types)} files?"):
                echo("Report deletion cancelled.")
                return
        
        report_manager = ReportManager(reports_dir)
        
        echo(f"\n🎯 Deleting {', '.join(file_types)} report files...")
        deleted_count = report_manager.clear_reports_by_type(file_types)
        
        if deleted_count > 0:
            secho(f"✅ Deleted {deleted_count} {', '.join(file_types)} report files!", fg='green')
        else:
            echo(f"ℹ️  No {', '.join(file_types)} files found to delete.")
        
    except Exception as e:
        secho(f"Error deleting reports by type: {e}", fg='red')
        sys.exit(1)


@cli.command()
@click.option('--reports-dir', default='reports', help='Reports directory path')
@click.option('--pattern', help='Pattern to match filenames (supports wildcards, e.g., "scan_report_*")')
@click.option('--confirm', is_flag=True, help='Skip confirmation prompt')
@click.pass_context
def clear_reports_by_pattern(ctx, reports_dir, pattern, confirm):
    """🔍 Clear report files matching a specific pattern."""
    try:
        if not pattern:
            secho("Error: --pattern must be specified", fg='red')
            echo("Example: --pattern 'scan_report_*' or --pattern '*test*'")
            sys.exit(1)
        
        if not confirm:
            echo(f"\n⚠️  This will delete all report files matching pattern: {pattern}")
            echo()
            
            if not click.confirm(f"Are you sure you want to delete files matching '{pattern}'?"):
                echo("Report deletion cancelled.")
                return
        
        report_manager = ReportManager(reports_dir)
        
        echo(f"\n🔍 Deleting report files matching pattern: {pattern}")
        deleted_count = report_manager.clear_reports_by_pattern(pattern)
        
        if deleted_count > 0:
            secho(f"✅ Deleted {deleted_count} files matching pattern '{pattern}'!", fg='green')
        else:
            echo(f"ℹ️  No files found matching pattern '{pattern}'.")
        
    except Exception as e:
        secho(f"Error deleting reports by pattern: {e}", fg='red')
        sys.exit(1)


@cli.command()
@click.pass_context
def scan_modes(ctx):
    """🎯 List available ZAP scan modes with detailed descriptions."""
    echo("\n🎯 AVAILABLE ZAP SCAN MODES")
    echo("="*80)
    echo("Note: Scan modes only apply to ZAP scanning, not custom plugins")
    echo("="*80)
    
    scan_mode_manager = ScanModeManager()
    modes = scan_mode_manager.list_all_modes()
    
    for mode_name, mode_info in modes.items():
        echo(f"\n🔹 {mode_name.upper()}")
        echo(f"   Name: {mode_info.name}")
        echo(f"   Description: {mode_info.description}")
        echo(f"   Use Case: {mode_info.use_case}")
        echo(f"   Duration: {mode_info.duration}")
        echo(f"   Risk Level: {mode_info.risk_level}")
        
        # Show key configuration details
        config = mode_info.config
        echo(f"   ZAP Enabled: {'Yes' if config['zap_enabled'] else 'No'}")
        echo(f"   Spider Depth: {config['spider_depth']}")
        echo(f"   Request Delay: {config['request_delay']}s")
        echo(f"   Concurrent Requests: {config['concurrent_requests']}")
        echo(f"   Aggressive Scanning: {'Yes' if config['aggressive_scanning'] else 'No'}")
        echo(f"   Stealth Mode: {'Yes' if config['stealth_mode'] else 'No'}")
    
    echo("\n💡 USAGE EXAMPLES (ZAP Scanning):")
    echo("-" * 50)
    echo("python main.py scan -f collection.json --scan-mode safe")
    echo("python main.py scan -f collection.json --scan-mode attack")
    echo("python main.py scan -f collection.json --scan-mode spidering")
    echo("python main.py scan -f collection.json --scan-mode comprehensive")
    echo("python main.py scan -f collection.json --scan-mode stealth")
    echo("python main.py scan -f collection.json --scan-mode aggressive")
    echo("python main.py scan -f collection.json --scan-mode quick")
    echo("python main.py scan -f collection.json --scan-mode api-focused")
    echo("")
    echo("💡 PLUGIN-ONLY SCANNING (No ZAP, No Scan Mode):")
    echo("-" * 50)
    echo("python main.py scan -f collection.json --no-zap")
    echo("python main.py scan -f collection.json --no-zap --plugins JWTSecurityChecker")
    
    echo("\n🔧 ZAP SCAN MODE COMPARISON:")
    echo("-" * 50)
    echo("Mode          | ZAP | Duration | Risk Level")
    echo("-" * 50)
    for mode_name, mode_info in modes.items():
        config = mode_info.config
        zap_status = "✓" if config['zap_enabled'] else "✗"
        duration = mode_info.duration.split('-')[0].strip()  # Get first part of duration range
        risk = mode_info.risk_level
        echo(f"{mode_name:<13} | {zap_status:<3} | {duration:<8} | {risk}")


@cli.command()
@click.pass_context
def templates(ctx):
    """📋 List available scan templates with descriptions."""
    echo("\n📋 AVAILABLE SCAN TEMPLATES")
    echo("="*60)
    
    templates = {
        'quick': {
            'description': 'Fast scan using only custom plugins (Security Headers, CORS)',
            'use_case': 'Quick security check for development',
            'duration': '1-2 minutes',
            'plugins': 'SecurityHeadersChecker, CORSChecker'
        },
        'comprehensive': {
            'description': 'Full security scan with ZAP and all custom plugins',
            'use_case': 'Complete security assessment',
            'duration': '10-30 minutes',
            'plugins': 'All available plugins + ZAP'
        },
        'jwt-focused': {
            'description': 'Specialized scan for JWT token security',
            'use_case': 'JWT/OAuth security testing',
            'duration': '2-5 minutes',
            'plugins': 'JWTSecurityChecker, SecurityHeadersChecker'
        },
        'api-only': {
            'description': 'API-specific security checks without ZAP',
            'use_case': 'API endpoint security validation',
            'duration': '3-8 minutes',
            'plugins': 'SecurityHeadersChecker, CORSChecker, ParameterPollutionChecker'
        },
        'zap-only': {
            'description': 'Traditional OWASP ZAP scanning only',
            'use_case': 'Standard web application security testing',
            'duration': '5-15 minutes',
            'plugins': 'OWASP ZAP only'
        }
    }
    
    for template_name, info in templates.items():
        echo(f"\n🔹 {template_name.upper()}")
        echo(f"   Description: {info['description']}")
        echo(f"   Use Case: {info['use_case']}")
        echo(f"   Duration: {info['duration']}")
        echo(f"   Plugins: {info['plugins']}")
    
    echo("\n💡 USAGE EXAMPLES:")
    echo("-" * 40)
    echo("python main.py scan -f collection.json --template quick")
    echo("python main.py scan -f collection.json --template comprehensive")
    echo("python main.py scan -f collection.json --template jwt-focused")


# Command aliases for better usability
@cli.command('ls')
@click.pass_context
def list_scans_alias(ctx):
    """Alias for list-scans command."""
    ctx.invoke(list_scans)

@cli.command('show')
@click.argument('scan_id')
@click.option('--db-path', default='scan_results.db', help='SQLite database path')
@click.option('--export', help='Export detailed report to HTML file')
@click.pass_context
def show_scan_alias(ctx, scan_id, db_path, export):
    """Alias for show-scan command."""
    ctx.invoke(show_scan, scan_id=scan_id, db_path=db_path, export=export)

@cli.command('clean')
@click.option('--db-path', default='scan_results.db', help='SQLite database path')
@click.option('--days', default=30, help='Delete scans older than this many days')
@click.option('--confirm', is_flag=True, help='Skip confirmation prompt')
@click.pass_context
def cleanup_alias(ctx, db_path, days, confirm):
    """Alias for cleanup command."""
    ctx.invoke(cleanup, db_path=db_path, days=days, confirm=confirm)

@cli.command('reset')
@click.option('--db-path', default='scan_results.db', help='SQLite database path')
@click.option('--no-backup', is_flag=True, help='Skip creating backup before reset')
@click.option('--confirm', is_flag=True, help='Skip confirmation prompt')
@click.pass_context
def reset_db_alias(ctx, db_path, no_backup, confirm):
    """Alias for reset-db command."""
    ctx.invoke(reset_db, db_path=db_path, no_backup=no_backup, confirm=confirm)

@cli.command('clear')
@click.option('--db-path', default='scan_results.db', help='SQLite database path')
@click.option('--confirm', is_flag=True, help='Skip confirmation prompt')
@click.pass_context
def clear_db_alias(ctx, db_path, confirm):
    """Alias for clear-db command."""
    ctx.invoke(clear_db, db_path=db_path, confirm=confirm)

@cli.command('reports')
@click.option('--reports-dir', default='reports', help='Reports directory path')
@click.pass_context
def reports_info_alias(ctx, reports_dir):
    """Alias for reports-info command."""
    ctx.invoke(reports_info, reports_dir=reports_dir)

@cli.command('clear-reports')
@click.option('--reports-dir', default='reports', help='Reports directory path')
@click.option('--no-backup', is_flag=True, help='Skip creating backup before clearing')
@click.option('--confirm', is_flag=True, help='Skip confirmation prompt')
@click.pass_context
def clear_reports_alias(ctx, reports_dir, no_backup, confirm):
    """Alias for clear-reports command."""
    ctx.invoke(clear_reports, reports_dir=reports_dir, no_backup=no_backup, confirm=confirm)


@cli.command()
@click.pass_context
def help_cmd(ctx):
    """📚 Show comprehensive help and usage examples."""
    echo("\n🔒 API Security Scanner - Help & Usage Guide")
    echo("="*60)
    
    echo("\n📖 QUICK START:")
    echo("-" * 30)
    echo("1. Basic scan: python main.py scan -f collection.json")
    echo("2. Interactive mode: python main.py --interactive scan")
    echo("3. Quick template: python main.py scan -f collection.json --template quick")
    echo("4. Configuration wizard: python main.py config --wizard")
    
    echo("\n🔧 COMMON COMMANDS:")
    echo("-" * 30)
    echo("scan          - Perform security scan")
    echo("scan-modes    - List available scan modes")
    echo("plugins       - List available plugins")
    echo("templates     - Show scan templates")
    echo("list-scans    - Show recent scans")
    echo("show-scan     - Show scan details")
    echo("config        - Manage configuration")
    echo("cleanup       - Clean old scan data")
    echo("stats         - Show database statistics")
    echo("reset-db      - Reset entire database")
    echo("clear-db      - Clear all data (keep structure)")
    echo("db-info       - Show detailed database info")
    echo("reports-info  - Show reports directory info")
    echo("clear-reports - Clear all report files")
    echo("cleanup-reports - Clean up old report files")
    echo("autocomplete  - Generate shell autocomplete files")
    echo("help          - Show this help message")
    
    echo("\n📁 INPUT FORMATS:")
    echo("-" * 30)
    echo("• Postman Collections (.json)")
    echo("• OpenAPI/Swagger specs (.json, .yaml)")
    echo("• HAR files (.har)")
    echo("• cURL commands")
    
    echo("\n🎯 ZAP SCAN MODES (Optional):")
    echo("-" * 30)
    echo("• safe         - Conservative ZAP scanning (15-30 min)")
    echo("• attack       - Aggressive ZAP vulnerability testing (1-2 hours)")
    echo("• spidering    - ZAP endpoint discovery and mapping (30-60 min)")
    echo("• comprehensive - Complete ZAP security assessment (2-3 hours)")
    echo("• stealth      - Minimal footprint ZAP scanning (10-15 min)")
    echo("• aggressive   - Maximum intensity ZAP scanning (3-4 hours)")
    echo("• quick        - Fast ZAP development testing (2-5 min)")
    echo("• api-focused  - Specialized ZAP API security testing (20-30 min)")
    echo("Note: Scan modes only apply to ZAP scanning, not custom plugins")
    
    echo("\n📋 SCAN TEMPLATES:")
    echo("-" * 30)
    echo("• quick        - Fast security check (1-2 min)")
    echo("• comprehensive - Full security assessment (10-30 min)")
    echo("• jwt-focused  - JWT token security (2-5 min)")
    echo("• api-only     - API-specific checks (3-8 min)")
    echo("• zap-only     - Traditional ZAP scanning (5-15 min)")
    
    echo("\n📊 REPORT FORMATS:")
    echo("-" * 30)
    echo("• HTML (default)")
    echo("• JSON")
    echo("• PDF")
    echo("• Excel")
    echo("• XML")
    
    echo("\n💡 EXAMPLES:")
    echo("-" * 30)
    echo("# Safe ZAP mode scan for production")
    echo("python main.py scan -f api.json --scan-mode safe")
    echo("")
    echo("# Aggressive ZAP penetration testing")
    echo("python main.py scan -f api.json --scan-mode attack")
    echo("")
    echo("# Quick ZAP development scan")
    echo("python main.py scan -f api.json --scan-mode quick")
    echo("")
    echo("# Comprehensive ZAP security assessment")
    echo("python main.py scan -f api.json --scan-mode comprehensive")
    echo("")
    echo("# Stealth ZAP mode to avoid detection")
    echo("python main.py scan -f api.json --scan-mode stealth")
    echo("")
    echo("# API-focused ZAP scanning")
    echo("python main.py scan -f api.json --scan-mode api-focused")
    echo("")
    echo("# Plugin-only scan (no ZAP, no scan mode)")
    echo("python main.py scan -f api.json --no-zap")
    echo("")
    echo("# Interactive guided scan")
    echo("python main.py --interactive scan")
    echo("")
    echo("# Scan with specific plugins only")
    echo("python main.py scan -f api.json --plugins JWTSecurityChecker,SecurityHeadersChecker")
    echo("")
    echo("# List available scan modes")
    echo("python main.py scan-modes")
    echo("")
    echo("# Setup autocomplete for your shell")
    echo("python main.py autocomplete")
    
    echo("\n🔗 For more detailed help on any command:")
    echo("python main.py <command> --help")


@cli.command()
@click.pass_context
def plugins(ctx):
    """🔌 List available custom plugins with detailed information."""
    try:
        plugin_manager = PluginManager("api_security_scanner/plugins")
        plugins = plugin_manager.get_plugin_list()
        
        if not plugins:
            echo("No custom plugins found")
            return
        
        echo(f"🔌 Available Custom Plugins ({len(plugins)}):")
        echo("=" * 80)
        echo()
        
        for i, plugin in enumerate(plugins, 1):
            echo(f"{i}. {plugin['name']}")
            echo(f"   Description: {plugin['description']}")
            echo(f"   Version: {plugin['version']}")
            echo(f"   Author: {plugin['author']}")
            echo()
        
        echo("💡 Usage Examples:")
        echo("-" * 40)
        echo("Run all plugins (default):")
        echo("  python main.py scan -f collection.json")
        echo()
        echo("Run specific plugins:")
        echo("  python main.py scan -f collection.json --plugins SecurityHeadersChecker,JWTSecurityChecker")
        echo()
        echo("Run only JWT security plugin:")
        echo("  python main.py scan -f collection.json --plugins JWTSecurityChecker")
        echo()
        echo("Run only security headers and CORS plugins:")
        echo("  python main.py scan -f collection.json --plugins SecurityHeadersChecker,CORSChecker")
        echo()
        
    except Exception as e:
        secho(f"Error listing plugins: {e}", fg='red')
        sys.exit(1)


@cli.command()
@click.option('--shell', type=click.Choice(['bash', 'zsh', 'fish', 'all']), 
              default='all', help='Generate autocomplete for specific shell')
@click.option('--install', is_flag=True, help='Install autocomplete files to system')
@click.pass_context
def autocomplete(ctx, shell: str, install: bool):
    """🚀 Generate and install shell autocomplete files."""
    try:
        echo("\n🚀 API Security Scanner - Autocomplete Setup")
        echo("=" * 50)
        
        # Generate autocomplete files
        generate_autocomplete_files()
        
        if install:
            echo("\n📦 Installing autocomplete files...")
            _install_autocomplete_files(shell)
        else:
            echo("\n💡 To install autocomplete files, run:")
            echo("  python main.py autocomplete --install")
            echo("\nOr manually install:")
            echo("  Bash: source autocomplete/api-security-scanner.bash")
            echo("  Zsh:  cp autocomplete/_api-security-scanner ~/.zsh/completions/")
            echo("  Fish: cp autocomplete/api-security-scanner.fish ~/.config/fish/completions/")
        
        echo("\n✅ Autocomplete setup complete!")
        echo("🔄 Restart your shell or run 'source ~/.bashrc' to activate autocomplete")
        
    except Exception as e:
        secho(f"Error setting up autocomplete: {e}", fg='red')
        sys.exit(1)


def _install_autocomplete_files(shell: str):
    """Install autocomplete files to system directories."""
    import shutil
    from pathlib import Path
    
    autocomplete_dir = Path("autocomplete")
    if not autocomplete_dir.exists():
        secho("Error: Autocomplete directory not found. Run without --install first.", fg='red')
        return
    
    home_dir = Path.home()
    
    if shell in ['bash', 'all']:
        # Install bash completion
        bash_source = autocomplete_dir / "api-security-scanner.bash"
        bash_target = home_dir / ".bash_completion.d" / "api-security-scanner"
        
        try:
            bash_target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(bash_source, bash_target)
            echo(f"✅ Bash completion installed to {bash_target}")
            
            # Add to .bashrc if not already present
            bashrc = home_dir / ".bashrc"
            if bashrc.exists():
                with open(bashrc, 'r') as f:
                    content = f.read()
                
                if "api-security-scanner" not in content:
                    with open(bashrc, 'a') as f:
                        f.write(f"\n# API Security Scanner autocomplete\nsource {bash_target}\n")
                    echo("✅ Added autocomplete to .bashrc")
        except Exception as e:
            secho(f"⚠️  Could not install bash completion: {e}", fg='yellow')
    
    if shell in ['zsh', 'all']:
        # Install zsh completion
        zsh_source = autocomplete_dir / "_api-security-scanner"
        zsh_target = home_dir / ".zsh" / "completions" / "_api-security-scanner"
        
        try:
            zsh_target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(zsh_source, zsh_target)
            echo(f"✅ Zsh completion installed to {zsh_target}")
        except Exception as e:
            secho(f"⚠️  Could not install zsh completion: {e}", fg='yellow')
    
    if shell in ['fish', 'all']:
        # Install fish completion
        fish_source = autocomplete_dir / "api-security-scanner.fish"
        fish_target = home_dir / ".config" / "fish" / "completions" / "api-security-scanner.fish"
        
        try:
            fish_target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(fish_source, fish_target)
            echo(f"✅ Fish completion installed to {fish_target}")
        except Exception as e:
            secho(f"⚠️  Could not install fish completion: {e}", fg='yellow')


def _show_welcome_message():
    """Display welcome message for interactive mode."""
    echo("\n" + "="*80)
    secho("🔒 API Security Scanner - Interactive Mode", fg='cyan', bold=True)
    echo("="*80)
    echo("Welcome to the interactive security scanning experience!")
    echo("This mode will guide you through the scanning process step by step.")
    echo("="*80 + "\n")


def _handle_error(error_msg: str, error_type: str = "Error", exit_code: int = 1):
    """Handle errors with user-friendly messages and suggestions."""
    echo("\n" + "="*60)
    secho(f"❌ {error_type}", fg='red', bold=True)
    echo("="*60)
    secho(error_msg, fg='red')
    echo("="*60)
    
    # Provide helpful suggestions based on error type
    if "file" in error_msg.lower() and "not found" in error_msg.lower():
        echo("\n💡 Suggestions:")
        echo("  • Check if the file path is correct")
        echo("  • Ensure the file exists and is readable")
        echo("  • Use absolute path if relative path doesn't work")
    elif "authentication" in error_msg.lower():
        echo("\n💡 Suggestions:")
        echo("  • Verify your authentication credentials")
        echo("  • Check if the authentication type is correct")
        echo("  • Ensure the API endpoint accepts your auth method")
    elif "zap" in error_msg.lower():
        echo("\n💡 Suggestions:")
        echo("  • Check if ZAP is installed and accessible")
        echo("  • Verify ZAP port is not in use by another process")
        echo("  • Try using --no-zap to skip ZAP scanning")
    elif "plugin" in error_msg.lower():
        echo("\n💡 Suggestions:")
        echo("  • Check available plugins with: python main.py plugins")
        echo("  • Verify plugin names are spelled correctly")
        echo("  • Try running without specific plugins first")
    
    echo("\nFor more help, use: python main.py --help")
    sys.exit(exit_code)


def _interactive_input_selection() -> Dict[str, Any]:
    """Interactive input selection for scan configuration."""
    echo("\n📁 INPUT SELECTION")
    echo("-" * 40)
    
    input_type = click.prompt(
        "Select input type",
        type=click.Choice(['file', 'curl', 'har'], case_sensitive=False),
        default='file'
    )
    
    input_data = {}
    
    if input_type == 'file':
        while True:
            file_path = prompt("Enter path to Postman Collection or OpenAPI spec file")
            if os.path.exists(file_path):
                input_data['input_file'] = file_path
                break
            else:
                secho("File not found. Please try again.", fg='red')
    
    elif input_type == 'curl':
        curl_command = prompt("Enter curl command")
        input_data['curl_command'] = curl_command
    
    elif input_type == 'har':
        while True:
            har_path = prompt("Enter path to HAR file")
            if os.path.exists(har_path):
                input_data['input_file'] = har_path
                break
            else:
                secho("File not found. Please try again.", fg='red')
    
    return input_data


def _interactive_auth_setup() -> Dict[str, Any]:
    """Interactive authentication setup."""
    echo("\n🔐 AUTHENTICATION SETUP")
    echo("-" * 40)
    
    if not confirm("Do you want to configure authentication?"):
        return {}
    
    auth_type = click.prompt(
        "Select authentication type",
        type=click.Choice(['header', 'cookie', 'token'], case_sensitive=False),
        default='header'
    )
    
    auth_name = prompt("Enter authentication parameter name (e.g., 'Authorization', 'X-API-Key')")
    auth_value = prompt("Enter authentication value", hide_input=True)
    
    return {
        'auth_type': auth_type,
        'auth_name': auth_name,
        'auth_value': auth_value
    }


def _interactive_plugin_selection() -> Dict[str, Any]:
    """Interactive plugin selection."""
    echo("\n🔌 PLUGIN SELECTION")
    echo("-" * 40)
    
    # Get available plugins
    try:
        plugin_manager = PluginManager("api_security_scanner/plugins")
        available_plugins = plugin_manager.get_plugin_list()
        
        if not available_plugins:
            echo("No custom plugins available.")
            return {}
        
        echo("Available plugins:")
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
                    return {'plugins': ','.join(selected_plugins)}
                except (ValueError, IndexError):
                    secho("Invalid selection. Using all plugins.", fg='yellow')
        
        return {}
        
    except Exception as e:
        secho(f"Error loading plugins: {e}", fg='yellow')
        return {}


def _interactive_report_setup() -> Dict[str, Any]:
    """Interactive report format selection."""
    echo("\n📊 REPORT CONFIGURATION")
    echo("-" * 40)
    
    report_options = {}
    
    if confirm("Generate PDF report?"):
        pdf_path = prompt("Enter PDF report path", default="scan_report.pdf")
        report_options['export_pdf'] = pdf_path
    
    if confirm("Generate Excel report?"):
        excel_path = prompt("Enter Excel report path", default="scan_report.xlsx")
        report_options['export_excel'] = excel_path
    
    if confirm("Generate XML report?"):
        xml_path = prompt("Enter XML report path", default="scan_report.xml")
        report_options['export_xml'] = xml_path
    
    if confirm("Show performance statistics?"):
        report_options['performance_stats'] = True
    
    return report_options




def _get_scan_template(template_name: str) -> Optional[Dict[str, Any]]:
    """Get predefined scan template configuration."""
    templates = {
        'quick': {
            'no_zap': True,
            'plugins': 'SecurityHeadersChecker,CORSChecker',
            'performance_stats': False,
            'no_progress': False
        },
        'comprehensive': {
            'no_zap': False,
            'no_plugins': False,
            'performance_stats': True,
            'spider_depth': 10,
            'spider_children': 20,
            'export_pdf': 'comprehensive_report.pdf',
            'export_excel': 'comprehensive_report.xlsx'
        },
        'jwt-focused': {
            'no_zap': True,
            'plugins': 'JWTSecurityChecker,SecurityHeadersChecker',
            'performance_stats': True,
            'export_pdf': 'jwt_security_report.pdf'
        },
        'api-only': {
            'no_zap': True,
            'no_plugins': False,
            'plugins': 'SecurityHeadersChecker,CORSChecker,ParameterPollutionChecker',
            'performance_stats': False
        },
        'zap-only': {
            'no_plugins': True,
            'no_zap': False,
            'performance_stats': True,
            'spider_depth': 5,
            'spider_children': 10
        }
    }
    
    if template_name not in templates:
        return None
    
    return templates[template_name]


def _interactive_scan_setup() -> Dict[str, Any]:
    """Complete interactive scan setup."""
    echo("\n🚀 INTERACTIVE SCAN SETUP")
    echo("="*50)
    
    # Collect all configuration
    config = {}
    config.update(_interactive_input_selection())
    config.update(_interactive_auth_setup())
    config.update(_interactive_plugin_selection())
    config.update(_interactive_report_setup())
    
    # Advanced options
    echo("\n⚙️  ADVANCED OPTIONS")
    echo("-" * 40)
    
    if confirm("Configure advanced scan options?"):
        if confirm("Skip ZAP scanning (custom plugins only)?"):
            config['no_zap'] = True
        
        if confirm("Skip custom plugins (ZAP only)?"):
            config['no_plugins'] = True
        
        if confirm("Disable progress bars?"):
            config['no_progress'] = True
    
    # Show configuration summary
    echo("\n📋 CONFIGURATION SUMMARY")
    echo("="*50)
    for key, value in config.items():
        if key == 'auth_value':
            echo(f"  {key}: {'*' * len(str(value))}")
        else:
            echo(f"  {key}: {value}")
    
    if confirm("\nProceed with this configuration?"):
        return config
    else:
        echo("Configuration cancelled.")
        sys.exit(0)


def _display_scan_banner(scan_id: str, target_url: str, scan_mode: Optional[str] = None, 
                        no_zap: bool = False, no_plugins: bool = False):
    """Display a banner for the scan command."""
    echo("\n" + "="*80)
    echo("🔒 API SECURITY SCANNER")
    echo("="*80)
    echo(f"📋 Scan ID: {scan_id}")
    echo(f"🎯 Target: {target_url}")
    
    if scan_mode and not no_zap:
        echo(f"⚙️  ZAP Scan Mode: {scan_mode.title()}")
    elif scan_mode and no_zap:
        echo(f"⚠️  ZAP Scan Mode: {scan_mode.title()} (ZAP disabled - mode ignored)")
    
    if no_zap and no_plugins:
        echo("🚫 No scanning enabled (both ZAP and plugins disabled)")
    elif no_zap:
        echo("🔧 Plugin-only scanning (ZAP disabled)")
    elif no_plugins:
        echo("🕷️  ZAP-only scanning (plugins disabled)")
    else:
        echo("🔍 Full scanning (ZAP + plugins)")
    
    echo("="*80)
    echo()


def _display_scan_completion_banner(scan_id: str, vulnerabilities_found: int, 
                                   zap_alerts: int, custom_alerts: int, 
                                   scan_duration: float, reports_generated: bool):
    """Display a completion banner for the scan."""
    echo("\n" + "="*80)
    echo("✅ SCAN COMPLETED SUCCESSFULLY")
    echo("="*80)
    echo(f"📋 Scan ID: {scan_id}")
    echo(f"⏱️  Duration: {scan_duration:.2f} seconds")
    echo(f"🔍 Total Vulnerabilities Found: {vulnerabilities_found}")
    
    if zap_alerts > 0 or custom_alerts > 0:
        echo(f"   🕷️  ZAP Alerts: {zap_alerts}")
        echo(f"   🔧 Plugin Alerts: {custom_alerts}")
    
    if reports_generated:
        echo("📊 Reports Generated: ✅")
    else:
        echo("📊 Reports Generated: ❌")
    
    echo("="*80)
    echo()


def _display_scan_cancellation_banner(scan_id: str, vulnerabilities_found: int, 
                                     zap_alerts: int, custom_alerts: int, 
                                     scan_duration: float):
    """Display a cancellation banner for the scan."""
    echo("\n" + "="*80)
    echo("🛑 SCAN CANCELLED BY USER")
    echo("="*80)
    echo(f"📋 Scan ID: {scan_id}")
    echo(f"⏱️  Duration: {scan_duration:.2f} seconds")
    echo(f"🔍 Vulnerabilities Found Before Cancellation: {vulnerabilities_found}")
    
    if zap_alerts > 0 or custom_alerts > 0:
        echo(f"   🕷️  ZAP Alerts: {zap_alerts}")
        echo(f"   🔧 Plugin Alerts: {custom_alerts}")
    
    echo("📊 Partial results saved to database")
    echo("="*80)
    echo()


def _display_issues_summary(zap_alerts, custom_alerts):
    """Display a summary of all identified issues with severity levels in table format."""
    all_vulnerabilities = zap_alerts + custom_alerts
    
    if not all_vulnerabilities:
        echo("\n✅ No security issues found!")
        return
    
    # Calculate risk counts
    risk_counts = {'High': 0, 'Medium': 0, 'Low': 0, 'Informational': 0}
    for vuln in all_vulnerabilities:
        risk = vuln.get('risk', 'Informational')
        if risk in risk_counts:
            risk_counts[risk] += 1
    
    echo("\n🔍 SECURITY ISSUES SUMMARY")
    echo("="*120)
    
    # Display risk summary
    if risk_counts['High'] > 0:
        secho(f"🔴 HIGH RISK: {risk_counts['High']} issues", fg='red', bold=True)
    if risk_counts['Medium'] > 0:
        secho(f"🟡 MEDIUM RISK: {risk_counts['Medium']} issues", fg='yellow', bold=True)
    if risk_counts['Low'] > 0:
        secho(f"🟢 LOW RISK: {risk_counts['Low']} issues", fg='green', bold=True)
    if risk_counts['Informational'] > 0:
        secho(f"🔵 INFORMATIONAL: {risk_counts['Informational']} issues", fg='blue', bold=True)
    
    echo(f"\nTotal Issues: {len(all_vulnerabilities)}")
    echo("\n" + "="*120)
    
    # Display table header
    echo(f"{'#':<3} {'Risk':<8} {'CVSS':<6} {'Issue Name':<45} {'Source':<18} {'URL':<35}")
    echo("-" * 115)
    
    # Display issues in table format
    for i, vuln in enumerate(all_vulnerabilities, 1):
        risk = vuln.get('risk', 'Informational')
        name = vuln.get('name', 'Unknown Issue')
        cvss_score = vuln.get('cvss_score', 'N/A')
        url = vuln.get('url', 'N/A')
        source = vuln.get('plugin_name', 'ZAP Scanner')
        
        # Truncate long names and URLs
        display_name = name[:42] + "..." if len(name) > 45 else name
        display_url = url[:32] + "..." if len(url) > 35 else url
        display_source = source[:15] + "..." if len(source) > 18 else source
        
        # Color code based on risk level
        if risk == 'High':
            risk_color = 'red'
            risk_icon = '🔴'
        elif risk == 'Medium':
            risk_color = 'yellow'
            risk_icon = '🟡'
        elif risk == 'Low':
            risk_color = 'green'
            risk_icon = '🟢'
        else:
            risk_color = 'blue'
            risk_icon = '🔵'
        
        # Display table row
        echo(f"{i:<3} ", nl=False)
        secho(f"{risk_icon} {risk:<6}", fg=risk_color, bold=True, nl=False)
        echo(f" {cvss_score:<6} {display_name:<45} {display_source:<18} {display_url:<35}")
    
    echo("\n" + "="*115)
    echo("💡 Check the generated HTML report for detailed information and remediation steps.")
    
    # Display detailed evidence for each issue
    echo("\n📋 DETAILED EVIDENCE:")
    echo("-" * 115)
    for i, vuln in enumerate(all_vulnerabilities, 1):
        risk = vuln.get('risk', 'Informational')
        name = vuln.get('name', 'Unknown Issue')
        evidence = vuln.get('evidence', '')
        
        # Color code based on risk level
        if risk == 'High':
            risk_color = 'red'
            risk_icon = '🔴'
        elif risk == 'Medium':
            risk_color = 'yellow'
            risk_icon = '🟡'
        elif risk == 'Low':
            risk_color = 'green'
            risk_icon = '🟢'
        else:
            risk_color = 'blue'
            risk_icon = '🔵'
        
        echo(f"\n{risk_icon} Issue #{i}: {name}")
        secho(f"   Risk: {risk}", fg=risk_color, bold=True)
        if evidence:
            echo(f"   Evidence: {evidence}")
        else:
            echo("   Evidence: No evidence available")


if __name__ == '__main__':
    cli()
