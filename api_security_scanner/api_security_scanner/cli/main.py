"""
Command-line interface for the API Security Scanner.
Provides a comprehensive CLI using the click library.
"""

import sys
import uuid
import warnings
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional
import time

import click
from click import echo, secho
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
from ..core.db_manager import DatabaseManager
from ..core.zap_manager import ZAPManager, ZAPManagerError
from ..core.scanner_plugins import PluginManager
from ..core.report_generator import ReportGenerator
from ..core.config import get_config_manager, get_config


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
@click.pass_context
def cli(ctx, verbose, log_dir):
    """API Security Scanner - Automated security testing for APIs."""
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


@cli.command()
@click.option('--env-file', default='.env', help='Path to .env configuration file')
@click.option('--save-config', is_flag=True, help='Save current configuration to .env file')
@click.option('--show-config', is_flag=True, help='Show current configuration and exit')
def config(env_file: str, save_config: bool, show_config: bool):
    """Configuration management commands."""
    config_manager = get_config_manager(env_file)
    config = config_manager.get_config()
    
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
    
    # Validate configuration
    validation = config_manager.validate_config()
    if validation['valid']:
        echo("Configuration is valid")
    else:
        echo("Configuration issues found:")
        for issue in validation['issues']:
            echo(f"  - {issue}")


@cli.command()
@click.option('-f', '--file', 'input_file', help='Path to Postman Collection or OpenAPI spec file')
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
@click.option('--performance-stats', is_flag=True, help='Show detailed performance statistics')
@click.option('--no-zap', is_flag=True, help='Skip ZAP scanning (custom plugins only)')
@click.option('--no-plugins', is_flag=True, help='Skip custom plugin scanning (ZAP only)')
@click.option('--spider-depth', default=5, help='Maximum spider depth')
@click.option('--spider-children', default=10, help='Maximum children per spider node')
@click.option('--max-scan-time', type=int, help='Maximum scan time in minutes (time-bound scanning)')
@click.option('--no-progress', is_flag=True, help='Disable progress bars (useful for verbose output)')
@click.pass_context
def scan(ctx, input_file, curl_command, auth_type, auth_name, auth_value, 
         zap_path, zap_port, zap_host, db_path, export, export_json, 
         performance_stats, no_zap, no_plugins, spider_depth, spider_children, max_scan_time, no_progress):
    """Perform security scan on API endpoints."""
    logger = ctx.obj['logger']
    
    try:
        # Validate input
        if not input_file and not curl_command:
            secho("Error: Either --file or --curl must be specified", fg='red')
            sys.exit(1)
        
        if input_file and curl_command:
            secho("Error: Cannot specify both --file and --curl", fg='red')
            sys.exit(1)
        
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
                secho(f"Input parsing error: {e}", fg='red')
                sys.exit(1)
            
            # Phase 2: Setup authentication
            progress.start_phase("Setting up authentication")
            auth_handler = None
            if auth_type and auth_name and auth_value:
                try:
                    auth_handler = create_auth_handler(auth_type, auth_name, auth_value)
                except AuthenticationError as e:
                    secho(f"Authentication error: {e}", fg='red')
                    sys.exit(1)
            
            # Apply authentication to requests
            if auth_handler:
                requests_data = auth_handler.apply_authentication(requests_data)
            
            # Phase 3: Initialize database
            progress.start_phase("Initializing database")
            db_manager = DatabaseManager(db_path)
            
            # Extract target URL from first request
            target_url = requests_data[0]['url'] if requests_data else 'unknown'
            
            # Create scan record
            db_manager.create_scan(
                scan_id=scan_id,
                target_url=target_url,
                input_type=input_type,
                input_source=input_source,
                auth_type=auth_type
            )
            
            # Phase 4: Initialize components
            progress.start_phase("Loading security plugins")
            zap_manager = None
            plugin_manager = None
            
            if not no_zap:
                zap_manager = ZAPManager(zap_path, zap_port, zap_host)
            
            if not no_plugins:
                plugin_manager = PluginManager("api_security_scanner/plugins")
            
            # Phase 5: Execute security checks
            progress.start_phase("Executing security checks")
            
            # Start ZAP scanning
            zap_alerts = []
            if zap_manager and not no_zap:
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
                    secho(f"ZAP error: {e}", fg='red')
                    logger.error(f"ZAP operation failed: {e}")
            
            # Run custom plugins
            custom_alerts = []
            if plugin_manager and not no_plugins:
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
                    secho(f"Plugin execution error: {e}", fg='red')
                    logger.error(f"Plugin execution failed: {e}")
            
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
        echo("\n" + "="*60)
        echo("SCAN COMPLETED")
        echo("="*60)
        echo(f"Scan ID: {scan_id}")
        echo(f"Target: {target_url}")
        echo(f"ZAP Alerts: {len(zap_alerts)}")
        echo(f"Custom Plugin Alerts: {len(custom_alerts)}")
        
        # Display issues summary
        _display_issues_summary(zap_alerts, custom_alerts)
        
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
            str(default_html_report)
        )
        
        # Generate JSON report
        json_success = report_generator.generate_json_report(
            scan_summary['scan'],
            all_vulnerabilities,
            scan_summary.get('performance_stats', []),
            str(default_json_report)
        )
        
        # Generate custom reports if specified
        if export or export_json:
            if export:
                custom_html_success = report_generator.generate_report(
                    scan_summary['scan'],
                    all_vulnerabilities,
                    scan_summary.get('performance_stats', []),
                    export
                )
                if custom_html_success:
                    echo(f"Custom HTML report saved to: {export}")
                else:
                    secho("Failed to generate custom HTML report", fg='red')
            
            if export_json:
                custom_json_success = report_generator.generate_json_report(
                    scan_summary['scan'],
                    all_vulnerabilities,
                    scan_summary.get('performance_stats', []),
                    export_json
                )
                if custom_json_success:
                    echo(f"Custom JSON report saved to: {export_json}")
                else:
                    secho("Failed to generate custom JSON report", fg='red')
        
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
            db_manager.update_scan_completion(scan_id, 'failed', 'Interrupted by user')
        sys.exit(1)
    except Exception as e:
        secho(f"Unexpected error: {e}", fg='red')
        logger.error(f"Unexpected error during scan: {e}", exc_info=True)
        if 'scan_id' in locals():
            db_manager.update_scan_completion(scan_id, 'failed', str(e))
        sys.exit(1)


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
            echo(f"\nGenerating detailed report: {export}")
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
                export
            )
            
            if success:
                echo(f"Detailed report saved to: {export}")
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
    """Show database statistics."""
    try:
        db_manager = DatabaseManager(db_path)
        stats = db_manager.get_database_stats()
        
        echo("DATABASE STATISTICS")
        echo("=" * 40)
        
        if stats.get('scans_by_status'):
            echo("Scans by Status:")
            for status, count in stats['scans_by_status'].items():
                echo(f"  {status}: {count}")
        
        echo(f"Total ZAP Alerts: {stats.get('total_zap_alerts', 0)}")
        echo(f"Total Custom Alerts: {stats.get('total_custom_alerts', 0)}")
        echo(f"Database Size: {stats.get('database_size_mb', 0):.2f} MB")
        
    except Exception as e:
        secho(f"Error getting stats: {e}", fg='red')
        sys.exit(1)


@cli.command()
@click.pass_context
def plugins(ctx):
    """List available custom plugins."""
    try:
        plugin_manager = PluginManager("api_security_scanner/plugins")
        plugins = plugin_manager.get_plugin_list()
        
        if not plugins:
            echo("No custom plugins found")
            return
        
        echo(f"Available Custom Plugins ({len(plugins)}):")
        echo("-" * 60)
        
        for plugin in plugins:
            echo(f"Name: {plugin['name']}")
            echo(f"  Description: {plugin['description']}")
            echo(f"  Version: {plugin['version']}")
            echo(f"  Author: {plugin['author']}")
            echo()
        
    except Exception as e:
        secho(f"Error listing plugins: {e}", fg='red')
        sys.exit(1)


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
