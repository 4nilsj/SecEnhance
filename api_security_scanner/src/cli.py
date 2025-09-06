"""
Command-line interface for the API Security Scanner.
Provides a comprehensive CLI using the click library.
"""

import sys
import uuid
from pathlib import Path
from typing import Optional
import time

import click
from click import echo, secho
from tqdm import tqdm

from utils.logger import setup_logging, get_logger
from utils.input_parsers import parse_input, InputParserError
from utils.auth_handler import create_auth_handler, AuthenticationError
from src.db_manager import DatabaseManager
from src.zap_manager import ZAPManager, ZAPManagerError
from src.scanner_plugins import PluginManager
from src.report_generator import ReportGenerator


class ScanProgressBar:
    """Progress bar for scan operations."""
    
    def __init__(self, total_steps: int, description: str = "Scanning", disable: bool = False):
        self.total_steps = total_steps
        self.current_step = 0
        self.description = description
        self.pbar = None
        self.start_time = time.time()
        self.disable = disable
    
    def __enter__(self):
        if not self.disable:
            self.pbar = tqdm(
                total=self.total_steps,
                desc=self.description,
                unit="step",
                bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}]',
                disable=self.disable
            )
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.pbar:
            self.pbar.close()
    
    def update(self, step: int = 1, description: str = None):
        """Update progress bar."""
        if self.pbar:
            if description:
                self.pbar.set_description(description)
            self.pbar.update(step)
            self.current_step += step
        elif self.disable and description:
            # If progress bar is disabled, just print the description
            print(f"[{self.description}] {description}")
    
    def set_description(self, description: str):
        """Set progress bar description."""
        if self.pbar:
            self.pbar.set_description(description)
        elif self.disable:
            print(f"[{self.description}] {description}")
    
    def finish(self):
        """Finish the progress bar."""
        if self.pbar:
            self.pbar.close()


@click.group()
@click.option('-v', '--verbose', count=True, help='Increase verbosity (use -v for INFO, -vv for DEBUG)')
@click.option('--log-dir', default='logs', help='Directory for log files')
@click.pass_context
def cli(ctx, verbose, log_dir):
    """API Security Scanner - Automated security testing for APIs."""
    # Ensure context object exists
    ctx.ensure_object(dict)
    
    # Setup logging
    logger_instance = setup_logging(verbose=verbose, log_dir=log_dir)
    ctx.obj['logger'] = logger_instance.get_logger()
    ctx.obj['verbose'] = verbose
    ctx.obj['log_dir'] = log_dir


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
        
        # Parse input
        with ScanProgressBar(1, "Parsing input", disable=no_progress or ctx.obj.get('verbose', 0) > 0) as progress:
            try:
                if input_file:
                    requests_data = parse_input(input_file)
                    input_type = "file"
                    input_source = input_file
                else:
                    requests_data = parse_input(curl_command)
                    input_type = "curl"
                    input_source = curl_command
                progress.update(1, f"Parsed {len(requests_data)} requests")
            except InputParserError as e:
                secho(f"Input parsing error: {e}", fg='red')
                sys.exit(1)
        
        # Setup authentication
        with ScanProgressBar(1, "Setting up authentication", disable=no_progress or ctx.obj.get('verbose', 0) > 0) as progress:
            auth_handler = None
            if auth_type and auth_name and auth_value:
                try:
                    auth_handler = create_auth_handler(auth_type, auth_name, auth_value)
                    progress.update(1, f"Authentication configured: {auth_type} - {auth_name}")
                except AuthenticationError as e:
                    secho(f"Authentication error: {e}", fg='red')
                    sys.exit(1)
            else:
                progress.update(1, "No authentication configured")
        
        # Apply authentication to requests
        if auth_handler:
            requests_data = auth_handler.apply_authentication(requests_data)
        
        # Initialize database
        with ScanProgressBar(1, "Initializing database", disable=no_progress or ctx.obj.get('verbose', 0) > 0) as progress:
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
            progress.update(1, f"Database initialized for target: {target_url}")
        
        # Initialize components
        with ScanProgressBar(1, "Initializing components", disable=no_progress or ctx.obj.get('verbose', 0) > 0) as progress:
            zap_manager = None
            plugin_manager = None
            
            if not no_zap:
                zap_manager = ZAPManager(zap_path, zap_port, zap_host)
            
            if not no_plugins:
                plugin_manager = PluginManager()
                progress.update(1, f"Loaded {len(plugin_manager.loaded_plugins)} custom plugins")
            else:
                progress.update(1, "Components initialized")
        
        # Start ZAP scanning
        zap_alerts = []
        if zap_manager and not no_zap:
            with ScanProgressBar(3, "ZAP Security Scan", disable=no_progress or ctx.obj.get('verbose', 0) > 0) as progress:
                try:
                    with zap_manager:
                        # Spider target
                        progress.set_description("Spidering target")
                        spider_success, spider_id = zap_manager.spider_target(
                            target_url, spider_depth, spider_children
                        )
                        progress.update(1, "Spidering completed")
                        
                        if spider_success:
                            # Active scan
                            progress.set_description("Performing active scan")
                            scan_success, scan_id_zap = zap_manager.active_scan_target(target_url)
                            progress.update(1, "Active scan completed")
                            
                            if scan_success:
                                # Get alerts
                                progress.set_description("Retrieving ZAP alerts")
                                zap_alerts = zap_manager.get_alerts(target_url)
                                
                                # Store ZAP alerts in database
                                for alert in zap_alerts:
                                    db_manager.add_zap_alert(scan_id, alert)
                                
                                progress.update(1, f"Found {len(zap_alerts)} ZAP alerts")
                            else:
                                progress.update(1, "Active scan failed")
                        else:
                            progress.update(2, "Spidering failed")
                            
                except ZAPManagerError as e:
                    secho(f"ZAP error: {e}", fg='red')
                    logger.error(f"ZAP operation failed: {e}")
        
        # Run custom plugins
        custom_alerts = []
        if plugin_manager and not no_plugins:
            plugin_count = len(plugin_manager.loaded_plugins)
            with ScanProgressBar(plugin_count, "Custom Plugin Scan", disable=no_progress or ctx.obj.get('verbose', 0) > 0) as progress:
                try:
                    plugin_results = plugin_manager.execute_all_plugins(
                        target_url, requests_data, 
                        auth_handler.get_auth_headers() if auth_handler else None
                    )
                    
                    for i, result in enumerate(plugin_results):
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
                            progress.update(1, f"{result.plugin_name}: {len(result.vulnerabilities)} issues found")
                        else:
                            progress.update(1, f"{result.plugin_name}: Failed - {result.error}")
                            logger.warning(f"Plugin {result.plugin_name} failed: {result.error}")
                    
                    progress.set_description(f"Custom plugins completed: {len(custom_alerts)} total issues")
                    
                except Exception as e:
                    secho(f"Plugin execution error: {e}", fg='red')
                    logger.error(f"Plugin execution failed: {e}")
        
        # Update scan completion
        with ScanProgressBar(1, "Finalizing scan", disable=no_progress or ctx.obj.get('verbose', 0) > 0) as progress:
            db_manager.update_scan_completion(scan_id, 'completed')
            
            # Get scan summary
            scan_summary = db_manager.get_scan_summary(scan_id)
            if not scan_summary:
                secho("Failed to retrieve scan summary", fg='red')
                sys.exit(1)
            progress.update(1, "Scan finalized")
        
        # Display results
        echo("\n" + "="*60)
        echo("SCAN COMPLETED")
        echo("="*60)
        echo(f"Scan ID: {scan_id}")
        echo(f"Target: {target_url}")
        echo(f"ZAP Alerts: {len(zap_alerts)}")
        echo(f"Custom Plugin Alerts: {len(custom_alerts)}")
        
        # Show performance stats if requested
        if performance_stats and scan_summary.get('performance_stats'):
            echo("\nPERFORMANCE STATISTICS:")
            for stat in scan_summary['performance_stats']:
                echo(f"  {stat['phase_name']}: {stat['duration']:.2f}s")
        
        # Generate reports
        if export or export_json:
            report_steps = 0
            if export:
                report_steps += 1
            if export_json:
                report_steps += 1
                
            with ScanProgressBar(report_steps, "Generating reports", disable=no_progress or ctx.obj.get('verbose', 0) > 0) as progress:
                report_generator = ReportGenerator()
                
                if export:
                    success = report_generator.generate_report(
                        scan_summary['scan'],
                        zap_alerts,
                        custom_alerts,
                        scan_summary.get('performance_stats', []),
                        export
                    )
                    if success:
                        progress.update(1, f"HTML report saved to: {export}")
                    else:
                        progress.update(1, "Failed to generate HTML report")
                        secho("Failed to generate HTML report", fg='red')
                
                if export_json:
                    success = report_generator.generate_json_report(
                        scan_summary['scan'],
                        zap_alerts,
                        custom_alerts,
                        scan_summary.get('performance_stats', []),
                        export_json
                    )
                    if success:
                        progress.update(1, f"JSON report saved to: {export_json}")
                    else:
                        progress.update(1, "Failed to generate JSON report")
                        secho("Failed to generate JSON report", fg='red')
        
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
            
            success = report_generator.generate_report(
                scan_data,
                zap_alerts_data,
                custom_alerts_data,
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
        plugin_manager = PluginManager()
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


if __name__ == '__main__':
    cli()
