#!/usr/bin/env python3
"""
Test script for enhanced dynamic analysis with Nox emulator support
"""

import sys
import os
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from mobile_security_tester import MobileSecurityTester
from rich.console import Console
from rich.panel import Panel

def test_dynamic_analysis(apk_path=None):
    """Test dynamic analysis with Nox emulator."""
    console = Console()
    
    console.print(Panel.fit(
        "[bold green]Enhanced Dynamic Analysis Test[/bold green]\n"
        "[cyan]Testing with Nox emulator support[/cyan]",
        border_style="blue"
    ))
    
    # Initialize tester with debug mode
    tester = MobileSecurityTester(debug=True)
    
    # Test device connection
    console.print("\n[bold]1. Testing Device Connection...[/bold]")
    from src.analyzers.dynamic_analyzer import DynamicAnalyzer
    dynamic_analyzer = DynamicAnalyzer(debug=True)
    
    if dynamic_analyzer._check_device_connection():
        console.print("[green]✅ Device connected successfully![/green]")
        
        # Get device info
        device_info = dynamic_analyzer._get_device_info()
        console.print(f"[cyan]Device Info:[/cyan]")
        for key, value in device_info.items():
            console.print(f"  {key}: {value}")
    else:
        console.print("[red]❌ No device connected. Please ensure Nox emulator is running and ADB is connected.[/red]")
        return
    
    # Determine APK to use
    sample_apk = apk_path
    if not sample_apk:
        # Search in current directory
        for apk_file in Path(".").glob("*.apk"):
            sample_apk = str(apk_file)
            break
    if not sample_apk:
        # Search in uploads directory
        uploads_dir = Path("uploads")
        if uploads_dir.exists():
            for apk_file in uploads_dir.glob("*.apk"):
                sample_apk = str(apk_file)
                break
    
    if sample_apk:
        console.print(f"\n[bold]2. Testing Dynamic Analysis with: {sample_apk}[/bold]")
        
        try:
            # Run comprehensive analysis including dynamic
            results = tester.analyze_apk(sample_apk, tests=["static", "dynamic", "network", "storage", "code"])
            
            # Display results
            console.print("\n[bold green]✅ Dynamic Analysis Completed![/bold green]")
            
            # Show device info
            if "device_info" in results:
                device_info = results["device_info"]
                console.print(f"\n[cyan]Device Information:[/cyan]")
                console.print(f"  Manufacturer: {device_info.get('manufacturer', 'Unknown')}")
                console.print(f"  Model: {device_info.get('model', 'Unknown')}")
                console.print(f"  Android Version: {device_info.get('android_version', 'Unknown')}")
                console.print(f"  Emulator Type: {device_info.get('emulator_type', 'Unknown')}")
                console.print(f"  Root Status: {device_info.get('root_status', 'Unknown')}")
            
            # Show dynamic analysis results
            if "runtime_behavior" in results:
                runtime = results["runtime_behavior"]
                console.print(f"\n[cyan]Runtime Behavior:[/cyan]")
                console.print(f"  Activities Found: {len(runtime.get('activities', []))}")
                console.print(f"  Services Found: {len(runtime.get('services', []))}")
                
                if "monitoring_results" in runtime:
                    monitoring = runtime["monitoring_results"]
                    console.print(f"  CPU Usage Samples: {len(monitoring.get('cpu_usage', []))}")
                    console.print(f"  Memory Usage Samples: {len(monitoring.get('memory_usage', []))}")
                    console.print(f"  Network Activity Samples: {len(monitoring.get('network_activity', []))}")
                    console.print(f"  Logcat Entries: {len(monitoring.get('logcat_output', []))}")
            
            # Show vulnerabilities
            vulnerabilities = results.get("vulnerabilities", [])
            if vulnerabilities:
                console.print(f"\n[red]Vulnerabilities Found: {len(vulnerabilities)}[/red]")
                for i, vuln in enumerate(vulnerabilities[:5], 1):  # Show first 5
                    console.print(f"  {i}. {vuln.get('type', 'Unknown')} - {vuln.get('severity', 'Unknown')}")
            else:
                console.print(f"\n[green]No vulnerabilities found during dynamic analysis.[/green]")
            
            # Generate report
            report_file = tester.generate_report(format="html")
            console.print(f"\n[green]📄 Report saved: {report_file}[/green]")
            
        except Exception as e:
            console.print(f"[red]❌ Error during dynamic analysis: {str(e)}[/red]")
    else:
        console.print("\n[yellow]No APK file found in current directory or uploads folder. Please place an APK file to test dynamic analysis.[/yellow]")
        console.print("[cyan]You can also test device analysis without an APK:[/cyan]")
        
        try:
            results = tester.analyze_device("android")
            console.print("\n[bold green]✅ Device Analysis Completed![/bold green]")
            
            if "device_info" in results:
                device_info = results["device_info"]
                console.print(f"\n[cyan]Device Information:[/cyan]")
                for key, value in device_info.items():
                    console.print(f"  {key}: {value}")
            
            if "installed_apps" in results:
                apps = results["installed_apps"]
                console.print(f"\n[cyan]Installed Apps: {len(apps)}[/cyan]")
                for app in apps[:10]:  # Show first 10
                    console.print(f"  - {app.get('name', 'Unknown')} ({app.get('package', 'Unknown')})")
            
        except Exception as e:
            console.print(f"[red]❌ Error during device analysis: {str(e)}[/red]")

if __name__ == "__main__":
    apk_arg = sys.argv[1] if len(sys.argv) > 1 else None
    test_dynamic_analysis(apk_arg) 