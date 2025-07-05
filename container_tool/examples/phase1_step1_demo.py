#!/usr/bin/env python3
"""
Phase 1, Step 1 Demo: Basic OS Package Vulnerability Scanning for Debian-based images
Image Extraction - Use Docker SDK to pull an image and extract its layers.
"""

import json
import sys
import time
from pathlib import Path

# Add the src directory to the path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from analyzers.debian_package_analyzer import DebianPackageAnalyzer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.tree import Tree

def demo_image_extraction():
    """Demonstrate Phase 1, Step 1: Image extraction for Debian-based images."""
    console = Console()
    console.print(Panel.fit(
        "[bold cyan]Phase 1, Step 1: Debian Image Extraction[/bold cyan]\n"
        "Basic OS Package Vulnerability Scanning for Debian-based images\n"
        "Step 1: Image Extraction - Use Docker SDK to pull an image and extract its layers",
        border_style="cyan"
    ))
    
    # Initialize Debian package analyzer
    analyzer = DebianPackageAnalyzer(debug=True)
    
    # Sample Debian-based images to test
    test_images = [
        "ubuntu:20.04",
        "debian:bullseye",
        "ubuntu:22.04"
    ]
    
    for image_name in test_images:
        console.print(f"\n[bold yellow]Testing image extraction: {image_name}[/bold yellow]")
        
        try:
            # Extract Debian image
            extraction_results = analyzer.extract_debian_image(image_name)
            
            # Display results
            display_extraction_results(console, extraction_results)
            
            # Generate and save report
            report = analyzer.generate_extraction_report(extraction_results)
            save_extraction_report(report, image_name)
            
        except Exception as e:
            console.print(f"[red]Error extracting {image_name}: {str(e)}[/red]")

def display_extraction_results(console: Console, results: dict):
    """Display extraction results in a formatted way."""
    
    # Basic extraction info
    console.print(f"\n[bold]✅ Extraction Results for {results.get('image_name', 'Unknown')}[/bold]")
    
    info_table = Table(title="Extraction Information")
    info_table.add_column("Metric", style="cyan")
    info_table.add_column("Value", style="magenta")
    
    info_table.add_row("Extraction Time", f"{results.get('extraction_time', 0):.2f} seconds")
    info_table.add_row("Total Layers", str(len(results.get('layers', []))))
    info_table.add_row("Total Size", f"{results.get('total_size', 0) / (1024*1024):.2f} MB")
    info_table.add_row("Extraction Path", results.get('extraction_path', 'N/A'))
    
    console.print(info_table)
    
    # Image metadata
    metadata = results.get('metadata', {})
    if metadata:
        console.print("\n[bold]📋 Image Metadata[/bold]")
        
        meta_table = Table(title="Image Details")
        meta_table.add_column("Property", style="cyan")
        meta_table.add_column("Value", style="magenta")
        
        meta_table.add_row("Image ID", metadata.get('id', 'N/A')[:12] + '...')
        meta_table.add_row("Tags", ', '.join(metadata.get('tags', [])))
        meta_table.add_row("Architecture", metadata.get('architecture', 'N/A'))
        meta_table.add_row("OS", metadata.get('os', 'N/A'))
        meta_table.add_row("Size", f"{metadata.get('size', 0) / (1024*1024):.2f} MB")
        meta_table.add_row("Created", metadata.get('created', 'N/A'))
        
        console.print(meta_table)
    
    # Debian information
    debian_info = results.get('debian_info', {})
    if debian_info:
        console.print("\n[bold]🐧 Debian Information[/bold]")
        
        debian_table = Table(title="Distribution Details")
        debian_table.add_column("Property", style="cyan")
        debian_table.add_column("Value", style="magenta")
        
        debian_table.add_row("Distribution", debian_info.get('distribution', 'N/A'))
        debian_table.add_row("Version", debian_info.get('version', 'N/A'))
        debian_table.add_row("Codename", debian_info.get('codename', 'N/A'))
        debian_table.add_row("Architecture", debian_info.get('architecture', 'N/A'))
        debian_table.add_row("Package Count", str(debian_info.get('package_count', 0)))
        debian_table.add_row("Package Managers", ', '.join(debian_info.get('package_managers', [])))
        
        console.print(debian_table)
    
    # Layer analysis
    layers = results.get('layers', [])
    if layers:
        console.print(f"\n[bold]📦 Layer Analysis ({len(layers)} layers)[/bold]")
        
        layer_table = Table(title="Layer Details")
        layer_table.add_column("Layer", style="cyan")
        layer_table.add_column("Size (MB)", style="magenta")
        layer_table.add_column("Files", style="green")
        layer_table.add_column("Debian Files", style="yellow")
        layer_table.add_column("Packages", style="blue")
        
        for layer in layers:
            layer_table.add_row(
                f"Layer {layer.get('index', 0)}",
                f"{layer.get('size', 0) / (1024*1024):.2f}",
                str(layer.get('files', {}).get('total', 0)),
                str(layer.get('files', {}).get('debian_files', 0)),
                str(len(layer.get('debian_packages', [])))
            )
        
        console.print(layer_table)
        
        # Show detailed layer information
        console.print("\n[bold]🔍 Detailed Layer Information[/bold]")
        for layer in layers[:3]:  # Show first 3 layers
            display_layer_details(console, layer)
    
    # Errors
    errors = results.get('errors', [])
    if errors:
        console.print(f"\n[bold red]❌ Errors ({len(errors)})[/bold red]")
        for error in errors:
            console.print(f"  • {error}")

def display_layer_details(console: Console, layer: dict):
    """Display detailed information about a specific layer."""
    layer_index = layer.get('index', 0)
    
    console.print(f"\n[bold]Layer {layer_index}[/bold]")
    
    # File statistics
    files = layer.get('files', {})
    console.print(f"  📁 Files: {files.get('total', 0)} total, {files.get('executables', 0)} executables, {files.get('config_files', 0)} config files")
    
    # Debian files found
    debian_files = layer.get('debian_files_found', [])
    if debian_files:
        console.print(f"  🐧 Debian Files: {len(debian_files)} found")
        for deb_file in debian_files[:5]:  # Show first 5
            console.print(f"    • {deb_file['path']} ({deb_file['type']})")
        if len(debian_files) > 5:
            console.print(f"    ... and {len(debian_files) - 5} more")
    
    # Packages found
    packages = layer.get('debian_packages', [])
    if packages:
        console.print(f"  📦 Packages: {len(packages)} found")
        for package in packages[:5]:  # Show first 5
            console.print(f"    • {package.get('name', 'N/A')} {package.get('version', 'N/A')}")
        if len(packages) > 5:
            console.print(f"    ... and {len(packages) - 5} more")
    
    # Modifications
    modifications = layer.get('modifications', [])
    if modifications:
        console.print(f"  🔧 Modifications: {len(modifications)} detected")
        for mod in modifications:
            console.print(f"    • {mod['type']}: {mod['indicator']}")

def save_extraction_report(report: dict, image_name: str):
    """Save extraction report to file."""
    try:
        # Create reports directory
        reports_dir = Path("reports")
        reports_dir.mkdir(exist_ok=True)
        
        # Generate filename
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        safe_image_name = image_name.replace(':', '_').replace('/', '_')
        filename = f"debian_extraction_{safe_image_name}_{timestamp}.json"
        filepath = reports_dir / filename
        
        # Save report
        with open(filepath, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        print(f"📄 Extraction report saved: {filepath}")
        
    except Exception as e:
        print(f"❌ Error saving report: {str(e)}")

def demo_layer_extraction_details():
    """Demonstrate detailed layer extraction process."""
    console = Console()
    console.print(Panel.fit(
        "[bold cyan]Layer Extraction Process Details[/bold cyan]\n"
        "Step-by-step breakdown of how layers are extracted and analyzed",
        border_style="cyan"
    ))
    
    console.print("\n[bold]🔧 Layer Extraction Process:[/bold]")
    
    steps = [
        {
            "step": "1.1",
            "title": "Pull Docker Image",
            "description": "Use Docker SDK to pull image if not present locally",
            "code": "docker_client.images.pull(image_name)"
        },
        {
            "step": "1.2", 
            "title": "Extract Image Metadata",
            "description": "Extract comprehensive image information (ID, tags, size, architecture)",
            "code": "image.attrs.get('Config', {}), image.attrs.get('RootFS', {})"
        },
        {
            "step": "1.3",
            "title": "Save Image to Tar",
            "description": "Save Docker image to tar file for extraction",
            "code": "image.save() -> tar file"
        },
        {
            "step": "1.4",
            "title": "Extract Tar Contents",
            "description": "Extract tar file to reveal layer structure",
            "code": "tarfile.extractall() -> layer directories"
        },
        {
            "step": "1.5",
            "title": "Analyze Each Layer",
            "description": "Analyze each layer for files, packages, and modifications",
            "code": "walk through layer directories"
        },
        {
            "step": "1.6",
            "title": "Extract Debian Packages",
            "description": "Parse dpkg status files and package information",
            "code": "parse /var/lib/dpkg/status"
        }
    ]
    
    for step in steps:
        console.print(f"\n[bold]{step['step']}. {step['title']}[/bold]")
        console.print(f"  {step['description']}")
        console.print(f"  [dim]Code: {step['code']}[/dim]")

def demo_debian_specific_features():
    """Demonstrate Debian-specific features and file detection."""
    console = Console()
    console.print(Panel.fit(
        "[bold cyan]Debian-Specific Features[/bold cyan]\n"
        "Specialized detection and analysis for Debian-based distributions",
        border_style="cyan"
    ))
    
    console.print("\n[bold]🐧 Debian File Detection:[/bold]")
    
    debian_files = [
        "/var/lib/dpkg/status",
        "/var/lib/dpkg/available", 
        "/etc/apt/sources.list",
        "/etc/apt/sources.list.d/",
        "/var/cache/apt/archives/",
        "/var/lib/apt/lists/",
        "/usr/share/doc/",
        "/DEBIAN/",
        "/debian/"
    ]
    
    for file_path in debian_files:
        console.print(f"  • {file_path}")
    
    console.print("\n[bold]📦 Package Information Extraction:[/bold]")
    
    package_info = [
        "Package name and version",
        "Architecture",
        "Description",
        "Dependencies",
        "Installed size",
        "Status (installed, config-files, etc.)",
        "Source package information"
    ]
    
    for info in package_info:
        console.print(f"  • {info}")
    
    console.print("\n[bold]🔍 Layer Modification Detection:[/bold]")
    
    modifications = [
        "Package installation patterns",
        "File creation in /usr/bin/, /usr/sbin/",
        "Configuration file changes in /etc/",
        "User/group creation",
        "Permission modifications"
    ]
    
    for mod in modifications:
        console.print(f"  • {mod}")

def main():
    """Main demo function."""
    console = Console()
    
    console.print(Panel.fit(
        "[bold green]Phase 1, Step 1: Debian Image Extraction Demo[/bold green]\n"
        "This demo showcases the first step of basic OS package vulnerability scanning:\n"
        "• Docker image extraction using Docker SDK\n"
        "• Layer-by-layer analysis\n"
        "• Debian-specific file detection\n"
        "• Package information extraction\n"
        "• Comprehensive reporting",
        border_style="green"
    ))
    
    # Run main extraction demo
    demo_image_extraction()
    
    # Show process details
    demo_layer_extraction_details()
    
    # Show Debian-specific features
    demo_debian_specific_features()
    
    console.print(Panel.fit(
        "[bold green]✅ Phase 1, Step 1 Demo Complete![/bold green]\n"
        "Successfully demonstrated image extraction for Debian-based containers.\n"
        "Next steps would include:\n"
        "• Package vulnerability scanning\n"
        "• CVE matching\n"
        "• Security assessment",
        border_style="green"
    ))

if __name__ == "__main__":
    main() 