#!/usr/bin/env python3
"""
Interactive CLI for Mobile Security Testing Tool
"""
import os
import sys
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt, Confirm

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))
from mobile_security_tester import MobileSecurityTester

def main():
    console = Console()
    console.print("[bold green]Welcome to the Interactive Mobile Security Testing CLI![/bold green]")
    console.print("[cyan]Let's get started with your mobile app security analysis.[/cyan]\n")

    # Step 1: Select file
    while True:
        file_path = Prompt.ask("Enter the path to your APK or IPA file")
        if os.path.exists(file_path) and file_path.lower().endswith((".apk", ".ipa")):
            break
        console.print("[red]Invalid file. Please enter a valid APK or IPA file path.[/red]")

    # Step 2: Choose tests
    test_options = ["static", "dynamic", "network", "storage", "code", "ai"]
    selected_tests = []
    console.print("\nSelect the types of tests to run:")
    for test in test_options:
        if Confirm.ask(f"Run {test.capitalize()} Analysis?", default=True):
            selected_tests.append(test)
    if not selected_tests:
        console.print("[yellow]No tests selected. Defaulting to all tests.[/yellow]")
        selected_tests = test_options

    # Step 3: Run analysis
    tester = MobileSecurityTester(debug=True)
    ext = Path(file_path).suffix.lower()
    console.print(f"\n[bold]Running analysis on:[/bold] {file_path}")
    if ext == ".apk":
        results = tester.analyze_apk(file_path, tests=selected_tests)
    else:
        results = tester.analyze_ipa(file_path, tests=selected_tests)

    # Step 4: Show summary
    console.print("\n[bold green]Analysis Complete![/bold green]")
    summary = results.get("summary", {})
    table = Table(title="Vulnerability Summary")
    table.add_column("Risk Level")
    table.add_column("Count")
    for level in ["critical", "high", "medium", "low"]:
        table.add_row(level.capitalize(), str(summary.get(level, 0)))
    console.print(table)

    # Step 5: Show AI-predicted vulnerabilities
    ai_vulns = [v for v in results.get("vulnerabilities", []) if v.get("type", "").startswith("AI-Predicted")]
    if ai_vulns:
        console.print("\n[bold magenta]AI-Predicted Vulnerabilities:[/bold magenta]")
        for vuln in ai_vulns:
            console.print(f"- [red]{vuln['type']}[/red]: {vuln['description']}")

    # Step 6: Save report
    if Confirm.ask("Do you want to save the report?", default=True):
        out_path = Prompt.ask("Enter output file name (e.g., report.html)", default="report.html")
        tester.generate_report(output_file=out_path, format="html")
        console.print(f"[green]Report saved to {out_path}[/green]")

    console.print("\n[bold green]Thank you for using the Interactive CLI![/bold green]")

if __name__ == "__main__":
    main() 