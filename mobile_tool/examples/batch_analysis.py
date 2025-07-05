#!/usr/bin/env python3
"""
Batch Analysis Example
Demonstrates how to perform security analysis on multiple APK/IPA files.
"""

import sys
import os
import json
from pathlib import Path
from datetime import datetime
import concurrent.futures
import time

# Add the src directory to the path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from mobile_security_tester import MobileSecurityTester

def analyze_single_file(file_path: str, output_dir: str, debug: bool = False) -> dict:
    """Analyze a single file and return results."""
    try:
        print(f"🔍 Analyzing: {Path(file_path).name}")
        
        # Initialize tester
        tester = MobileSecurityTester(debug=debug)
        
        # Determine file type and analyze
        file_ext = Path(file_path).suffix.lower()
        if file_ext == '.apk':
            results = tester.analyze_apk(file_path, tests=["static", "code", "storage", "network"])
        elif file_ext == '.ipa':
            results = tester.analyze_ipa(file_path, tests=["static", "code", "storage", "network"])
        else:
            return {"error": f"Unsupported file type: {file_ext}", "file": file_path}
        
        # Generate report
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_name = f"{Path(file_path).stem}_{timestamp}"
        
        report_file = tester.generate_report(
            output_file=os.path.join(output_dir, f"{base_name}.html"),
            format="html"
        )
        
        return {
            "file": file_path,
            "success": True,
            "results": results,
            "report": report_file,
            "summary": results.get("summary", {})
        }
        
    except Exception as e:
        return {
            "file": file_path,
            "success": False,
            "error": str(e)
        }

def main():
    """Run batch analysis example."""
    print("🔍 Mobile Security Testing Tool - Batch Analysis")
    print("=" * 60)
    
    # Check if directory is provided
    if len(sys.argv) < 2:
        print("Usage: python batch_analysis.py <directory> [max_workers]")
        print("Example: python batch_analysis.py ./apps/ 4")
        sys.exit(1)
    
    directory = sys.argv[1]
    max_workers = int(sys.argv[2]) if len(sys.argv) > 2 else 4
    
    # Check if directory exists
    if not os.path.exists(directory):
        print(f"❌ Error: Directory not found: {directory}")
        sys.exit(1)
    
    # Find APK and IPA files
    apk_files = list(Path(directory).glob("*.apk"))
    ipa_files = list(Path(directory).glob("*.ipa"))
    all_files = apk_files + ipa_files
    
    if not all_files:
        print(f"❌ Error: No APK or IPA files found in {directory}")
        sys.exit(1)
    
    print(f"📁 Found {len(all_files)} files to analyze:")
    print(f"  • APK files: {len(apk_files)}")
    print(f"  • IPA files: {len(ipa_files)}")
    print(f"  • Max workers: {max_workers}")
    
    # Create output directory
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = f"batch_analysis_{timestamp}"
    os.makedirs(output_dir, exist_ok=True)
    print(f"📁 Output directory: {output_dir}")
    
    # Batch analysis results
    batch_results = {
        "batch_info": {
            "directory": directory,
            "total_files": len(all_files),
            "apk_files": len(apk_files),
            "ipa_files": len(ipa_files),
            "start_time": datetime.now().isoformat(),
            "max_workers": max_workers
        },
        "results": [],
        "summary": {
            "successful": 0,
            "failed": 0,
            "total_vulnerabilities": 0,
            "critical_vulnerabilities": 0,
            "high_vulnerabilities": 0,
            "medium_vulnerabilities": 0,
            "low_vulnerabilities": 0
        }
    }
    
    start_time = time.time()
    
    try:
        # Perform batch analysis
        print(f"\n🚀 Starting batch analysis...")
        print("-" * 40)
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all analysis tasks
            future_to_file = {
                executor.submit(analyze_single_file, str(file_path), output_dir, "--debug" in sys.argv): file_path
                for file_path in all_files
            }
            
            # Process completed tasks
            for future in concurrent.futures.as_completed(future_to_file):
                file_path = future_to_file[future]
                try:
                    result = future.result()
                    batch_results["results"].append(result)
                    
                    if result["success"]:
                        batch_results["summary"]["successful"] += 1
                        print(f"✅ Completed: {Path(file_path).name}")
                        
                        # Update vulnerability counts
                        summary = result.get("summary", {})
                        batch_results["summary"]["total_vulnerabilities"] += summary.get("total_vulnerabilities", 0)
                        batch_results["summary"]["critical_vulnerabilities"] += summary.get("critical", 0)
                        batch_results["summary"]["high_vulnerabilities"] += summary.get("high", 0)
                        batch_results["summary"]["medium_vulnerabilities"] += summary.get("medium", 0)
                        batch_results["summary"]["low_vulnerabilities"] += summary.get("low", 0)
                    else:
                        batch_results["summary"]["failed"] += 1
                        print(f"❌ Failed: {Path(file_path).name} - {result.get('error', 'Unknown error')}")
                        
                except Exception as e:
                    batch_results["summary"]["failed"] += 1
                    print(f"❌ Exception: {Path(file_path).name} - {str(e)}")
                    batch_results["results"].append({
                        "file": str(file_path),
                        "success": False,
                        "error": str(e)
                    })
        
        # Calculate total time
        end_time = time.time()
        total_time = end_time - start_time
        batch_results["batch_info"]["end_time"] = datetime.now().isoformat()
        batch_results["batch_info"]["total_time"] = total_time
        
        # Generate batch summary
        print(f"\n📊 Batch Analysis Summary:")
        print("-" * 40)
        print(f"Total Files: {batch_results['batch_info']['total_files']}")
        print(f"Successful: {batch_results['summary']['successful']}")
        print(f"Failed: {batch_results['summary']['failed']}")
        print(f"Total Time: {total_time:.2f} seconds")
        print(f"Average Time per File: {total_time / len(all_files):.2f} seconds")
        
        print(f"\n🚨 Vulnerability Summary:")
        print("-" * 40)
        print(f"Total Vulnerabilities: {batch_results['summary']['total_vulnerabilities']}")
        print(f"Critical: {batch_results['summary']['critical_vulnerabilities']}")
        print(f"High: {batch_results['summary']['high_vulnerabilities']}")
        print(f"Medium: {batch_results['summary']['medium_vulnerabilities']}")
        print(f"Low: {batch_results['summary']['low_vulnerabilities']}")
        
        # Find most vulnerable apps
        vulnerable_apps = []
        for result in batch_results["results"]:
            if result["success"]:
                summary = result.get("summary", {})
                total_vulns = summary.get("total_vulnerabilities", 0)
                if total_vulns > 0:
                    vulnerable_apps.append({
                        "file": Path(result["file"]).name,
                        "vulnerabilities": total_vulns,
                        "risk": summary.get("overall_risk", "Unknown")
                    })
        
        if vulnerable_apps:
            vulnerable_apps.sort(key=lambda x: x["vulnerabilities"], reverse=True)
            print(f"\n🔴 Most Vulnerable Apps:")
            print("-" * 40)
            for i, app in enumerate(vulnerable_apps[:5], 1):
                print(f"{i}. {app['file']} - {app['vulnerabilities']} vulnerabilities ({app['risk']})")
        
        # Generate batch report
        print(f"\n📄 Generating batch report...")
        batch_report_file = os.path.join(output_dir, "batch_analysis_report.json")
        with open(batch_report_file, 'w', encoding='utf-8') as f:
            json.dump(batch_results, f, indent=2, ensure_ascii=False)
        
        # Generate HTML summary
        html_summary = generate_html_summary(batch_results, output_dir)
        
        print(f"✅ Batch analysis completed successfully!")
        print(f"📄 Batch report: {batch_report_file}")
        print(f"📄 HTML summary: {html_summary}")
        
        # Show individual file results
        print(f"\n📋 Individual File Results:")
        print("-" * 40)
        for result in batch_results["results"]:
            status = "✅" if result["success"] else "❌"
            file_name = Path(result["file"]).name
            if result["success"]:
                summary = result.get("summary", {})
                vulns = summary.get("total_vulnerabilities", 0)
                risk = summary.get("overall_risk", "Unknown")
                print(f"{status} {file_name} - {vulns} vulnerabilities ({risk})")
            else:
                error = result.get("error", "Unknown error")
                print(f"{status} {file_name} - {error}")
        
    except Exception as e:
        print(f"❌ Error during batch analysis: {str(e)}")
        if "--debug" in sys.argv:
            import traceback
            traceback.print_exc()
        sys.exit(1)

def generate_html_summary(batch_results: dict, output_dir: str) -> str:
    """Generate HTML summary of batch analysis."""
    html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Batch Analysis Summary</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 0 20px rgba(0,0,0,0.1);
        }}
        .header {{
            text-align: center;
            border-bottom: 3px solid #007bff;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }}
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }}
        .summary-item {{
            text-align: center;
            padding: 15px;
            background-color: #f8f9fa;
            border-radius: 8px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }}
        .summary-item h3 {{
            margin: 0;
            color: #007bff;
        }}
        .summary-item p {{
            margin: 5px 0 0 0;
            font-size: 1.5em;
            font-weight: bold;
        }}
        .critical {{ color: #dc3545; }}
        .high {{ color: #fd7e14; }}
        .medium {{ color: #ffc107; }}
        .low {{ color: #28a745; }}
        .success {{ color: #28a745; }}
        .failed {{ color: #dc3545; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        th {{
            background-color: #f8f9fa;
            font-weight: bold;
        }}
        .status-success {{ color: #28a745; }}
        .status-failed {{ color: #dc3545; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Batch Analysis Summary</h1>
            <p>Generated on {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        </div>

        <div class="summary-grid">
            <div class="summary-item">
                <h3>Total Files</h3>
                <p>{batch_results['batch_info']['total_files']}</p>
            </div>
            <div class="summary-item">
                <h3>Successful</h3>
                <p class="success">{batch_results['summary']['successful']}</p>
            </div>
            <div class="summary-item">
                <h3>Failed</h3>
                <p class="failed">{batch_results['summary']['failed']}</p>
            </div>
            <div class="summary-item">
                <h3>Total Time</h3>
                <p>{batch_results['batch_info']['total_time']:.2f}s</p>
            </div>
        </div>

        <h2>Vulnerability Summary</h2>
        <div class="summary-grid">
            <div class="summary-item">
                <h3>Total Vulnerabilities</h3>
                <p>{batch_results['summary']['total_vulnerabilities']}</p>
            </div>
            <div class="summary-item">
                <h3>Critical</h3>
                <p class="critical">{batch_results['summary']['critical_vulnerabilities']}</p>
            </div>
            <div class="summary-item">
                <h3>High</h3>
                <p class="high">{batch_results['summary']['high_vulnerabilities']}</p>
            </div>
            <div class="summary-item">
                <h3>Medium</h3>
                <p class="medium">{batch_results['summary']['medium_vulnerabilities']}</p>
            </div>
            <div class="summary-item">
                <h3>Low</h3>
                <p class="low">{batch_results['summary']['low_vulnerabilities']}</p>
            </div>
        </div>

        <h2>Analysis Results</h2>
        <table>
            <thead>
                <tr>
                    <th>File</th>
                    <th>Status</th>
                    <th>Vulnerabilities</th>
                    <th>Risk Level</th>
                    <th>Report</th>
                </tr>
            </thead>
            <tbody>
"""
    
    for result in batch_results["results"]:
        file_name = Path(result["file"]).name
        status = "✅ Success" if result["success"] else "❌ Failed"
        status_class = "status-success" if result["success"] else "status-failed"
        
        if result["success"]:
            summary = result.get("summary", {})
            vulns = summary.get("total_vulnerabilities", 0)
            risk = summary.get("overall_risk", "Unknown")
            report_link = f'<a href="{Path(result["report"]).name}">View Report</a>' if result.get("report") else "N/A"
        else:
            vulns = "N/A"
            risk = "N/A"
            report_link = "N/A"
        
        html_content += f"""
                <tr>
                    <td>{file_name}</td>
                    <td class="{status_class}">{status}</td>
                    <td>{vulns}</td>
                    <td>{risk}</td>
                    <td>{report_link}</td>
                </tr>
"""
    
    html_content += """
            </tbody>
        </table>
    </div>
</body>
</html>
"""
    
    html_file = os.path.join(output_dir, "batch_summary.html")
    with open(html_file, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    return html_file

if __name__ == "__main__":
    main() 