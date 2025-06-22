#!/usr/bin/env python3
"""
Test script to verify diagnostics functionality
"""

import requests
import json
import time

def test_diagnostics():
    """Test the diagnostics endpoint"""
    
    base_url = "http://localhost:5000"
    
    print("🔍 Testing Diagnostics Functionality")
    print("=" * 50)
    
    # Test 1: Check if web UI is running
    print("\n1. Checking if web UI is accessible...")
    try:
        response = requests.get(f"{base_url}/", timeout=5)
        if response.status_code == 200:
            print("✅ Web UI is running and accessible")
        else:
            print(f"❌ Web UI returned status code: {response.status_code}")
            return False
    except requests.exceptions.RequestException as e:
        print(f"❌ Cannot connect to web UI: {e}")
        return False
    
    # Test 2: Test diagnostics endpoint
    print("\n2. Testing diagnostics endpoint...")
    try:
        response = requests.get(f"{base_url}/api/diagnostics", timeout=10)
        if response.status_code == 200:
            diagnostics = response.json()
            print("✅ Diagnostics endpoint responded successfully")
            
            # Display diagnostics information
            print("\n📊 Diagnostics Summary:")
            print("-" * 30)
            
            if 'metrics_summary' in diagnostics:
                metrics = diagnostics['metrics_summary']
                print(f"CPU Usage: {metrics.get('current_cpu', 'N/A')}%")
                print(f"Memory Usage: {metrics.get('current_memory', 'N/A')}%")
                print(f"Active Threads: {metrics.get('current_threads', 'N/A')}")
                print(f"Monitoring Duration: {metrics.get('monitoring_duration', 'N/A')}")
            
            if 'debug_stats' in diagnostics:
                stats = diagnostics['debug_stats']
                print(f"\n📈 Debug Statistics:")
                print(f"Request Count: {stats.get('request_count', 0)}")
                print(f"Error Count: {stats.get('error_count', 0)}")
                print(f"Active Scans: {stats.get('active_scans', 0)}")
                print(f"Completed Scans: {stats.get('completed_scans', 0)}")
                print(f"Failed Scans: {stats.get('failed_scans', 0)}")
            
            if 'diagnostics' in diagnostics and 'summary' in diagnostics['diagnostics']:
                system = diagnostics['diagnostics']['summary']
                print(f"\n💻 System Information:")
                print(f"Platform: {system.get('platform', 'N/A')}")
                print(f"Python Version: {system.get('python_version', 'N/A')}")
                print(f"Process ID: {system.get('process_id', 'N/A')}")
                print(f"Memory Usage: {system.get('memory_usage_mb', 'N/A')} MB")
                print(f"CPU Usage: {system.get('cpu_usage_percent', 'N/A')}%")
            
            if 'error' in diagnostics:
                print(f"\n⚠️  Error in diagnostics: {diagnostics['error']}")
                
        else:
            print(f"❌ Diagnostics endpoint returned status code: {response.status_code}")
            return False
    except requests.exceptions.RequestException as e:
        print(f"❌ Error testing diagnostics: {e}")
        return False
    
    # Test 3: Test diagnostics export
    print("\n3. Testing diagnostics export...")
    try:
        response = requests.post(f"{base_url}/api/diagnostics/export", timeout=10)
        if response.status_code == 200:
            export_result = response.json()
            if export_result.get('success'):
                print("✅ Diagnostics export successful")
                print(f"Export file: {export_result.get('file', 'N/A')}")
            else:
                print(f"❌ Diagnostics export failed: {export_result.get('error', 'Unknown error')}")
        else:
            print(f"❌ Diagnostics export returned status code: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"❌ Error testing diagnostics export: {e}")
    
    print("\n" + "=" * 50)
    print("🎯 Diagnostics Test Summary")
    print("=" * 50)
    print("The diagnostics functionality should now be working with:")
    print("• Real-time system metrics (CPU, Memory, Threads)")
    print("• Application statistics (scans, requests, errors)")
    print("• System information (platform, process details)")
    print("• Export functionality for debugging")
    print("\nTo test manually:")
    print("1. Open http://localhost:5000 in your browser")
    print("2. Go to the Logs & Diagnostics tab")
    print("3. Check the Diagnostics Summary section")
    print("4. Try the Export All Debug Data button")
    
    return True

if __name__ == "__main__":
    test_diagnostics() 