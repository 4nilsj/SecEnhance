#!/usr/bin/env python3
"""
Debug Utilities for API Security Scanner
Debugging tools, monitoring functions, and diagnostic capabilities
"""

import os
import sys
import json
import time
import psutil
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import traceback

from debug_config import debug_logger, get_debug_stats, debug_config

class DebugMonitor:
    """Real-time monitoring and debugging utilities"""
    
    def __init__(self):
        self.monitoring = False
        self.monitor_thread = None
        self.metrics = {
            'cpu_usage': [],
            'memory_usage': [],
            'disk_usage': [],
            'network_io': [],
            'active_threads': [],
            'scan_operations': [],
            'error_count': 0,
            'request_count': 0
        }
        self.start_time = None
    
    def start_monitoring(self, interval: int = 5):
        """Start real-time monitoring"""
        if self.monitoring:
            debug_logger.warning("Monitoring already active")
            return
        
        self.monitoring = True
        self.start_time = datetime.now()
        self.monitor_thread = threading.Thread(target=self._monitor_loop, args=(interval,))
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        
        debug_logger.info("Debug monitoring started", interval=interval)
    
    def stop_monitoring(self):
        """Stop real-time monitoring"""
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        
        debug_logger.info("Debug monitoring stopped")
    
    def _monitor_loop(self, interval: int):
        """Monitoring loop"""
        while self.monitoring:
            try:
                self._collect_metrics()
                time.sleep(interval)
            except Exception as e:
                debug_logger.error("Error in monitoring loop", exception=e)
    
    def _collect_metrics(self):
        """Collect system and application metrics"""
        timestamp = datetime.now()
        
        # CPU usage
        cpu_percent = psutil.cpu_percent(interval=1)
        self.metrics['cpu_usage'].append({
            'timestamp': timestamp.isoformat(),
            'value': cpu_percent
        })
        
        # Memory usage
        memory = psutil.virtual_memory()
        self.metrics['memory_usage'].append({
            'timestamp': timestamp.isoformat(),
            'percent': memory.percent,
            'used': memory.used,
            'available': memory.available,
            'total': memory.total
        })
        
        # Disk usage
        disk = psutil.disk_usage('/')
        self.metrics['disk_usage'].append({
            'timestamp': timestamp.isoformat(),
            'percent': (disk.used / disk.total) * 100,
            'used': disk.used,
            'free': disk.free,
            'total': disk.total
        })
        
        # Network I/O
        network = psutil.net_io_counters()
        self.metrics['network_io'].append({
            'timestamp': timestamp.isoformat(),
            'bytes_sent': network.bytes_sent,
            'bytes_recv': network.bytes_recv,
            'packets_sent': network.packets_sent,
            'packets_recv': network.packets_recv
        })
        
        # Active threads
        active_threads = threading.active_count()
        self.metrics['active_threads'].append({
            'timestamp': timestamp.isoformat(),
            'count': active_threads
        })
        
        # Keep only last 100 entries
        for key in self.metrics:
            if isinstance(self.metrics[key], list) and len(self.metrics[key]) > 100:
                self.metrics[key] = self.metrics[key][-100:]
    
    def get_metrics_summary(self) -> Dict[str, Any]:
        """Get metrics summary"""
        if not self.metrics['cpu_usage']:
            return {'error': 'No metrics collected'}
        
        summary = {
            'monitoring_duration': str(datetime.now() - self.start_time) if self.start_time else 'N/A',
            'current_cpu': self.metrics['cpu_usage'][-1]['value'] if self.metrics['cpu_usage'] else 0,
            'current_memory': self.metrics['memory_usage'][-1]['percent'] if self.metrics['memory_usage'] else 0,
            'current_disk': self.metrics['disk_usage'][-1]['percent'] if self.metrics['disk_usage'] else 0,
            'current_threads': self.metrics['active_threads'][-1]['count'] if self.metrics['active_threads'] else 0,
            'avg_cpu': sum(m['value'] for m in self.metrics['cpu_usage']) / len(self.metrics['cpu_usage']),
            'avg_memory': sum(m['percent'] for m in self.metrics['memory_usage']) / len(self.metrics['memory_usage']),
            'max_cpu': max(m['value'] for m in self.metrics['cpu_usage']),
            'max_memory': max(m['percent'] for m in self.metrics['memory_usage']),
            'total_requests': self.metrics['request_count'],
            'total_errors': self.metrics['error_count']
        }
        
        return summary
    
    def export_metrics(self, filename: str = None) -> str:
        """Export metrics to JSON file"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"logs/metrics_{timestamp}.json"
        
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        
        export_data = {
            'export_timestamp': datetime.now().isoformat(),
            'monitoring_start': self.start_time.isoformat() if self.start_time else None,
            'metrics': self.metrics,
            'summary': self.get_metrics_summary()
        }
        
        with open(filename, 'w') as f:
            json.dump(export_data, f, indent=2, default=str)
        
        debug_logger.info(f"Metrics exported to {filename}")
        return filename

class DebugDiagnostics:
    """Diagnostic tools for troubleshooting"""
    
    @staticmethod
    def check_dependencies() -> Dict[str, Any]:
        """Check if all required dependencies are available"""
        dependencies = {
            'requests': 'HTTP client library',
            'yaml': 'YAML parser',
            'cryptography': 'Cryptographic functions',
            'pycryptodome': 'Crypto library',
            'beautifulsoup4': 'HTML parser',
            'lxml': 'XML parser',
            'jinja2': 'Template engine',
            'markdown': 'Markdown parser',
            'flask': 'Web framework'
        }
        
        results = {}
        missing = []
        
        for module, description in dependencies.items():
            try:
                __import__(module)
                results[module] = {
                    'status': 'available',
                    'description': description
                }
            except ImportError:
                results[module] = {
                    'status': 'missing',
                    'description': description
                }
                missing.append(module)
        
        results['summary'] = {
            'total': len(dependencies),
            'available': len(dependencies) - len(missing),
            'missing': len(missing),
            'missing_modules': missing
        }
        
        return results
    
    @staticmethod
    def check_file_permissions() -> Dict[str, Any]:
        """Check file and directory permissions"""
        directories = ['logs', 'uploads', 'templates', 'static']
        files = ['debug_config.py', 'api_security_scanner.py', 'web_ui.py']
        
        results = {
            'directories': {},
            'files': {},
            'summary': {'accessible': 0, 'inaccessible': 0}
        }
        
        # Check directories
        for directory in directories:
            try:
                if os.path.exists(directory):
                    os.access(directory, os.R_OK | os.W_OK)
                    results['directories'][directory] = {
                        'status': 'accessible',
                        'exists': True,
                        'readable': True,
                        'writable': True
                    }
                    results['summary']['accessible'] += 1
                else:
                    results['directories'][directory] = {
                        'status': 'missing',
                        'exists': False
                    }
                    results['summary']['inaccessible'] += 1
            except Exception as e:
                results['directories'][directory] = {
                    'status': 'error',
                    'error': str(e)
                }
                results['summary']['inaccessible'] += 1
        
        # Check files
        for file in files:
            try:
                if os.path.exists(file):
                    os.access(file, os.R_OK)
                    results['files'][file] = {
                        'status': 'accessible',
                        'exists': True,
                        'readable': True,
                        'size': os.path.getsize(file)
                    }
                    results['summary']['accessible'] += 1
                else:
                    results['files'][file] = {
                        'status': 'missing',
                        'exists': False
                    }
                    results['summary']['inaccessible'] += 1
            except Exception as e:
                results['files'][file] = {
                    'status': 'error',
                    'error': str(e)
                }
                results['summary']['inaccessible'] += 1
        
        return results
    
    @staticmethod
    def check_network_connectivity() -> Dict[str, Any]:
        """Check network connectivity to common endpoints"""
        import requests
        
        endpoints = [
            'https://httpbin.org/status/200',
            'https://api.github.com',
            'https://jsonplaceholder.typicode.com/posts/1'
        ]
        
        results = {}
        
        for endpoint in endpoints:
            try:
                start_time = time.time()
                response = requests.get(endpoint, timeout=10)
                duration = time.time() - start_time
                
                results[endpoint] = {
                    'status': 'reachable',
                    'status_code': response.status_code,
                    'response_time': duration,
                    'content_length': len(response.content)
                }
            except Exception as e:
                results[endpoint] = {
                    'status': 'unreachable',
                    'error': str(e)
                }
        
        return results
    
    @staticmethod
    def check_system_resources() -> Dict[str, Any]:
        """Check system resource availability"""
        try:
            cpu_count = psutil.cpu_count()
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            return {
                'cpu': {
                    'count': cpu_count,
                    'usage_percent': psutil.cpu_percent(interval=1)
                },
                'memory': {
                    'total': memory.total,
                    'available': memory.available,
                    'used': memory.used,
                    'percent': memory.percent
                },
                'disk': {
                    'total': disk.total,
                    'used': disk.used,
                    'free': disk.free,
                    'percent': (disk.used / disk.total) * 100
                },
                'network': {
                    'interfaces': list(psutil.net_if_addrs().keys())
                }
            }
        except Exception as e:
            return {'error': str(e)}
    
    @staticmethod
    def run_full_diagnostics() -> Dict[str, Any]:
        """Run complete system diagnostics"""
        debug_logger.info("Running full system diagnostics")
        
        diagnostics = {
            'timestamp': datetime.now().isoformat(),
            'dependencies': DebugDiagnostics.check_dependencies(),
            'permissions': DebugDiagnostics.check_file_permissions(),
            'network': DebugDiagnostics.check_network_connectivity(),
            'system': DebugDiagnostics.check_system_resources(),
            'debug_stats': get_debug_stats()
        }
        
        # Export diagnostics
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"logs/diagnostics_{timestamp}.json"
        
        os.makedirs('logs', exist_ok=True)
        with open(filename, 'w') as f:
            json.dump(diagnostics, f, indent=2, default=str)
        
        debug_logger.info(f"Diagnostics exported to {filename}")
        return diagnostics

class DebugProfiler:
    """Performance profiling utilities"""
    
    def __init__(self):
        self.profiles = {}
        self.active_profiles = {}
    
    def start_profile(self, name: str):
        """Start profiling a function or operation"""
        self.active_profiles[name] = {
            'start_time': time.time(),
            'start_memory': psutil.Process().memory_info().rss
        }
        debug_logger.debug(f"Started profiling: {name}")
    
    def end_profile(self, name: str) -> Dict[str, Any]:
        """End profiling and return results"""
        if name not in self.active_profiles:
            debug_logger.warning(f"Profile {name} not found")
            return {}
        
        end_time = time.time()
        end_memory = psutil.Process().memory_info().rss
        
        profile_data = self.active_profiles[name]
        duration = end_time - profile_data['start_time']
        memory_delta = end_memory - profile_data['start_memory']
        
        result = {
            'name': name,
            'duration': duration,
            'memory_delta': memory_delta,
            'start_time': profile_data['start_time'],
            'end_time': end_time
        }
        
        if name not in self.profiles:
            self.profiles[name] = []
        
        self.profiles[name].append(result)
        del self.active_profiles[name]
        
        debug_logger.debug(f"Ended profiling: {name}", duration=duration, memory_delta=memory_delta)
        return result
    
    def get_profile_summary(self, name: str = None) -> Dict[str, Any]:
        """Get profiling summary"""
        if name:
            if name not in self.profiles:
                return {'error': f'Profile {name} not found'}
            
            profiles = self.profiles[name]
        else:
            profiles = []
            for profile_list in self.profiles.values():
                profiles.extend(profile_list)
        
        if not profiles:
            return {'error': 'No profiles found'}
        
        durations = [p['duration'] for p in profiles]
        memory_deltas = [p['memory_delta'] for p in profiles]
        
        return {
            'total_runs': len(profiles),
            'avg_duration': sum(durations) / len(durations),
            'min_duration': min(durations),
            'max_duration': max(durations),
            'avg_memory_delta': sum(memory_deltas) / len(memory_deltas),
            'total_duration': sum(durations),
            'total_memory_delta': sum(memory_deltas)
        }
    
    def export_profiles(self, filename: str = None) -> str:
        """Export profiling data"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"logs/profiles_{timestamp}.json"
        
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        
        export_data = {
            'export_timestamp': datetime.now().isoformat(),
            'profiles': self.profiles,
            'summary': {name: self.get_profile_summary(name) for name in self.profiles}
        }
        
        with open(filename, 'w') as f:
            json.dump(export_data, f, indent=2, default=str)
        
        debug_logger.info(f"Profiles exported to {filename}")
        return filename

# Global instances
debug_monitor = DebugMonitor()
debug_profiler = DebugProfiler()

def start_debug_monitoring(interval: int = 5):
    """Start debug monitoring"""
    debug_monitor.start_monitoring(interval)

def stop_debug_monitoring():
    """Stop debug monitoring"""
    debug_monitor.stop_monitoring()

def get_debug_summary() -> Dict[str, Any]:
    """Get comprehensive debug summary"""
    return {
        'debug_stats': get_debug_stats(),
        'metrics_summary': debug_monitor.get_metrics_summary(),
        'profile_summary': debug_profiler.get_profile_summary(),
        'diagnostics': DebugDiagnostics.run_full_diagnostics()
    }

def export_debug_data():
    """Export all debug data"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Export debug logs
    debug_logger.export_debug_data(f"logs/debug_export_{timestamp}.json")
    
    # Export metrics
    debug_monitor.export_metrics(f"logs/metrics_{timestamp}.json")
    
    # Export profiles
    debug_profiler.export_profiles(f"logs/profiles_{timestamp}.json")
    
    # Export diagnostics
    DebugDiagnostics.run_full_diagnostics()
    
    debug_logger.info("All debug data exported", timestamp=timestamp)

if __name__ == '__main__':
    # Run diagnostics
    print("🔍 Running API Security Scanner Diagnostics...")
    diagnostics = DebugDiagnostics.run_full_diagnostics()
    
    print("\n📊 Dependencies Check:")
    deps = diagnostics['dependencies']
    for module, info in deps.items():
        if module != 'summary':
            status = "✅" if info['status'] == 'available' else "❌"
            print(f"  {status} {module}: {info['description']}")
    
    print(f"\n📈 Summary: {deps['summary']['available']}/{deps['summary']['total']} dependencies available")
    
    if deps['summary']['missing'] > 0:
        print(f"❌ Missing: {', '.join(deps['summary']['missing_modules'])}")
    
    print("\n🔧 System Resources:")
    system = diagnostics['system']
    if 'error' not in system:
        print(f"  CPU: {system['cpu']['usage_percent']:.1f}% ({system['cpu']['count']} cores)")
        print(f"  Memory: {system['memory']['percent']:.1f}% ({system['memory']['used'] // (1024**3):.1f}GB / {system['memory']['total'] // (1024**3):.1f}GB)")
        print(f"  Disk: {system['disk']['percent']:.1f}% ({system['disk']['used'] // (1024**3):.1f}GB / {system['disk']['total'] // (1024**3):.1f}GB)")
    
    print("\n🌐 Network Connectivity:")
    network = diagnostics['network']
    for endpoint, info in network.items():
        status = "✅" if info['status'] == 'reachable' else "❌"
        print(f"  {status} {endpoint}: {info.get('status_code', 'N/A')} ({info.get('response_time', 0):.3f}s)")
    
    print(f"\n📁 Diagnostics saved to: logs/diagnostics_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json") 