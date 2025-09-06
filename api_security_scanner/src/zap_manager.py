"""
ZAP (OWASP Zed Attack Proxy) integration manager.
Handles ZAP operations including spidering, active scanning, and alert retrieval.
"""

import time
import subprocess
import requests
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path
import json

from utils.logger import get_logger, LoggedTimer


class ZAPManagerError(Exception):
    """Custom exception for ZAP manager errors."""
    pass


class ZAPManager:
    """Manages ZAP operations and integration."""
    
    def __init__(self, zap_path: Optional[str] = None, zap_port: int = 8080, 
                 zap_host: str = 'localhost', api_key: Optional[str] = None):
        self.logger = get_logger(__name__)
        self.zap_path = zap_path
        self.zap_port = zap_port
        self.zap_host = zap_host
        self.api_key = api_key
        self.zap_process = None
        self.zap_api_url = f"http://{zap_host}:{zap_port}"
        self.is_running = False
        
        # Performance tracking
        self.performance_stats = {}
    
    def start_zap(self, headless: bool = True) -> bool:
        """
        Start ZAP daemon.
        
        Args:
            headless: Whether to run ZAP in headless mode
            
        Returns:
            True if ZAP started successfully
        """
        try:
            with LoggedTimer(self.logger, "ZAP startup"):
                if self.is_zap_running():
                    self.logger.info("ZAP is already running")
                    return True
                
                # Build ZAP command
                cmd = self._build_zap_command(headless)
                
                self.logger.info(f"Starting ZAP with command: {' '.join(cmd)}")
                
                # Start ZAP process
                self.zap_process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                
                # Wait for ZAP to start
                if self._wait_for_zap_startup():
                    self.is_running = True
                    self.logger.info("ZAP started successfully")
                    return True
                else:
                    self.logger.error("ZAP failed to start within timeout")
                    return False
                    
        except Exception as e:
            self.logger.error(f"Failed to start ZAP: {e}")
            return False
    
    def _build_zap_command(self, headless: bool) -> List[str]:
        """Build ZAP command line arguments."""
        cmd = []
        
        if self.zap_path:
            cmd.append(self.zap_path)
        else:
            # Try to find ZAP in common locations
            zap_locations = [
                'zap.sh',  # Linux/Mac
                'zap.bat',  # Windows
                '/usr/share/zaproxy/zap.sh',
                '/opt/zaproxy/zap.sh',
                'C:\\Program Files\\OWASP\\Zed Attack Proxy\\zap.bat'
            ]
            
            for location in zap_locations:
                if Path(location).exists():
                    cmd.append(location)
                    break
            else:
                raise ZAPManagerError("ZAP executable not found. Please specify zap_path.")
        
        # Add command line options
        if headless:
            cmd.extend(['-daemon'])
        
        cmd.extend([
            '-port', str(self.zap_port),
            '-host', self.zap_host,
            '-config', 'api.disablekey=true',  # Disable API key requirement
            '-config', 'api.addrs.addr.name=.*',
            '-config', 'api.addrs.addr.regex=true'
        ])
        
        return cmd
    
    def _wait_for_zap_startup(self, timeout: int = 60) -> bool:
        """Wait for ZAP to start and be ready."""
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            try:
                response = requests.get(f"{self.zap_api_url}/JSON/core/view/version/", 
                                      timeout=5)
                if response.status_code == 200:
                    self.logger.info(f"ZAP version: {response.json().get('version', 'Unknown')}")
                    return True
            except requests.exceptions.RequestException:
                pass
            
            time.sleep(2)
        
        return False
    
    def is_zap_running(self) -> bool:
        """Check if ZAP is running and accessible."""
        try:
            response = requests.get(f"{self.zap_api_url}/JSON/core/view/version/", 
                                  timeout=5)
            return response.status_code == 200
        except requests.exceptions.RequestException:
            return False
    
    def stop_zap(self) -> bool:
        """Stop ZAP daemon."""
        try:
            with LoggedTimer(self.logger, "ZAP shutdown"):
                if self.zap_process:
                    self.logger.info("Stopping ZAP process")
                    self.zap_process.terminate()
                    
                    # Wait for process to terminate
                    try:
                        self.zap_process.wait(timeout=30)
                    except subprocess.TimeoutExpired:
                        self.logger.warning("ZAP process did not terminate gracefully, forcing kill")
                        self.zap_process.kill()
                        self.zap_process.wait()
                    
                    self.zap_process = None
                
                self.is_running = False
                self.logger.info("ZAP stopped successfully")
                return True
                
        except Exception as e:
            self.logger.error(f"Failed to stop ZAP: {e}")
            return False
    
    def spider_target(self, target_url: str, max_depth: int = 5, 
                     max_children: int = 10) -> Tuple[bool, str]:
        """
        Spider a target URL to discover endpoints.
        
        Args:
            target_url: URL to spider
            max_depth: Maximum spider depth
            max_children: Maximum children per node
            
        Returns:
            Tuple of (success, scan_id)
        """
        try:
            with LoggedTimer(self.logger, f"Spidering {target_url}"):
                # Configure spider
                self._configure_spider(max_depth, max_children)
                
                # Start spider
                params = {
                    'url': target_url,
                    'maxChildren': max_children,
                    'recurse': 'true',
                    'contextName': '',
                    'subtreeOnly': 'false'
                }
                
                response = requests.get(f"{self.zap_api_url}/JSON/spider/action/scan/", 
                                      params=params, timeout=30)
                
                if response.status_code != 200:
                    raise ZAPManagerError(f"Failed to start spider: {response.text}")
                
                scan_id = response.json().get('scan')
                self.logger.info(f"Spider started with ID: {scan_id}")
                
                # Wait for spider to complete
                if self._wait_for_spider_completion(scan_id):
                    self.logger.info("Spider completed successfully")
                    return True, scan_id
                else:
                    self.logger.error("Spider failed to complete")
                    return False, scan_id
                    
        except Exception as e:
            self.logger.error(f"Spider operation failed: {e}")
            return False, ""
    
    def _configure_spider(self, max_depth: int, max_children: int):
        """Configure spider parameters."""
        try:
            # Set max depth
            params = {'Integer': str(max_depth)}
            requests.get(f"{self.zap_api_url}/JSON/spider/action/setOptionMaxDepth/", 
                        params=params, timeout=10)
            
            # Set max children
            params = {'Integer': str(max_children)}
            requests.get(f"{self.zap_api_url}/JSON/spider/action/setOptionMaxChildren/", 
                        params=params, timeout=10)
            
            self.logger.debug(f"Spider configured: max_depth={max_depth}, max_children={max_children}")
            
        except Exception as e:
            self.logger.warning(f"Failed to configure spider: {e}")
    
    def _wait_for_spider_completion(self, scan_id: str, timeout: int = 300) -> bool:
        """Wait for spider scan to complete."""
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            try:
                params = {'scanId': scan_id}
                response = requests.get(f"{self.zap_api_url}/JSON/spider/view/status/", 
                                      params=params, timeout=10)
                
                if response.status_code == 200:
                    status = response.json().get('status')
                    if status == '100':  # Completed
                        return True
                    elif status == '-1':  # Failed
                        self.logger.error("Spider scan failed")
                        return False
                    
                    # Log progress
                    self.logger.debug(f"Spider progress: {status}%")
                
                time.sleep(5)
                
            except requests.exceptions.RequestException as e:
                self.logger.warning(f"Error checking spider status: {e}")
                time.sleep(5)
        
        self.logger.error("Spider scan timed out")
        return False
    
    def active_scan_target(self, target_url: str, policy: str = "Default Policy") -> Tuple[bool, str]:
        """
        Perform active scan on target URL.
        
        Args:
            target_url: URL to scan
            policy: Scan policy to use
            
        Returns:
            Tuple of (success, scan_id)
        """
        try:
            with LoggedTimer(self.logger, f"Active scanning {target_url}"):
                # Start active scan
                params = {
                    'url': target_url,
                    'recurse': 'true',
                    'inScopeOnly': 'false',
                    'scanPolicyName': policy,
                    'method': 'GET',
                    'postData': ''
                }
                
                response = requests.get(f"{self.zap_api_url}/JSON/ascan/action/scan/", 
                                      params=params, timeout=30)
                
                if response.status_code != 200:
                    raise ZAPManagerError(f"Failed to start active scan: {response.text}")
                
                scan_id = response.json().get('scan')
                self.logger.info(f"Active scan started with ID: {scan_id}")
                
                # Wait for scan to complete
                if self._wait_for_active_scan_completion(scan_id):
                    self.logger.info("Active scan completed successfully")
                    return True, scan_id
                else:
                    self.logger.error("Active scan failed to complete")
                    return False, scan_id
                    
        except Exception as e:
            self.logger.error(f"Active scan operation failed: {e}")
            return False, ""
    
    def _wait_for_active_scan_completion(self, scan_id: str, timeout: int = 1800) -> bool:
        """Wait for active scan to complete."""
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            try:
                params = {'scanId': scan_id}
                response = requests.get(f"{self.zap_api_url}/JSON/ascan/view/status/", 
                                      params=params, timeout=10)
                
                if response.status_code == 200:
                    status = response.json().get('status')
                    if status == '100':  # Completed
                        return True
                    elif status == '-1':  # Failed
                        self.logger.error("Active scan failed")
                        return False
                    
                    # Log progress
                    self.logger.debug(f"Active scan progress: {status}%")
                
                time.sleep(10)
                
            except requests.exceptions.RequestException as e:
                self.logger.warning(f"Error checking active scan status: {e}")
                time.sleep(10)
        
        self.logger.error("Active scan timed out")
        return False
    
    def get_alerts(self, base_url: Optional[str] = None, 
                  risk_level: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Get alerts from ZAP.
        
        Args:
            base_url: Filter alerts by base URL
            risk_level: Filter alerts by risk level (High, Medium, Low, Informational)
            
        Returns:
            List of alert dictionaries
        """
        try:
            with LoggedTimer(self.logger, "Retrieving ZAP alerts"):
                params = {}
                if base_url:
                    params['baseurl'] = base_url
                
                response = requests.get(f"{self.zap_api_url}/JSON/core/view/alerts/", 
                                      params=params, timeout=30)
                
                if response.status_code != 200:
                    raise ZAPManagerError(f"Failed to get alerts: {response.text}")
                
                alerts = response.json().get('alerts', [])
                
                # Filter by risk level if specified
                if risk_level:
                    alerts = [alert for alert in alerts if alert.get('risk') == risk_level]
                
                self.logger.info(f"Retrieved {len(alerts)} alerts from ZAP")
                return alerts
                
        except Exception as e:
            self.logger.error(f"Failed to get alerts: {e}")
            return []
    
    def get_scan_progress(self, scan_type: str, scan_id: str) -> Dict[str, Any]:
        """
        Get progress information for a scan.
        
        Args:
            scan_type: Type of scan ('spider' or 'ascan')
            scan_id: Scan ID
            
        Returns:
            Dictionary containing progress information
        """
        try:
            if scan_type == 'spider':
                endpoint = f"{self.zap_api_url}/JSON/spider/view/status/"
            elif scan_type == 'ascan':
                endpoint = f"{self.zap_api_url}/JSON/ascan/view/status/"
            else:
                raise ZAPManagerError(f"Invalid scan type: {scan_type}")
            
            params = {'scanId': scan_id}
            response = requests.get(endpoint, params=params, timeout=10)
            
            if response.status_code == 200:
                return response.json()
            else:
                raise ZAPManagerError(f"Failed to get scan progress: {response.text}")
                
        except Exception as e:
            self.logger.error(f"Failed to get scan progress: {e}")
            return {}
    
    def add_context(self, context_name: str, target_url: str) -> bool:
        """
        Add a context to ZAP for better scanning.
        
        Args:
            context_name: Name of the context
            target_url: Target URL for the context
            
        Returns:
            True if context was added successfully
        """
        try:
            # Create context
            params = {'contextName': context_name}
            response = requests.get(f"{self.zap_api_url}/JSON/context/action/newContext/", 
                                  params=params, timeout=10)
            
            if response.status_code != 200:
                raise ZAPManagerError(f"Failed to create context: {response.text}")
            
            # Add URL to context
            params = {
                'contextName': context_name,
                'regex': f"^{target_url}.*"
            }
            response = requests.get(f"{self.zap_api_url}/JSON/context/action/includeInContext/", 
                                  params=params, timeout=10)
            
            if response.status_code == 200:
                self.logger.info(f"Context '{context_name}' created for {target_url}")
                return True
            else:
                raise ZAPManagerError(f"Failed to add URL to context: {response.text}")
                
        except Exception as e:
            self.logger.error(f"Failed to add context: {e}")
            return False
    
    def get_performance_stats(self) -> Dict[str, Any]:
        """Get performance statistics for ZAP operations."""
        return self.performance_stats.copy()
    
    def clear_performance_stats(self):
        """Clear performance statistics."""
        self.performance_stats.clear()
    
    def __enter__(self):
        """Context manager entry."""
        if not self.start_zap():
            raise ZAPManagerError("Failed to start ZAP")
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.stop_zap()
