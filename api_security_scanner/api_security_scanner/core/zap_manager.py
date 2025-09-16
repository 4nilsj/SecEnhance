"""
ZAP (OWASP Zed Attack Proxy) integration manager.
Handles ZAP operations including spidering, active scanning, and alert retrieval.
"""

import time
import subprocess
import requests
import signal
import threading
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path
import json
import os

from ..utils.logger import get_logger, LoggedTimer
from .config import get_config


class ZAPManagerError(Exception):
    """Custom exception for ZAP manager errors."""
    pass


class ZAPManager:
    """Manages ZAP operations and integration."""
    
    def __init__(self, zap_path: Optional[str] = None, zap_port: Optional[int] = None, 
                 zap_host: Optional[str] = None, api_key: Optional[str] = None,
                 scan_mode_config: Optional[Dict[str, Any]] = None, proxy_config: Optional[Any] = None):
        self.logger = get_logger(__name__)
        config = get_config()
        
        # Use provided values or fall back to configuration
        self.zap_path = zap_path or config.zap.path
        self.zap_port = zap_port or config.zap.port
        self.zap_host = zap_host or config.zap.host
        self.api_key = api_key or config.zap.api_key
        self.timeout = config.zap.timeout
        self.max_scan_time = config.zap.max_scan_time
        self.spider_depth = config.zap.spider_depth
        self.max_children = config.zap.max_children
        self.thread_count = config.zap.thread_count
        
        # Apply scan mode configuration if provided
        if scan_mode_config:
            self._apply_scan_mode_config(scan_mode_config)
        
        # Store proxy configuration
        self.proxy_config = proxy_config
        
        self.zap_process = None
        self.zap_api_url = f"http://{self.zap_host}:{self.zap_port}"
        self.is_running = False
        self.use_external_zap = config.zap.external_zap
        
        # Performance tracking
        self.performance_stats = {}
        
        # Scan cancellation support
        self._cancellation_requested = False
        self._active_scans = {}  # Track active scan IDs
        self._scan_lock = threading.Lock()
        
        # Load container configuration
        self._load_container_config()
        
        # Auto-detect ZAP path if not provided
        if not self.zap_path:
            self.zap_path = self._get_default_zap_path()
        
        self.logger.info(f"ZAP Manager initialized: host={self.zap_host}, port={self.zap_port}, external={self.use_external_zap}")
    
    def _make_zap_request(self, url: str, params: Optional[Dict[str, Any]] = None, 
                         timeout: int = 10) -> requests.Response:
        """
        Make a request to ZAP API with optional proxy support.
        
        Args:
            url: The ZAP API URL
            params: Query parameters
            timeout: Request timeout
            
        Returns:
            Response object
        """
        # Prepare request arguments
        request_kwargs = {'timeout': timeout}
        
        # Add proxy configuration if available
        if self.proxy_config and hasattr(self.proxy_config, 'is_configured') and self.proxy_config.is_configured():
            from ..utils.proxy_handler import ProxyHandler
            proxy_handler = ProxyHandler(self.proxy_config)
            proxy_kwargs = proxy_handler.get_request_kwargs()
            
            # Add proxy settings explicitly
            if 'proxies' in proxy_kwargs:
                request_kwargs['proxies'] = proxy_kwargs['proxies']
            if 'verify' in proxy_kwargs:
                request_kwargs['verify'] = proxy_kwargs['verify']
            
            if proxy_kwargs.get('proxies'):
                self.logger.debug(f"Using proxy for ZAP API request: {proxy_kwargs['proxies']}")
        
        return requests.get(url, params=params, **request_kwargs)  # type: ignore
    
    def _apply_scan_mode_config(self, scan_mode_config: Dict[str, Any]):
        """Apply scan mode configuration to ZAP settings."""
        try:
            # Apply spider settings
            if 'spider_depth' in scan_mode_config:
                self.spider_depth = scan_mode_config['spider_depth']
            if 'spider_children' in scan_mode_config:
                self.max_children = scan_mode_config['spider_children']
            
            # Apply scan timing settings
            if 'max_scan_time' in scan_mode_config:
                self.max_scan_time = scan_mode_config['max_scan_time']
            if 'timeout' in scan_mode_config:
                self.timeout = scan_mode_config['timeout']
            
            # Apply concurrency settings
            if 'concurrent_requests' in scan_mode_config:
                self.thread_count = scan_mode_config['concurrent_requests']
            
            # Store scan mode specific settings for later use
            self.scan_mode_config = scan_mode_config
            
            self.logger.info(f"Applied scan mode configuration: spider_depth={self.spider_depth}, "
                           f"max_children={self.max_children}, thread_count={self.thread_count}")
            
        except Exception as e:
            self.logger.warning(f"Failed to apply some scan mode settings: {e}")
    
    def _get_scan_policy(self, default_policy: str) -> str:
        """Determine scan policy based on scan mode configuration."""
        if hasattr(self, 'scan_mode_config') and self.scan_mode_config:
            aggressive = self.scan_mode_config.get('aggressive_scanning', False)
            if aggressive:
                return "Attack Policy"  # More aggressive scanning
            else:
                return "Default Policy"  # Conservative scanning
        return default_policy
    
    def _configure_scan_settings(self):
        """Configure ZAP settings based on scan mode."""
        if not hasattr(self, 'scan_mode_config') or not self.scan_mode_config:
            return
        
        try:
            config = self.scan_mode_config
            
            # Configure request delay
            if 'request_delay' in config:
                delay_ms = int(config['request_delay'] * 1000)  # Convert to milliseconds
                params = {'Integer': str(delay_ms)}
                self._make_zap_request(f"{self.zap_api_url}/JSON/ascan/action/setOptionDelayInMs/", 
                                     params=params, timeout=10)
                self.logger.info(f"Set ZAP request delay to {delay_ms}ms")
            
            # Configure thread count
            if 'concurrent_requests' in config:
                thread_count = config['concurrent_requests']
                params = {'Integer': str(thread_count)}
                self._make_zap_request(f"{self.zap_api_url}/JSON/ascan/action/setOptionThreadPerHost/", 
                                     params=params, timeout=10)
                self.logger.info(f"Set ZAP thread count to {thread_count}")
            
            # Configure user agent for stealth mode
            if config.get('stealth_mode', False) and 'custom_user_agent' in config:
                user_agent = config['custom_user_agent']
                params = {'String': user_agent}
                self._make_zap_request(f"{self.zap_api_url}/JSON/core/action/setOptionDefaultUserAgent/", 
                                     params=params, timeout=10)
                self.logger.info(f"Set ZAP user agent to: {user_agent}")
            elif config.get('stealth_mode', False):
                # Use a common browser user agent for stealth
                stealth_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
                params = {'String': stealth_ua}
                self._make_zap_request(f"{self.zap_api_url}/JSON/core/action/setOptionDefaultUserAgent/", 
                                     params=params, timeout=10)
                self.logger.info("Set ZAP to stealth mode with common browser user agent")
            
            # Configure timeout
            if 'timeout' in config:
                timeout_sec = config['timeout']
                params = {'Integer': str(timeout_sec)}
                self._make_zap_request(f"{self.zap_api_url}/JSON/core/action/setOptionTimeoutInSecs/", 
                                     params=params, timeout=10)
                self.logger.info(f"Set ZAP timeout to {timeout_sec} seconds")
            
        except Exception as e:
            self.logger.warning(f"Failed to configure some ZAP settings: {e}")
    
    def request_cancellation(self):
        """Request cancellation of all active scans."""
        with self._scan_lock:
            self._cancellation_requested = True
            self.logger.info("Scan cancellation requested")
    
    def is_cancellation_requested(self) -> bool:
        """Check if scan cancellation has been requested."""
        return self._cancellation_requested
    
    def cancel_all_scans(self) -> bool:
        """Cancel all active ZAP scans."""
        try:
            with self._scan_lock:
                if not self._active_scans:
                    self.logger.info("No active scans to cancel")
                    return True
                
                cancelled_count = 0
                
                # Cancel spider scans
                for scan_id, scan_type in list(self._active_scans.items()):
                    if scan_type == 'spider':
                        if self._cancel_spider_scan(scan_id):
                            cancelled_count += 1
                    elif scan_type == 'ascan':
                        if self._cancel_active_scan(scan_id):
                            cancelled_count += 1
                
                self.logger.info(f"Cancelled {cancelled_count} active scans")
                return cancelled_count > 0
                
        except Exception as e:
            self.logger.error(f"Failed to cancel scans: {e}")
            return False
    
    def _cancel_spider_scan(self, scan_id: str) -> bool:
        """Cancel a specific spider scan."""
        try:
            params = {'scanId': scan_id}
            response = self._make_zap_request(f"{self.zap_api_url}/JSON/spider/action/stop/", 
                                            params=params, timeout=10)
            
            if response.status_code == 200:
                self.logger.info(f"Cancelled spider scan: {scan_id}")
                self._active_scans.pop(scan_id, None)
                return True
            else:
                self.logger.warning(f"Failed to cancel spider scan {scan_id}: {response.text}")
                return False
                
        except Exception as e:
            self.logger.error(f"Error cancelling spider scan {scan_id}: {e}")
            return False
    
    def _cancel_active_scan(self, scan_id: str) -> bool:
        """Cancel a specific active scan."""
        try:
            params = {'scanId': scan_id}
            response = self._make_zap_request(f"{self.zap_api_url}/JSON/ascan/action/stop/", 
                                            params=params, timeout=10)
            
            if response.status_code == 200:
                self.logger.info(f"Cancelled active scan: {scan_id}")
                self._active_scans.pop(scan_id, None)
                return True
            else:
                self.logger.warning(f"Failed to cancel active scan {scan_id}: {response.text}")
                return False
                
        except Exception as e:
            self.logger.error(f"Error cancelling active scan {scan_id}: {e}")
            return False
    
    def _load_container_config(self):
        """Load container-specific configuration."""
        try:
            # Try to import container config
            import sys
            from pathlib import Path
            container_config_path = Path(__file__).parent.parent / 'container-config.py'
            if container_config_path.exists():
                sys.path.insert(0, str(container_config_path.parent))
                from container_config import container_config  # type: ignore
                self.container_config = container_config
                self.logger.debug("Container configuration loaded")
            else:
                self.container_config = None
        except ImportError:
            self.container_config = None
            self.logger.debug("Container configuration not available")
    
    def _get_default_zap_path(self) -> Optional[str]:
        """Get default ZAP path based on environment."""
        if self.container_config and self.container_config.is_container:
            zap_config = self.container_config.get_zap_config()
            return zap_config.get('zap_path')
        
        # Default paths for non-container environments
        zap_locations = [
            'zap.sh',  # Linux/Mac
            'zap.bat',  # Windows
            '/usr/share/zaproxy/zap.sh',
            '/opt/zaproxy/zap.sh',
            'C:\\Program Files\\OWASP\\Zed Attack Proxy\\zap.bat'
        ]
        
        for location in zap_locations:
            if Path(location).exists():
                return location
        
        return None
    
    def _should_use_external_zap(self) -> bool:
        """Determine if we should use external ZAP instance."""
        if self.container_config and self.container_config.is_container:
            zap_config = self.container_config.get_zap_config()
            return zap_config.get('use_external_zap', False)
        
        # Check if ZAP_HOST is not localhost
        return self.zap_host != 'localhost'
    
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
                
                # If using external ZAP, just check connectivity
                if self.use_external_zap:
                    self.logger.info(f"Using external ZAP at {self.zap_host}:{self.zap_port}")
                    if self._wait_for_zap_startup():
                        self.is_running = True
                        self.logger.info("External ZAP is accessible")
                        return True
                    else:
                        self.logger.error("External ZAP is not accessible")
                        return False
                
                # Build ZAP command for local instance
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
                response = self._make_zap_request(f"{self.zap_api_url}/JSON/core/view/version/", 
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
            response = self._make_zap_request(f"{self.zap_api_url}/JSON/core/view/version/", 
                                            timeout=5)
            return response.status_code == 200
        except requests.exceptions.RequestException:
            return False
    
    def stop_zap(self) -> bool:
        """Stop ZAP daemon."""
        try:
            with LoggedTimer(self.logger, "ZAP shutdown"):
                # If using external ZAP, just mark as not running
                if self.use_external_zap:
                    self.logger.info("External ZAP - no local process to stop")
                    self.is_running = False
                    return True
                
                # Stop local ZAP process
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
                
                response = self._make_zap_request(f"{self.zap_api_url}/JSON/spider/action/scan/", 
                                                params=params, timeout=30)
                
                if response.status_code != 200:
                    raise ZAPManagerError(f"Failed to start spider: {response.text}")
                
                scan_id = response.json().get('scan')
                
                # Track active scan
                with self._scan_lock:
                    self._active_scans[scan_id] = 'spider'
                
                self.logger.info(f"Spider started with ID: {scan_id}")
                
                # Wait for spider to complete
                if self._wait_for_spider_completion(scan_id):
                    with self._scan_lock:
                        self._active_scans.pop(scan_id, None)
                    self.logger.info("Spider completed successfully")
                    return True, scan_id
                else:
                    with self._scan_lock:
                        self._active_scans.pop(scan_id, None)
                    self.logger.error("Spider failed to complete or was cancelled")
                    return False, scan_id
                    
        except Exception as e:
            self.logger.error(f"Spider operation failed: {e}")
            return False, ""
    
    def _configure_spider(self, max_depth: int, max_children: int):
        """Configure spider parameters."""
        try:
            # Set max depth
            params = {'Integer': str(max_depth)}
            self._make_zap_request(f"{self.zap_api_url}/JSON/spider/action/setOptionMaxDepth/", 
                                 params=params, timeout=10)
            
            # Set max children
            params = {'Integer': str(max_children)}
            self._make_zap_request(f"{self.zap_api_url}/JSON/spider/action/setOptionMaxChildren/", 
                                 params=params, timeout=10)
            
            self.logger.debug(f"Spider configured: max_depth={max_depth}, max_children={max_children}")
            
        except Exception as e:
            self.logger.warning(f"Failed to configure spider: {e}")
    
    def _wait_for_spider_completion(self, scan_id: str, timeout: int = 300) -> bool:
        """Wait for spider scan to complete."""
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            # Check for cancellation
            if self.is_cancellation_requested():
                self.logger.info("Spider scan cancellation requested")
                self._cancel_spider_scan(scan_id)
                return False
            
            try:
                params = {'scanId': scan_id}
                response = self._make_zap_request(f"{self.zap_api_url}/JSON/spider/view/status/", 
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
                # Determine scan policy based on scan mode
                scan_policy = self._get_scan_policy(policy)
                
                # Configure ZAP settings based on scan mode
                self._configure_scan_settings()
                
                # Start active scan
                params = {
                    'url': target_url,
                    'recurse': 'true',
                    'inScopeOnly': 'false',
                    'scanPolicyName': scan_policy,
                    'method': 'GET',
                    'postData': ''
                }
                
                response = self._make_zap_request(f"{self.zap_api_url}/JSON/ascan/action/scan/", 
                                                params=params, timeout=30)
                
                if response.status_code != 200:
                    raise ZAPManagerError(f"Failed to start active scan: {response.text}")
                
                scan_id = response.json().get('scan')
                
                # Track active scan
                with self._scan_lock:
                    self._active_scans[scan_id] = 'ascan'
                
                self.logger.info(f"Active scan started with ID: {scan_id}")
                
                # Wait for scan to complete
                if self._wait_for_active_scan_completion(scan_id):
                    with self._scan_lock:
                        self._active_scans.pop(scan_id, None)
                    self.logger.info("Active scan completed successfully")
                    return True, scan_id
                else:
                    with self._scan_lock:
                        self._active_scans.pop(scan_id, None)
                    self.logger.error("Active scan failed to complete or was cancelled")
                    return False, scan_id
                    
        except Exception as e:
            self.logger.error(f"Active scan operation failed: {e}")
            return False, ""
    
    def _wait_for_active_scan_completion(self, scan_id: str, timeout: int = 1800) -> bool:
        """Wait for active scan to complete."""
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            # Check for cancellation
            if self.is_cancellation_requested():
                self.logger.info("Active scan cancellation requested")
                self._cancel_active_scan(scan_id)
                return False
            
            try:
                params = {'scanId': scan_id}
                response = self._make_zap_request(f"{self.zap_api_url}/JSON/ascan/view/status/", 
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
                
                response = self._make_zap_request(f"{self.zap_api_url}/JSON/core/view/alerts/", 
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
            response = self._make_zap_request(endpoint, params=params, timeout=10)
            
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
            response = self._make_zap_request(f"{self.zap_api_url}/JSON/context/action/newContext/", 
                                            params=params, timeout=10)
            
            if response.status_code != 200:
                raise ZAPManagerError(f"Failed to create context: {response.text}")
            
            # Add URL to context
            params = {
                'contextName': context_name,
                'regex': f"^{target_url}.*"
            }
            response = self._make_zap_request(f"{self.zap_api_url}/JSON/context/action/includeInContext/", 
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
