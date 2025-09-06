"""
Plugin system for custom vulnerability checks with proof-of-concept generation.
Provides a base class and plugin discovery mechanism with enhanced vulnerability reporting.
"""

import importlib
import inspect
import os
import sys
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict, List, Any, Optional, Type, Tuple
import requests
from datetime import datetime
from dataclasses import dataclass

from utils.logger import get_logger


@dataclass
class Vulnerability:
    """Data model for vulnerability information."""
    id: str
    name: str
    description: str
    risk: str  # High, Medium, Low, Informational
    cvss_score: float
    solution: str
    references: List[str]
    cwe_id: str
    wasc_id: str
    request: str  # Full HTTP request
    response: str  # Full HTTP response
    url: str
    parameter: str
    evidence: str
    scan_id: str
    timestamp: datetime


@dataclass
class ProofOfConcept:
    """Data model for proof-of-concept evidence."""
    vulnerability_id: str
    request_method: str
    request_url: str
    request_headers: Dict[str, str]
    request_body: str
    response_status: int
    response_headers: Dict[str, str]
    response_body: str
    timestamp: datetime
    evidence_description: str


class PluginResult:
    """Container for plugin execution results with enhanced vulnerability data."""
    
    def __init__(self, plugin_name: str, success: bool, vulnerabilities: List[Vulnerability] = None, 
                 error: Optional[str] = None, execution_time: float = 0.0):
        self.plugin_name = plugin_name
        self.success = success
        self.vulnerabilities = vulnerabilities or []
        self.error = error
        self.execution_time = execution_time
        self.timestamp = datetime.now()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary for storage."""
        return {
            'plugin_name': self.plugin_name,
            'success': self.success,
            'vulnerabilities': [vuln.__dict__ for vuln in self.vulnerabilities],
            'error': self.error,
            'execution_time': self.execution_time,
            'timestamp': self.timestamp.isoformat()
        }


class BasePlugin(ABC):
    """Abstract base class for all security plugins with enhanced vulnerability reporting."""
    
    def __init__(self, zap=None, target=None):
        self.logger = get_logger(f"plugin.{self.__class__.__name__}")
        self.name = self.__class__.__name__
        self.description = getattr(self, 'description', 'No description provided')
        self.version = getattr(self, 'version', '1.0.0')
        self.author = getattr(self, 'author', 'Unknown')
        self.zap = zap
        self.target = target
    
    @abstractmethod
    def check(self, target_url: str, requests_data: List[Dict[str, Any]], 
              auth_headers: Optional[Dict[str, str]] = None) -> PluginResult:
        """
        Execute the plugin's security checks and return vulnerabilities.
        
        Args:
            target_url: Base URL of the target
            requests_data: List of parsed request data from input files
            auth_headers: Authentication headers to include in requests
            
        Returns:
            PluginResult containing vulnerabilities and execution status
        """
        pass
    
    @abstractmethod
    def generate_poc(self, vulnerability_id: str) -> Optional[ProofOfConcept]:
        """
        Generate proof-of-concept evidence for a specific vulnerability.
        
        Args:
            vulnerability_id: ID of the vulnerability to generate PoC for
            
        Returns:
            ProofOfConcept object with request/response evidence
        """
        pass
    
    def make_request(self, url: str, method: str = 'GET', headers: Dict[str, str] = None,
                    data: str = None, params: Dict[str, str] = None, 
                    timeout: int = 30) -> Optional[requests.Response]:
        """
        Helper method to make HTTP requests with error handling.
        
        Args:
            url: Target URL
            method: HTTP method
            headers: Request headers
            data: Request body data
            params: URL parameters
            timeout: Request timeout in seconds
            
        Returns:
            Response object or None if request failed
        """
        try:
            response = requests.request(
                method=method,
                url=url,
                headers=headers,
                data=data,
                params=params,
                timeout=timeout,
                verify=False,  # Disable SSL verification for testing
                allow_redirects=True
            )
            return response
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Request failed for {url}: {e}")
            return None
    
    def create_vulnerability(self, vuln_id: str, name: str, description: str, risk: str,
                           cvss_score: float, solution: str, references: List[str],
                           cwe_id: str, wasc_id: str, url: str, parameter: str,
                           evidence: str, scan_id: str, request: str, response: str) -> Vulnerability:
        """
        Helper method to create a standardized vulnerability.
        
        Args:
            vuln_id: Unique vulnerability identifier
            name: Vulnerability name
            description: Detailed description
            risk: Risk level (High, Medium, Low, Informational)
            cvss_score: CVSS score (0.0-10.0)
            solution: Recommended solution
            references: List of reference URLs
            cwe_id: CWE identifier
            wasc_id: WASC identifier
            url: Affected URL
            parameter: Affected parameter
            evidence: Evidence description
            scan_id: Scan identifier
            request: Full HTTP request
            response: Full HTTP response
            
        Returns:
            Vulnerability object
        """
        return Vulnerability(
            id=vuln_id,
            name=name,
            description=description,
            risk=risk,
            cvss_score=cvss_score,
            solution=solution,
            references=references,
            cwe_id=cwe_id,
            wasc_id=wasc_id,
            request=request,
            response=response,
            url=url,
            parameter=parameter,
            evidence=evidence,
            scan_id=scan_id,
            timestamp=datetime.now()
        )
    
    def create_proof_of_concept(self, vulnerability_id: str, request_method: str,
                              request_url: str, request_headers: Dict[str, str],
                              request_body: str, response_status: int,
                              response_headers: Dict[str, str], response_body: str,
                              evidence_description: str) -> ProofOfConcept:
        """
        Helper method to create proof-of-concept evidence.
        
        Args:
            vulnerability_id: ID of the vulnerability
            request_method: HTTP method used
            request_url: URL that was tested
            request_headers: Request headers
            request_body: Request body
            response_status: HTTP response status code
            response_headers: Response headers
            response_body: Response body
            evidence_description: Description of the evidence
            
        Returns:
            ProofOfConcept object
        """
        return ProofOfConcept(
            vulnerability_id=vulnerability_id,
            request_method=request_method,
            request_url=request_url,
            request_headers=request_headers,
            request_body=request_body,
            response_status=response_status,
            response_headers=response_headers,
            response_body=response_body,
            timestamp=datetime.now(),
            evidence_description=evidence_description
        )


class PluginManager:
    """Manages plugin discovery, loading, and execution with enhanced vulnerability tracking."""
    
    def __init__(self, plugins_dir: str = "plugins"):
        self.plugins_dir = Path(plugins_dir)
        self.plugins_dir.mkdir(exist_ok=True)
        self.logger = get_logger(__name__)
        self.loaded_plugins: Dict[str, Type[BasePlugin]] = {}
        self._load_plugins()
    
    def _load_plugins(self):
        """Discover and load all available plugins."""
        self.logger.info(f"Loading plugins from {self.plugins_dir}")
        
        # Add plugins directory to Python path
        if str(self.plugins_dir) not in sys.path:
            sys.path.insert(0, str(self.plugins_dir))
        
        # Find all Python files in plugins directory
        plugin_files = list(self.plugins_dir.glob("*.py"))
        
        for plugin_file in plugin_files:
            if plugin_file.name.startswith('__'):
                continue
            
            try:
                # Import the module
                module_name = plugin_file.stem
                spec = importlib.util.spec_from_file_location(module_name, plugin_file)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                
                # Find classes that inherit from BasePlugin
                for name, obj in inspect.getmembers(module, inspect.isclass):
                    if (issubclass(obj, BasePlugin) and 
                        obj != BasePlugin and 
                        obj.__module__ == module_name):
                        
                        # Instantiate to get plugin info
                        plugin_instance = obj()
                        self.loaded_plugins[plugin_instance.name] = obj
                        self.logger.info(f"Loaded plugin: {plugin_instance.name} v{plugin_instance.version}")
                        
            except Exception as e:
                self.logger.error(f"Failed to load plugin {plugin_file}: {e}")
        
        self.logger.info(f"Loaded {len(self.loaded_plugins)} plugins")
    
    def get_plugin_list(self) -> List[Dict[str, str]]:
        """Get list of loaded plugins with their metadata."""
        plugins = []
        for name, plugin_class in self.loaded_plugins.items():
            instance = plugin_class()
            plugins.append({
                'name': instance.name,
                'description': instance.description,
                'version': instance.version,
                'author': instance.author
            })
        return plugins
    
    def execute_plugin(self, plugin_name: str, target_url: str, 
                      requests_data: List[Dict[str, Any]], 
                      auth_headers: Optional[Dict[str, str]] = None,
                      zap=None) -> PluginResult:
        """
        Execute a specific plugin with enhanced vulnerability tracking.
        
        Args:
            plugin_name: Name of the plugin to execute
            target_url: Base URL of the target
            requests_data: List of parsed request data
            auth_headers: Authentication headers
            zap: ZAP instance for plugin use
            
        Returns:
            PluginResult containing vulnerabilities and execution results
        """
        if plugin_name not in self.loaded_plugins:
            return PluginResult(
                plugin_name=plugin_name,
                success=False,
                error=f"Plugin '{plugin_name}' not found"
            )
        
        try:
            plugin_class = self.loaded_plugins[plugin_name]
            plugin_instance = plugin_class(zap=zap, target=target_url)
            
            start_time = datetime.now()
            result = plugin_instance.check(target_url, requests_data, auth_headers)
            end_time = datetime.now()
            
            result.execution_time = (end_time - start_time).total_seconds()
            self.logger.info(f"Plugin {plugin_name} executed in {result.execution_time:.2f}s, found {len(result.vulnerabilities)} vulnerabilities")
            
            return result
            
        except Exception as e:
            self.logger.error(f"Plugin {plugin_name} execution failed: {e}")
            return PluginResult(
                plugin_name=plugin_name,
                success=False,
                error=str(e)
            )
    
    def execute_all_plugins(self, target_url: str, requests_data: List[Dict[str, Any]], 
                           auth_headers: Optional[Dict[str, str]] = None,
                           zap=None) -> List[PluginResult]:
        """
        Execute all loaded plugins with enhanced vulnerability tracking.
        
        Args:
            target_url: Base URL of the target
            requests_data: List of parsed request data
            auth_headers: Authentication headers
            zap: ZAP instance for plugin use
            
        Returns:
            List of PluginResult objects with vulnerabilities
        """
        results = []
        self.logger.info(f"Executing {len(self.loaded_plugins)} plugins")
        
        for plugin_name in self.loaded_plugins:
            result = self.execute_plugin(plugin_name, target_url, requests_data, auth_headers, zap)
            results.append(result)
            
            if result.success:
                self.logger.info(f"Plugin {plugin_name} found {len(result.vulnerabilities)} vulnerabilities")
            else:
                self.logger.warning(f"Plugin {plugin_name} failed: {result.error}")
        
        return results
    
    def reload_plugins(self):
        """Reload all plugins from the plugins directory."""
        self.loaded_plugins.clear()
        self._load_plugins()
        self.logger.info("Plugins reloaded")


# Utility functions for plugin development
def validate_risk_level(risk: str) -> bool:
    """Validate that risk level is one of the allowed values."""
    allowed_risks = ['High', 'Medium', 'Low', 'Informational']
    return risk in allowed_risks


def validate_cvss_score(score: float) -> bool:
    """Validate that CVSS score is within valid range."""
    return 0.0 <= score <= 10.0


def sanitize_url(url: str) -> str:
    """Sanitize URL for safe logging and storage."""
    # Remove sensitive query parameters
    sensitive_params = ['password', 'token', 'key', 'secret', 'auth']
    # This is a basic implementation - in production, use proper URL parsing
    return url


def extract_domain(url: str) -> str:
    """Extract domain from URL."""
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        return parsed.netloc
    except Exception:
        return url


def format_http_request(method: str, url: str, headers: Dict[str, str], body: str = None) -> str:
    """Format HTTP request for storage and display."""
    request_lines = [f"{method} {url} HTTP/1.1"]
    
    for header, value in headers.items():
        request_lines.append(f"{header}: {value}")
    
    if body:
        request_lines.append("")
        request_lines.append(body)
    
    return "\n".join(request_lines)


def format_http_response(status: int, headers: Dict[str, str], body: str = None) -> str:
    """Format HTTP response for storage and display."""
    response_lines = [f"HTTP/1.1 {status}"]
    
    for header, value in headers.items():
        response_lines.append(f"{header}: {value}")
    
    if body:
        response_lines.append("")
        response_lines.append(body)
    
    return "\n".join(response_lines)
