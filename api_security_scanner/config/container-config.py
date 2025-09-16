"""
Container configuration utilities for API Security Scanner.
Handles environment detection and container-specific configurations.
"""

import os
import socket
from typing import Dict, Any, Optional
from pathlib import Path


class ContainerConfig:
    """Configuration manager for containerized environments."""
    
    def __init__(self):
        self.is_container = self._detect_container()
        self.config = self._load_config()
    
    def _detect_container(self) -> bool:
        """Detect if running inside a container."""
        # Check for common container indicators
        container_indicators = [
            '/.dockerenv',  # Docker
            '/run/.containerenv',  # Podman
            '/proc/1/cgroup',  # Check cgroup for container info
        ]
        
        for indicator in container_indicators:
            if Path(indicator).exists():
                return True
        
        # Check environment variables
        container_env_vars = [
            'CONTAINER',
            'DOCKER_CONTAINER',
            'PODMAN_CONTAINER',
            'KUBERNETES_SERVICE_HOST',
        ]
        
        for env_var in container_env_vars:
            if os.getenv(env_var):
                return True
        
        return False
    
    def _load_config(self) -> Dict[str, Any]:
        """Load container-specific configuration."""
        config = {
            'is_container': self.is_container,
            'zap_host': self._get_zap_host(),
            'zap_port': int(os.getenv('ZAP_PORT', '8080')),
            'scan_db_path': os.getenv('SCAN_DB_PATH', '/app/data/scan_results.db'),
            'log_dir': os.getenv('LOG_DIR', '/app/logs'),
            'reports_dir': os.getenv('REPORTS_DIR', '/app/reports'),
            'workspace_dir': os.getenv('WORKSPACE_DIR', '/workspace'),
        }
        
        # Container-specific adjustments
        if self.is_container:
            config.update({
                'zap_path': self._get_zap_path(),
                'use_external_zap': self._should_use_external_zap(),
                'network_mode': self._get_network_mode(),
            })
        
        return config
    
    def _get_zap_host(self) -> str:
        """Get ZAP host based on environment."""
        zap_host = os.getenv('ZAP_HOST', 'localhost')
        
        if self.is_container:
            # In container, try to detect if ZAP is in another container
            if zap_host == 'localhost':
                # Check if we're in docker-compose network
                try:
                    socket.gethostbyname('zap')
                    return 'zap'
                except socket.gaierror:
                    pass
                
                # Check if we're in podman network
                try:
                    socket.gethostbyname('zap-proxy')
                    return 'zap-proxy'
                except socket.gaierror:
                    pass
                
                # Fallback to host.docker.internal for Docker Desktop
                try:
                    socket.gethostbyname('host.docker.internal')
                    return 'host.docker.internal'
                except socket.gaierror:
                    pass
        
        return zap_host
    
    def _get_zap_path(self) -> Optional[str]:
        """Get ZAP executable path for container environment."""
        if not self.is_container:
            return None
        
        # In container, ZAP might be installed or available via network
        zap_paths = [
            '/usr/local/bin/zap.sh',
            '/opt/zaproxy/zap.sh',
            '/zap/zap.sh',
            'zap.sh',
        ]
        
        for path in zap_paths:
            if Path(path).exists():
                return path
        
        return None
    
    def _should_use_external_zap(self) -> bool:
        """Determine if we should use external ZAP instance."""
        if not self.is_container:
            return False
        
        # If ZAP_HOST is not localhost, we're using external ZAP
        zap_host = self.config.get('zap_host', 'localhost')
        return zap_host != 'localhost'
    
    def _get_network_mode(self) -> str:
        """Detect network mode."""
        if os.getenv('DOCKER_NETWORK_MODE'):
            return os.getenv('DOCKER_NETWORK_MODE')
        
        # Check if we can reach external ZAP
        zap_host = self.config.get('zap_host', 'localhost')
        if zap_host in ['zap', 'zap-proxy']:
            return 'docker-compose'
        elif zap_host == 'host.docker.internal':
            return 'docker-desktop'
        else:
            return 'host'
    
    def get_zap_config(self) -> Dict[str, Any]:
        """Get ZAP configuration for current environment."""
        return {
            'zap_path': self.config.get('zap_path'),
            'zap_host': self.config['zap_host'],
            'zap_port': self.config['zap_port'],
            'use_external_zap': self.config.get('use_external_zap', False),
            'network_mode': self.config.get('network_mode', 'host'),
        }
    
    def get_paths_config(self) -> Dict[str, str]:
        """Get paths configuration for current environment."""
        return {
            'scan_db_path': self.config['scan_db_path'],
            'log_dir': self.config['log_dir'],
            'reports_dir': self.config['reports_dir'],
            'workspace_dir': self.config['workspace_dir'],
        }
    
    def ensure_directories(self):
        """Ensure required directories exist."""
        paths = self.get_paths_config()
        
        for path_name, path_value in paths.items():
            if path_name != 'workspace_dir':  # Don't create workspace dir
                Path(path_value).mkdir(parents=True, exist_ok=True)
    
    def get_container_info(self) -> Dict[str, Any]:
        """Get information about the container environment."""
        return {
            'is_container': self.is_container,
            'config': self.config,
            'environment_vars': {
                'ZAP_HOST': os.getenv('ZAP_HOST'),
                'ZAP_PORT': os.getenv('ZAP_PORT'),
                'SCAN_DB_PATH': os.getenv('SCAN_DB_PATH'),
                'LOG_DIR': os.getenv('LOG_DIR'),
                'REPORTS_DIR': os.getenv('REPORTS_DIR'),
                'WORKSPACE_DIR': os.getenv('WORKSPACE_DIR'),
            }
        }


# Global container config instance
container_config = ContainerConfig()
