"""
Unit tests for container configuration.
"""

import pytest
import os
import socket
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path

from api_security_scanner.container_config import ContainerConfig, container_config


class TestContainerConfig:
    """Test container configuration functionality."""
    
    def test_container_config_init(self):
        """Test container configuration initialization."""
        config = ContainerConfig()
        assert config.is_container is not None
        assert config.config is not None
    
    def test_detect_container_docker_env(self):
        """Test container detection with Docker environment file."""
        with patch('pathlib.Path.exists') as mock_exists:
            mock_exists.side_effect = lambda path: str(path) == '/.dockerenv'
            
            config = ContainerConfig()
            assert config.is_container is True
    
    def test_detect_container_podman_env(self):
        """Test container detection with Podman environment file."""
        with patch('pathlib.Path.exists') as mock_exists:
            mock_exists.side_effect = lambda path: str(path) == '/run/.containerenv'
            
            config = ContainerConfig()
            assert config.is_container is True
    
    def test_detect_container_cgroup(self):
        """Test container detection with cgroup file."""
        with patch('pathlib.Path.exists') as mock_exists:
            mock_exists.side_effect = lambda path: str(path) == '/proc/1/cgroup'
            
            config = ContainerConfig()
            assert config.is_container is True
    
    def test_detect_container_env_vars(self):
        """Test container detection with environment variables."""
        with patch.dict(os.environ, {'CONTAINER': 'true'}):
            config = ContainerConfig()
            assert config.is_container is True
    
    def test_detect_container_kubernetes(self):
        """Test container detection with Kubernetes environment."""
        with patch.dict(os.environ, {'KUBERNETES_SERVICE_HOST': '10.96.0.1'}):
            config = ContainerConfig()
            assert config.is_container is True
    
    def test_detect_container_not_container(self):
        """Test container detection when not in container."""
        with patch('pathlib.Path.exists', return_value=False), \
             patch.dict(os.environ, {}, clear=True):
            
            config = ContainerConfig()
            assert config.is_container is False
    
    def test_get_zap_host_localhost(self):
        """Test getting ZAP host for localhost."""
        with patch.dict(os.environ, {}, clear=True):
            config = ContainerConfig()
            config.is_container = False
            
            zap_host = config._get_zap_host()
            assert zap_host == 'localhost'
    
    def test_get_zap_host_env_variable(self):
        """Test getting ZAP host from environment variable."""
        with patch.dict(os.environ, {'ZAP_HOST': 'zap-proxy'}):
            config = ContainerConfig()
            
            zap_host = config._get_zap_host()
            assert zap_host == 'zap-proxy'
    
    def test_get_zap_host_docker_compose(self):
        """Test getting ZAP host for Docker Compose."""
        with patch('socket.gethostbyname') as mock_gethostbyname:
            mock_gethostbyname.side_effect = lambda host: {
                'zap': '172.18.0.2',
                'zap-proxy': socket.gaierror(),
                'host.docker.internal': socket.gaierror()
            }.get(host, socket.gaierror())
            
            config = ContainerConfig()
            config.is_container = True
            
            zap_host = config._get_zap_host()
            assert zap_host == 'zap'
    
    def test_get_zap_host_podman(self):
        """Test getting ZAP host for Podman."""
        with patch('socket.gethostbyname') as mock_gethostbyname:
            mock_gethostbyname.side_effect = lambda host: {
                'zap': socket.gaierror(),
                'zap-proxy': '172.18.0.2',
                'host.docker.internal': socket.gaierror()
            }.get(host, socket.gaierror())
            
            config = ContainerConfig()
            config.is_container = True
            
            zap_host = config._get_zap_host()
            assert zap_host == 'zap-proxy'
    
    def test_get_zap_host_docker_desktop(self):
        """Test getting ZAP host for Docker Desktop."""
        with patch('socket.gethostbyname') as mock_gethostbyname:
            mock_gethostbyname.side_effect = lambda host: {
                'zap': socket.gaierror(),
                'zap-proxy': socket.gaierror(),
                'host.docker.internal': '192.168.65.2'
            }.get(host, socket.gaierror())
            
            config = ContainerConfig()
            config.is_container = True
            
            zap_host = config._get_zap_host()
            assert zap_host == 'host.docker.internal'
    
    def test_get_zap_path_container(self):
        """Test getting ZAP path in container."""
        with patch('pathlib.Path.exists') as mock_exists:
            mock_exists.side_effect = lambda path: str(path) == '/usr/local/bin/zap.sh'
            
            config = ContainerConfig()
            config.is_container = True
            
            zap_path = config._get_zap_path()
            assert zap_path == '/usr/local/bin/zap.sh'
    
    def test_get_zap_path_non_container(self):
        """Test getting ZAP path outside container."""
        with patch('pathlib.Path.exists') as mock_exists:
            mock_exists.side_effect = lambda path: str(path) == 'zap.sh'
            
            config = ContainerConfig()
            config.is_container = False
            
            zap_path = config._get_zap_path()
            assert zap_path == 'zap.sh'
    
    def test_get_zap_path_not_found(self):
        """Test getting ZAP path when not found."""
        with patch('pathlib.Path.exists', return_value=False):
            config = ContainerConfig()
            config.is_container = False
            
            zap_path = config._get_zap_path()
            assert zap_path is None
    
    def test_should_use_external_zap_container(self):
        """Test external ZAP detection in container."""
        config = ContainerConfig()
        config.is_container = True
        config.config = {
            'zap_host': 'zap-proxy'
        }
        
        with patch.object(config, '_get_zap_config') as mock_get_config:
            mock_get_config.return_value = {'use_external_zap': True}
            
            result = config._should_use_external_zap()
            assert result is True
    
    def test_should_use_external_zap_non_container(self):
        """Test external ZAP detection outside container."""
        config = ContainerConfig()
        config.is_container = False
        config.zap_host = 'localhost'
        
        result = config._should_use_external_zap()
        assert result is False
    
    def test_should_use_external_zap_remote_host(self):
        """Test external ZAP detection with remote host."""
        config = ContainerConfig()
        config.is_container = False
        config.zap_host = '192.168.1.100'
        
        result = config._should_use_external_zap()
        assert result is True
    
    def test_get_network_mode_docker_compose(self):
        """Test getting network mode for Docker Compose."""
        config = ContainerConfig()
        config.config = {'zap_host': 'zap'}
        
        network_mode = config._get_network_mode()
        assert network_mode == 'docker-compose'
    
    def test_get_network_mode_docker_desktop(self):
        """Test getting network mode for Docker Desktop."""
        config = ContainerConfig()
        config.config = {'zap_host': 'host.docker.internal'}
        
        network_mode = config._get_network_mode()
        assert network_mode == 'docker-desktop'
    
    def test_get_network_mode_host(self):
        """Test getting network mode for host."""
        config = ContainerConfig()
        config.config = {'zap_host': 'localhost'}
        
        network_mode = config._get_network_mode()
        assert network_mode == 'host'
    
    def test_get_network_mode_env_variable(self):
        """Test getting network mode from environment variable."""
        with patch.dict(os.environ, {'DOCKER_NETWORK_MODE': 'custom'}):
            config = ContainerConfig()
            
            network_mode = config._get_network_mode()
            assert network_mode == 'custom'
    
    def test_get_zap_config(self):
        """Test getting ZAP configuration."""
        config = ContainerConfig()
        config.is_container = True
        config.config = {
            'zap_path': '/usr/local/bin/zap.sh',
            'zap_host': 'zap',
            'zap_port': 8080,
            'use_external_zap': True,
            'network_mode': 'docker-compose'
        }
        
        zap_config = config.get_zap_config()
        
        assert zap_config['zap_path'] == '/usr/local/bin/zap.sh'
        assert zap_config['zap_host'] == 'zap'
        assert zap_config['zap_port'] == 8080
        assert zap_config['use_external_zap'] is True
        assert zap_config['network_mode'] == 'docker-compose'
    
    def test_get_paths_config(self):
        """Test getting paths configuration."""
        config = ContainerConfig()
        config.config = {
            'scan_db_path': '/app/data/scan_results.db',
            'log_dir': '/app/logs',
            'reports_dir': '/app/reports',
            'workspace_dir': '/workspace'
        }
        
        paths_config = config.get_paths_config()
        
        assert paths_config['scan_db_path'] == '/app/data/scan_results.db'
        assert paths_config['log_dir'] == '/app/logs'
        assert paths_config['reports_dir'] == '/app/reports'
        assert paths_config['workspace_dir'] == '/workspace'
    
    def test_ensure_directories(self, temp_dir):
        """Test ensuring directories exist."""
        config = ContainerConfig()
        config.config = {
            'scan_db_path': os.path.join(temp_dir, 'data', 'scan.db'),
            'log_dir': os.path.join(temp_dir, 'logs'),
            'reports_dir': os.path.join(temp_dir, 'reports'),
            'workspace_dir': os.path.join(temp_dir, 'workspace')
        }
        
        config.ensure_directories()
        
        assert os.path.exists(os.path.join(temp_dir, 'data'))
        assert os.path.exists(os.path.join(temp_dir, 'logs'))
        assert os.path.exists(os.path.join(temp_dir, 'reports'))
        # workspace_dir should not be created (read-only mount)
    
    def test_get_container_info(self):
        """Test getting container information."""
        with patch.dict(os.environ, {
            'ZAP_HOST': 'zap',
            'ZAP_PORT': '8080',
            'SCAN_DB_PATH': '/app/data/scan.db',
            'LOG_DIR': '/app/logs',
            'REPORTS_DIR': '/app/reports',
            'WORKSPACE_DIR': '/workspace'
        }):
            config = ContainerConfig()
            
            info = config.get_container_info()
            
            assert 'is_container' in info
            assert 'config' in info
            assert 'environment_vars' in info
            assert info['environment_vars']['ZAP_HOST'] == 'zap'
            assert info['environment_vars']['ZAP_PORT'] == '8080'
    
    def test_load_config_with_env_vars(self):
        """Test loading configuration with environment variables."""
        with patch.dict(os.environ, {
            'ZAP_HOST': 'custom-zap',
            'ZAP_PORT': '8081',
            'SCAN_DB_PATH': '/custom/data/scan.db',
            'LOG_DIR': '/custom/logs',
            'REPORTS_DIR': '/custom/reports',
            'WORKSPACE_DIR': '/custom/workspace'
        }):
            config = ContainerConfig()
            
            assert config.config['zap_host'] == 'custom-zap'
            assert config.config['zap_port'] == 8081
            assert config.config['scan_db_path'] == '/custom/data/scan.db'
            assert config.config['log_dir'] == '/custom/logs'
            assert config.config['reports_dir'] == '/custom/reports'
            assert config.config['workspace_dir'] == '/custom/workspace'
    
    def test_load_config_defaults(self):
        """Test loading configuration with default values."""
        with patch.dict(os.environ, {}, clear=True):
            config = ContainerConfig()
            
            assert config.config['zap_port'] == 8080
            assert config.config['scan_db_path'] == '/app/data/scan_results.db'
            assert config.config['log_dir'] == '/app/logs'
            assert config.config['reports_dir'] == '/app/reports'
            assert config.config['workspace_dir'] == '/workspace'


class TestGlobalContainerConfig:
    """Test global container configuration instance."""
    
    def test_global_container_config_exists(self):
        """Test that global container config instance exists."""
        assert container_config is not None
        assert isinstance(container_config, ContainerConfig)
    
    def test_global_container_config_methods(self):
        """Test that global container config has required methods."""
        assert hasattr(container_config, 'get_zap_config')
        assert hasattr(container_config, 'get_paths_config')
        assert hasattr(container_config, 'ensure_directories')
        assert hasattr(container_config, 'get_container_info')
        assert callable(container_config.get_zap_config)
        assert callable(container_config.get_paths_config)
        assert callable(container_config.ensure_directories)
        assert callable(container_config.get_container_info)
    
    def test_global_container_config_consistency(self):
        """Test that global container config is consistent."""
        zap_config = container_config.get_zap_config()
        paths_config = container_config.get_paths_config()
        
        assert isinstance(zap_config, dict)
        assert isinstance(paths_config, dict)
        
        # Required keys should be present
        required_zap_keys = ['zap_host', 'zap_port']
        required_paths_keys = ['scan_db_path', 'log_dir', 'reports_dir', 'workspace_dir']
        
        for key in required_zap_keys:
            assert key in zap_config
        
        for key in required_paths_keys:
            assert key in paths_config
