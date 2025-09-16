"""
Scan Mode Manager for API Security Scanner.
Handles different scanning modes and their configurations.
"""

from typing import Dict, Any, Optional, List
from dataclasses import dataclass
from .config import ScanModeConfig


@dataclass
class ScanModePreset:
    """Predefined scan mode configuration."""
    name: str
    description: str
    config: Dict[str, Any]
    use_case: str
    duration: str
    risk_level: str


class ScanModeManager:
    """Manages different scan modes and their configurations."""
    
    def __init__(self):
        self.presets = self._initialize_presets()
    
    def _initialize_presets(self) -> Dict[str, ScanModePreset]:
        """Initialize predefined scan mode presets."""
        return {
            'safe': ScanModePreset(
                name='Safe Mode',
                description='Conservative scanning with minimal impact on target systems',
                config={
                    'zap_enabled': True,
                    'spider_depth': 3,
                    'spider_children': 5,
                    'max_scan_time': 1800,  # 30 minutes
                    'request_delay': 0.5,  # 500ms between requests
                    'concurrent_requests': 1,
                    'aggressive_scanning': False,
                    'stealth_mode': True,
                    'follow_redirects': True,
                    'max_redirects': 3,
                    'verify_ssl': True,
                    'timeout': 30,
                    'retry_attempts': 2,
                    'fuzzing_enabled': False,
                    'injection_tests': False,
                    'authentication_tests': True,
                    'rate_limiting_tests': True,
                    'headers_analysis': True,
                    'cors_analysis': True,
                    'jwt_analysis': True,
                    'graphql_analysis': True,
                    'grpc_analysis': True,
                    'ai_detection_enabled': True
                },
                use_case='Production environments, sensitive systems',
                duration='15-30 minutes',
                risk_level='Low'
            ),
            
            'attack': ScanModePreset(
                name='Attack Mode',
                description='Aggressive scanning with comprehensive vulnerability testing',
                config={
                    'zap_enabled': True,
                    'spider_depth': 10,
                    'spider_children': 20,
                    'max_scan_time': 7200,  # 2 hours
                    'request_delay': 0.1,  # 100ms between requests
                    'concurrent_requests': 5,
                    'aggressive_scanning': True,
                    'stealth_mode': False,
                    'follow_redirects': True,
                    'max_redirects': 10,
                    'verify_ssl': False,  # Test SSL bypass
                    'timeout': 60,
                    'retry_attempts': 5,
                    'fuzzing_enabled': True,
                    'injection_tests': True,
                    'authentication_tests': True,
                    'rate_limiting_tests': True,
                    'headers_analysis': True,
                    'cors_analysis': True,
                    'jwt_analysis': True,
                    'graphql_analysis': True,
                    'grpc_analysis': True,
                    'ai_detection_enabled': True
                },
                use_case='Penetration testing, security assessments',
                duration='1-2 hours',
                risk_level='High'
            ),
            
            'spidering': ScanModePreset(
                name='Spidering Mode',
                description='Focus on discovery and mapping of endpoints',
                config={
                    'zap_enabled': True,
                    'spider_depth': 15,
                    'spider_children': 50,
                    'max_scan_time': 3600,  # 1 hour
                    'request_delay': 0.2,  # 200ms between requests
                    'concurrent_requests': 3,
                    'aggressive_scanning': False,
                    'stealth_mode': True,
                    'follow_redirects': True,
                    'max_redirects': 5,
                    'verify_ssl': True,
                    'timeout': 30,
                    'retry_attempts': 3,
                    'fuzzing_enabled': False,
                    'injection_tests': False,
                    'authentication_tests': False,
                    'rate_limiting_tests': False,
                    'headers_analysis': False,
                    'cors_analysis': False,
                    'jwt_analysis': False,
                    'graphql_analysis': False,
                    'grpc_analysis': False,
                    'ai_detection_enabled': False
                },
                use_case='Endpoint discovery, API mapping',
                duration='30-60 minutes',
                risk_level='Very Low'
            ),
            
            'comprehensive': ScanModePreset(
                name='Comprehensive Mode',
                description='Complete security assessment with all available tools',
                config={
                    'zap_enabled': True,
                    'spider_depth': 8,
                    'spider_children': 15,
                    'max_scan_time': 10800,  # 3 hours
                    'request_delay': 0.2,  # 200ms between requests
                    'concurrent_requests': 3,
                    'aggressive_scanning': True,
                    'stealth_mode': False,
                    'follow_redirects': True,
                    'max_redirects': 8,
                    'verify_ssl': True,
                    'timeout': 45,
                    'retry_attempts': 4,
                    'fuzzing_enabled': True,
                    'injection_tests': True,
                    'authentication_tests': True,
                    'rate_limiting_tests': True,
                    'headers_analysis': True,
                    'cors_analysis': True,
                    'jwt_analysis': True,
                    'graphql_analysis': True,
                    'grpc_analysis': True,
                    'ai_detection_enabled': True
                },
                use_case='Full security audit, compliance testing',
                duration='2-3 hours',
                risk_level='Medium'
            ),
            
            'stealth': ScanModePreset(
                name='Stealth Mode',
                description='Minimal footprint scanning to avoid detection',
                config={
                    'zap_enabled': False,
                    'spider_depth': 2,
                    'spider_children': 3,
                    'max_scan_time': 900,  # 15 minutes
                    'request_delay': 2.0,  # 2 seconds between requests
                    'concurrent_requests': 1,
                    'aggressive_scanning': False,
                    'stealth_mode': True,
                    'custom_user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                    'follow_redirects': True,
                    'max_redirects': 2,
                    'verify_ssl': True,
                    'timeout': 60,
                    'retry_attempts': 1,
                    'fuzzing_enabled': False,
                    'injection_tests': False,
                    'authentication_tests': False,
                    'rate_limiting_tests': False,
                    'headers_analysis': True,
                    'cors_analysis': True,
                    'jwt_analysis': True,
                    'graphql_analysis': False,
                    'grpc_analysis': False,
                    'ai_detection_enabled': False
                },
                use_case='Covert testing, avoiding WAF detection',
                duration='10-15 minutes',
                risk_level='Very Low'
            ),
            
            'aggressive': ScanModePreset(
                name='Aggressive Mode',
                description='Maximum intensity scanning with all attack vectors',
                config={
                    'zap_enabled': True,
                    'spider_depth': 20,
                    'spider_children': 100,
                    'max_scan_time': 14400,  # 4 hours
                    'request_delay': 0.05,  # 50ms between requests
                    'concurrent_requests': 10,
                    'aggressive_scanning': True,
                    'stealth_mode': False,
                    'follow_redirects': True,
                    'max_redirects': 20,
                    'verify_ssl': False,
                    'timeout': 120,
                    'retry_attempts': 10,
                    'fuzzing_enabled': True,
                    'injection_tests': True,
                    'authentication_tests': True,
                    'rate_limiting_tests': True,
                    'headers_analysis': True,
                    'cors_analysis': True,
                    'jwt_analysis': True,
                    'graphql_analysis': True,
                    'grpc_analysis': True,
                    'ai_detection_enabled': True
                },
                use_case='Red team exercises, maximum coverage testing',
                duration='3-4 hours',
                risk_level='Very High'
            ),
            
            'quick': ScanModePreset(
                name='Quick Mode',
                description='Fast scanning for development and CI/CD pipelines',
                config={
                    'zap_enabled': False,
                    'spider_depth': 1,
                    'spider_children': 5,
                    'max_scan_time': 300,  # 5 minutes
                    'request_delay': 0.1,  # 100ms between requests
                    'concurrent_requests': 5,
                    'aggressive_scanning': False,
                    'stealth_mode': False,
                    'follow_redirects': True,
                    'max_redirects': 3,
                    'verify_ssl': True,
                    'timeout': 15,
                    'retry_attempts': 1,
                    'fuzzing_enabled': False,
                    'injection_tests': False,
                    'authentication_tests': True,
                    'rate_limiting_tests': True,
                    'headers_analysis': True,
                    'cors_analysis': True,
                    'jwt_analysis': True,
                    'graphql_analysis': False,
                    'grpc_analysis': False,
                    'ai_detection_enabled': False
                },
                use_case='Development testing, CI/CD integration',
                duration='2-5 minutes',
                risk_level='Very Low'
            ),
            
            'api-focused': ScanModePreset(
                name='API-Focused Mode',
                description='Specialized scanning for REST/GraphQL/gRPC APIs',
                config={
                    'zap_enabled': False,
                    'spider_depth': 5,
                    'spider_children': 10,
                    'max_scan_time': 1800,  # 30 minutes
                    'request_delay': 0.2,  # 200ms between requests
                    'concurrent_requests': 3,
                    'aggressive_scanning': False,
                    'stealth_mode': False,
                    'follow_redirects': True,
                    'max_redirects': 5,
                    'verify_ssl': True,
                    'timeout': 30,
                    'retry_attempts': 3,
                    'fuzzing_enabled': True,
                    'injection_tests': True,
                    'authentication_tests': True,
                    'rate_limiting_tests': True,
                    'headers_analysis': True,
                    'cors_analysis': True,
                    'jwt_analysis': True,
                    'graphql_analysis': True,
                    'grpc_analysis': True,
                    'ai_detection_enabled': True
                },
                use_case='API security testing, microservices assessment',
                duration='20-30 minutes',
                risk_level='Low'
            )
        }
    
    def get_scan_mode_config(self, mode: str) -> Optional[ScanModeConfig]:
        """Get scan mode configuration for a specific mode."""
        if mode not in self.presets:
            return None
        
        preset = self.presets[mode]
        config_dict = preset.config
        
        return ScanModeConfig(
            mode=mode,
            zap_enabled=config_dict.get('zap_enabled', True),
            spider_depth=config_dict.get('spider_depth', 5),
            spider_children=config_dict.get('spider_children', 10),
            max_scan_time=config_dict.get('max_scan_time', 3600),
            request_delay=config_dict.get('request_delay', 0.1),
            concurrent_requests=config_dict.get('concurrent_requests', 2),
            aggressive_scanning=config_dict.get('aggressive_scanning', False),
            stealth_mode=config_dict.get('stealth_mode', False),
            custom_user_agent=config_dict.get('custom_user_agent'),
            follow_redirects=config_dict.get('follow_redirects', True),
            max_redirects=config_dict.get('max_redirects', 5),
            verify_ssl=config_dict.get('verify_ssl', True),
            timeout=config_dict.get('timeout', 30),
            retry_attempts=config_dict.get('retry_attempts', 3),
            fuzzing_enabled=config_dict.get('fuzzing_enabled', False),
            injection_tests=config_dict.get('injection_tests', False),
            authentication_tests=config_dict.get('authentication_tests', True),
            rate_limiting_tests=config_dict.get('rate_limiting_tests', True),
            headers_analysis=config_dict.get('headers_analysis', True),
            cors_analysis=config_dict.get('cors_analysis', True),
            jwt_analysis=config_dict.get('jwt_analysis', True),
            graphql_analysis=config_dict.get('graphql_analysis', True),
            grpc_analysis=config_dict.get('grpc_analysis', True),
            ai_detection_enabled=config_dict.get('ai_detection_enabled', True)
        )
    
    def get_available_modes(self) -> List[str]:
        """Get list of available scan modes."""
        return list(self.presets.keys())
    
    def get_mode_info(self, mode: str) -> Optional[ScanModePreset]:
        """Get information about a specific scan mode."""
        return self.presets.get(mode)
    
    def list_all_modes(self) -> Dict[str, ScanModePreset]:
        """Get all available scan modes with their information."""
        return self.presets.copy()
    
    def validate_mode(self, mode: str) -> bool:
        """Validate if a scan mode exists."""
        return mode in self.presets
    
