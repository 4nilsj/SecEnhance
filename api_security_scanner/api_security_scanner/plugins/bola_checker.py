"""
Broken Object Level Authorization (BOLA) Security Checker Plugin.

This plugin detects Broken Object Level Authorization vulnerabilities,
including Insecure Direct Object References (IDOR) and unauthorized
access to other users' resources.
"""

import uuid
import json
import re
from typing import Dict, List, Any, Optional
from datetime import datetime
from urllib.parse import urlparse, parse_qs

from api_security_scanner.core.scanner_plugins import (
    BasePlugin, PluginResult, Vulnerability, ProofOfConcept,
    format_http_request, format_http_response
)


class BOLAChecker(BasePlugin):
    """Detects Broken Object Level Authorization vulnerabilities."""
    
    name = "BOLAChecker"
    description = "Detects Broken Object Level Authorization (BOLA) and IDOR vulnerabilities"
    version = "1.0.0"
    author = "API Security Scanner"
    
    def check(self, target_url: str, requests_data: List[Dict[str, Any]], 
              auth_headers: Optional[Dict[str, str]] = None) -> PluginResult:
        """Perform BOLA vulnerability detection."""
        vulnerabilities = []
        
        try:
            for request in requests_data:
                url = request.get('url', '')
                method = request.get('method', 'GET')
                headers = request.get('headers', {}).copy()
                
                if auth_headers:
                    headers.update(auth_headers)
                
                # Test for BOLA vulnerabilities
                bola_vulns = self._test_bola_vulnerabilities(url, method, headers, request.get('body', ''))
                vulnerabilities.extend(bola_vulns)
                
                # Test for IDOR vulnerabilities
                idor_vulns = self._test_idor_vulnerabilities(url, method, headers, request.get('body', ''))
                vulnerabilities.extend(idor_vulns)
                
                # Test for horizontal privilege escalation
                horizontal_vulns = self._test_horizontal_privilege_escalation(url, method, headers, request.get('body', ''))
                vulnerabilities.extend(horizontal_vulns)
                
                # Test for vertical privilege escalation
                vertical_vulns = self._test_vertical_privilege_escalation(url, method, headers, request.get('body', ''))
                vulnerabilities.extend(vertical_vulns)
        
        except Exception as e:
            self.logger.error(f"Error in BOLA checker: {e}")
            return PluginResult(
                plugin_name=self.name,
                success=False,
                vulnerabilities=[],
                error=str(e),
                execution_time=0.0
            )
        
        return PluginResult(
            plugin_name=self.name,
            success=True,
            vulnerabilities=vulnerabilities,
            execution_time=0.0
        )
    
    def _test_bola_vulnerabilities(self, url: str, method: str, headers: Dict[str, str], body: str) -> List[Vulnerability]:
        """Test for Broken Object Level Authorization vulnerabilities."""
        vulnerabilities = []
        
        try:
            # Extract object identifiers from URL and body
            object_ids = self._extract_object_identifiers(url, body)
            
            if not object_ids:
                return vulnerabilities
            
            # Test with different object IDs
            for obj_id in object_ids:
                # Test with sequential IDs
                sequential_vulns = self._test_sequential_id_access(url, method, headers, body, obj_id)
                vulnerabilities.extend(sequential_vulns)
                
                # Test with predictable IDs
                predictable_vulns = self._test_predictable_id_access(url, method, headers, body, obj_id)
                vulnerabilities.extend(predictable_vulns)
                
                # Test with other users' IDs
                other_user_vulns = self._test_other_user_access(url, method, headers, body, obj_id)
                vulnerabilities.extend(other_user_vulns)
        
        except Exception as e:
            self.logger.error(f"Error testing BOLA vulnerabilities: {e}")
        
        return vulnerabilities
    
    def _test_idor_vulnerabilities(self, url: str, method: str, headers: Dict[str, str], body: str) -> List[Vulnerability]:
        """Test for Insecure Direct Object Reference vulnerabilities."""
        vulnerabilities = []
        
        try:
            # Extract parameters that might be object references
            params = self._extract_parameters(url, body)
            
            for param_name, param_value in params.items():
                if self._is_object_reference(param_name, param_value):
                    # Test with modified object references
                    modified_vulns = self._test_modified_object_references(url, method, headers, body, param_name, param_value)
                    vulnerabilities.extend(modified_vulns)
        
        except Exception as e:
            self.logger.error(f"Error testing IDOR vulnerabilities: {e}")
        
        return vulnerabilities
    
    def _test_horizontal_privilege_escalation(self, url: str, method: str, headers: Dict[str, str], body: str) -> List[Vulnerability]:
        """Test for horizontal privilege escalation vulnerabilities."""
        vulnerabilities = []
        
        try:
            # Test with different user contexts
            user_contexts = self._generate_user_contexts()
            
            for context in user_contexts:
                # Test access to other users' resources
                escalation_vulns = self._test_user_resource_access(url, method, headers, body, context)
                vulnerabilities.extend(escalation_vulns)
        
        except Exception as e:
            self.logger.error(f"Error testing horizontal privilege escalation: {e}")
        
        return vulnerabilities
    
    def _test_vertical_privilege_escalation(self, url: str, method: str, headers: Dict[str, str], body: str) -> List[Vulnerability]:
        """Test for vertical privilege escalation vulnerabilities."""
        vulnerabilities = []
        
        try:
            # Test with different privilege levels
            privilege_levels = self._generate_privilege_levels()
            
            for level in privilege_levels:
                # Test access to higher privilege resources
                escalation_vulns = self._test_privilege_level_access(url, method, headers, body, level)
                vulnerabilities.extend(escalation_vulns)
        
        except Exception as e:
            self.logger.error(f"Error testing vertical privilege escalation: {e}")
        
        return vulnerabilities
    
    def _extract_object_identifiers(self, url: str, body: str) -> List[str]:
        """Extract potential object identifiers from URL and body."""
        identifiers = []
        
        # Extract from URL path
        path_segments = urlparse(url).path.split('/')
        for segment in path_segments:
            if self._is_object_id(segment):
                identifiers.append(segment)
        
        # Extract from URL query parameters
        query_params = parse_qs(urlparse(url).query)
        for param_name, param_values in query_params.items():
            if self._is_object_id_param(param_name):
                identifiers.extend(param_values)
        
        # Extract from JSON body
        if body:
            try:
                body_data = json.loads(body)
                identifiers.extend(self._extract_ids_from_json(body_data))
            except (json.JSONDecodeError, TypeError):
                pass
        
        return list(set(identifiers))  # Remove duplicates
    
    def _extract_parameters(self, url: str, body: str) -> Dict[str, str]:
        """Extract parameters from URL and body."""
        params = {}
        
        # Extract from URL query parameters
        query_params = parse_qs(urlparse(url).query)
        for param_name, param_values in query_params.items():
            if param_values:
                params[param_name] = param_values[0]
        
        # Extract from JSON body
        if body:
            try:
                body_data = json.loads(body)
                params.update(self._extract_params_from_json(body_data))
            except (json.JSONDecodeError, TypeError):
                pass
        
        return params
    
    def _is_object_id(self, value: str) -> bool:
        """Check if a value looks like an object ID."""
        if not value or not isinstance(value, str):
            return False
        
        # Check for common ID patterns
        patterns = [
            r'^\d+$',  # Numeric IDs
            r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$',  # UUIDs
            r'^[a-zA-Z0-9]{24}$',  # MongoDB ObjectIds
            r'^[a-zA-Z0-9_-]{10,}$',  # Long alphanumeric strings
        ]
        
        return any(re.match(pattern, value) for pattern in patterns)
    
    def _is_object_id_param(self, param_name: str) -> bool:
        """Check if a parameter name suggests it's an object ID."""
        id_keywords = ['id', 'user_id', 'account_id', 'order_id', 'product_id', 'document_id', 'file_id', 'resource_id']
        return any(keyword in param_name.lower() for keyword in id_keywords)
    
    def _is_object_reference(self, param_name: str, param_value: str) -> bool:
        """Check if a parameter is likely an object reference."""
        return self._is_object_id_param(param_name) and self._is_object_id(param_value)
    
    def _extract_ids_from_json(self, data: Any, path: str = "") -> List[str]:
        """Recursively extract IDs from JSON data."""
        ids = []
        
        if isinstance(data, dict):
            for key, value in data.items():
                current_path = f"{path}.{key}" if path else key
                if self._is_object_id_param(key) and isinstance(value, str) and self._is_object_id(value):
                    ids.append(value)
                ids.extend(self._extract_ids_from_json(value, current_path))
        elif isinstance(data, list):
            for i, item in enumerate(data):
                current_path = f"{path}[{i}]"
                ids.extend(self._extract_ids_from_json(item, current_path))
        
        return ids
    
    def _extract_params_from_json(self, data: Any, path: str = "") -> Dict[str, str]:
        """Recursively extract parameters from JSON data."""
        params = {}
        
        if isinstance(data, dict):
            for key, value in data.items():
                current_path = f"{path}.{key}" if path else key
                if isinstance(value, (str, int, float)):
                    params[current_path] = str(value)
                params.update(self._extract_params_from_json(value, current_path))
        elif isinstance(data, list):
            for i, item in enumerate(data):
                current_path = f"{path}[{i}]"
                params.update(self._extract_params_from_json(item, current_path))
        
        return params
    
    def _test_sequential_id_access(self, url: str, method: str, headers: Dict[str, str], body: str, obj_id: str) -> List[Vulnerability]:
        """Test access to sequential object IDs."""
        vulnerabilities = []
        
        try:
            if obj_id.isdigit():
                # Test with sequential IDs
                base_id = int(obj_id)
                test_ids = [str(base_id + 1), str(base_id - 1), str(base_id + 10), str(base_id - 10)]
                
                for test_id in test_ids:
                    if self._test_object_access(url, method, headers, body, obj_id, test_id):
                        vuln_id = f"bola-sequential-{uuid.uuid4().hex[:8]}"
                        vulnerabilities.append(Vulnerability(
                            id=vuln_id,
                            name="BOLA - Sequential ID Access",
                            description=f"API allows access to sequential object IDs. Original ID: {obj_id}, Accessed ID: {test_id}",
                            risk="High",
                            cvss_score=8.5,
                            solution="Implement proper authorization checks to ensure users can only access their own resources",
                            references=[
                                "https://owasp.org/www-project-api-security/",
                                "https://owasp.org/www-community/attacks/Insecure_Direct_Object_References"
                            ],
                            cwe_id="CWE-639",
                            wasc_id="WASC-42",
                            request=format_http_request(method, url, headers, body),
                            response=format_http_response(200, {}, "Sequential ID access test"),
                            url=url,
                            parameter=obj_id,
                            evidence=f"Successfully accessed object ID {test_id} when original was {obj_id}",
                            scan_id="",
                            timestamp=datetime.now()
                        ))
                        break  # Found vulnerability, no need to test more
        
        except (ValueError, TypeError):
            pass
        
        return vulnerabilities
    
    def _test_predictable_id_access(self, url: str, method: str, headers: Dict[str, str], body: str, obj_id: str) -> List[Vulnerability]:
        """Test access to predictable object IDs."""
        vulnerabilities = []
        
        try:
            # Test with common predictable IDs
            predictable_ids = ['1', '2', '3', '100', '1000', 'admin', 'test', 'demo']
            
            for test_id in predictable_ids:
                if test_id != obj_id and self._test_object_access(url, method, headers, body, obj_id, test_id):
                    vuln_id = f"bola-predictable-{uuid.uuid4().hex[:8]}"
                    vulnerabilities.append(Vulnerability(
                        id=vuln_id,
                        name="BOLA - Predictable ID Access",
                        description=f"API allows access to predictable object IDs. Original ID: {obj_id}, Accessed ID: {test_id}",
                        risk="High",
                        cvss_score=8.0,
                        solution="Use cryptographically secure random IDs and implement proper authorization checks",
                        references=[
                            "https://owasp.org/www-project-api-security/",
                            "https://owasp.org/www-community/attacks/Insecure_Direct_Object_References"
                        ],
                        cwe_id="CWE-639",
                        wasc_id="WASC-42",
                        request=format_http_request(method, url, headers, body),
                        response=format_http_response(200, {}, "Predictable ID access test"),
                        url=url,
                        parameter=obj_id,
                        evidence=f"Successfully accessed predictable object ID {test_id}",
                        scan_id="",
                        timestamp=datetime.now()
                    ))
                    break  # Found vulnerability, no need to test more
        
        except Exception as e:
            self.logger.error(f"Error testing predictable ID access: {e}")
        
        return vulnerabilities
    
    def _test_other_user_access(self, url: str, method: str, headers: Dict[str, str], body: str, obj_id: str) -> List[Vulnerability]:
        """Test access to other users' object IDs."""
        vulnerabilities = []
        
        try:
            # Test with other user IDs (simulated)
            other_user_ids = ['999', '888', '777', 'other_user', 'another_user']
            
            for test_id in other_user_ids:
                if test_id != obj_id and self._test_object_access(url, method, headers, body, obj_id, test_id):
                    vuln_id = f"bola-other-user-{uuid.uuid4().hex[:8]}"
                    vulnerabilities.append(Vulnerability(
                        id=vuln_id,
                        name="BOLA - Other User Access",
                        description=f"API allows access to other users' resources. Original ID: {obj_id}, Accessed ID: {test_id}",
                        risk="Critical",
                        cvss_score=9.0,
                        solution="Implement proper user authorization checks to ensure users can only access their own resources",
                        references=[
                            "https://owasp.org/www-project-api-security/",
                            "https://owasp.org/www-community/attacks/Insecure_Direct_Object_References"
                        ],
                        cwe_id="CWE-639",
                        wasc_id="WASC-42",
                        request=format_http_request(method, url, headers, body),
                        response=format_http_response(200, {}, "Other user access test"),
                        url=url,
                        parameter=obj_id,
                        evidence=f"Successfully accessed other user's object ID {test_id}",
                        scan_id="",
                        timestamp=datetime.now()
                    ))
                    break  # Found vulnerability, no need to test more
        
        except Exception as e:
            self.logger.error(f"Error testing other user access: {e}")
        
        return vulnerabilities
    
    def _test_modified_object_references(self, url: str, method: str, headers: Dict[str, str], body: str, param_name: str, param_value: str) -> List[Vulnerability]:
        """Test with modified object references."""
        vulnerabilities = []
        
        try:
            # Test with modified object references
            modified_values = self._generate_modified_object_references(param_value)
            
            for modified_value in modified_values:
                if self._test_parameter_access(url, method, headers, body, param_name, param_value, modified_value):
                    vuln_id = f"idor-modified-{uuid.uuid4().hex[:8]}"
                    vulnerabilities.append(Vulnerability(
                        id=vuln_id,
                        name="IDOR - Modified Object Reference",
                        description=f"API allows access with modified object references. Parameter: {param_name}, Original: {param_value}, Modified: {modified_value}",
                        risk="High",
                        cvss_score=8.0,
                        solution="Implement proper authorization checks and use indirect object references",
                        references=[
                            "https://owasp.org/www-project-api-security/",
                            "https://owasp.org/www-community/attacks/Insecure_Direct_Object_References"
                        ],
                        cwe_id="CWE-639",
                        wasc_id="WASC-42",
                        request=format_http_request(method, url, headers, body),
                        response=format_http_response(200, {}, "Modified object reference test"),
                        url=url,
                        parameter=param_name,
                        evidence=f"Successfully accessed with modified object reference {modified_value}",
                        scan_id="",
                        timestamp=datetime.now()
                    ))
                    break  # Found vulnerability, no need to test more
        
        except Exception as e:
            self.logger.error(f"Error testing modified object references: {e}")
        
        return vulnerabilities
    
    def _test_user_resource_access(self, url: str, method: str, headers: Dict[str, str], body: str, context: Dict[str, str]) -> List[Vulnerability]:
        """Test access to other users' resources."""
        vulnerabilities = []
        
        try:
            # Modify headers with different user context
            modified_headers = headers.copy()
            modified_headers.update(context)
            
            # Test access with different user context
            response = self.make_request(url, method, modified_headers, body)
            
            if response and response.get('status_code') == 200:
                vuln_id = f"bola-horizontal-{uuid.uuid4().hex[:8]}"
                vulnerabilities.append(Vulnerability(
                    id=vuln_id,
                    name="BOLA - Horizontal Privilege Escalation",
                    description="API allows horizontal privilege escalation - access to other users' resources",
                    risk="High",
                    cvss_score=8.5,
                    solution="Implement proper user authorization checks and resource ownership validation",
                    references=[
                        "https://owasp.org/www-project-api-security/",
                        "https://owasp.org/www-community/attacks/Insecure_Direct_Object_References"
                    ],
                    cwe_id="CWE-639",
                    wasc_id="WASC-42",
                    request=format_http_request(method, url, modified_headers, body),
                    response=format_http_response(200, {}, "Horizontal privilege escalation test"),
                    url=url,
                    parameter="user_context",
                    evidence=f"Successfully accessed resources with different user context: {context}",
                    scan_id="",
                    timestamp=datetime.now()
                ))
        
        except Exception as e:
            self.logger.error(f"Error testing user resource access: {e}")
        
        return vulnerabilities
    
    def _test_privilege_level_access(self, url: str, method: str, headers: Dict[str, str], body: str, level: Dict[str, str]) -> List[Vulnerability]:
        """Test access with different privilege levels."""
        vulnerabilities = []
        
        try:
            # Modify headers with different privilege level
            modified_headers = headers.copy()
            modified_headers.update(level)
            
            # Test access with different privilege level
            response = self.make_request(url, method, modified_headers, body)
            
            if response and response.get('status_code') == 200:
                vuln_id = f"bola-vertical-{uuid.uuid4().hex[:8]}"
                vulnerabilities.append(Vulnerability(
                    id=vuln_id,
                    name="BOLA - Vertical Privilege Escalation",
                    description="API allows vertical privilege escalation - access to higher privilege resources",
                    risk="Critical",
                    cvss_score=9.0,
                    solution="Implement proper role-based access control and privilege validation",
                    references=[
                        "https://owasp.org/www-project-api-security/",
                        "https://owasp.org/www-community/attacks/Insecure_Direct_Object_References"
                    ],
                    cwe_id="CWE-639",
                    wasc_id="WASC-42",
                    request=format_http_request(method, url, modified_headers, body),
                    response=format_http_response(200, {}, "Vertical privilege escalation test"),
                    url=url,
                    parameter="privilege_level",
                    evidence=f"Successfully accessed resources with higher privilege level: {level}",
                    scan_id="",
                    timestamp=datetime.now()
                ))
        
        except Exception as e:
            self.logger.error(f"Error testing privilege level access: {e}")
        
        return vulnerabilities
    
    def _test_object_access(self, url: str, method: str, headers: Dict[str, str], body: str, original_id: str, test_id: str) -> bool:
        """Test if we can access an object with a different ID."""
        try:
            # Replace the original ID with test ID in URL and body
            modified_url = url.replace(original_id, test_id)
            modified_body = body.replace(original_id, test_id) if body else body
            
            # Make request with modified ID
            response = self.make_request(modified_url, method, headers, modified_body)
            
            # Check if we got a successful response (indicating access)
            return bool(response and response.status_code in [200, 201, 202])
        
        except Exception as e:
            self.logger.error(f"Error testing object access: {e}")
            return False
    
    def _test_parameter_access(self, url: str, method: str, headers: Dict[str, str], body: str, param_name: str, original_value: str, test_value: str) -> bool:
        """Test if we can access with a modified parameter value."""
        try:
            # Replace the original parameter value with test value
            modified_url = url.replace(f"{param_name}={original_value}", f"{param_name}={test_value}")
            modified_body = body.replace(f'"{param_name}": "{original_value}"', f'"{param_name}": "{test_value}"') if body else body
            
            # Make request with modified parameter
            response = self.make_request(modified_url, method, headers, modified_body)
            
            # Check if we got a successful response (indicating access)
            return bool(response and response.status_code in [200, 201, 202])
        
        except Exception as e:
            self.logger.error(f"Error testing parameter access: {e}")
            return False
    
    def _generate_modified_object_references(self, original_value: str) -> List[str]:
        """Generate modified object references for testing."""
        modified_values = []
        
        if original_value.isdigit():
            # For numeric IDs, try sequential values
            base_id = int(original_value)
            modified_values.extend([str(base_id + 1), str(base_id - 1), str(base_id + 10)])
        else:
            # For non-numeric IDs, try common variations
            modified_values.extend(['1', '2', '3', 'admin', 'test', 'demo'])
        
        return modified_values
    
    def _generate_user_contexts(self) -> List[Dict[str, str]]:
        """Generate different user contexts for testing."""
        return [
            {'X-User-ID': '999', 'X-User-Role': 'user'},
            {'X-User-ID': '888', 'X-User-Role': 'user'},
            {'X-User-ID': '777', 'X-User-Role': 'user'},
            {'Authorization': 'Bearer other_user_token'},
            {'X-User-Context': 'other_user'},
        ]
    
    def _generate_privilege_levels(self) -> List[Dict[str, str]]:
        """Generate different privilege levels for testing."""
        return [
            {'X-User-Role': 'admin', 'X-Admin-Token': 'admin_token'},
            {'X-User-Role': 'superuser', 'X-Superuser-Token': 'superuser_token'},
            {'X-User-Role': 'root', 'X-Root-Token': 'root_token'},
            {'Authorization': 'Bearer admin_token'},
            {'X-Privilege-Level': 'admin'},
        ]
    
    def generate_poc(self, vulnerability_id: str) -> Optional[ProofOfConcept]:
        """Generate proof of concept for BOLA vulnerability."""
        return None  # BOLA vulnerabilities don't typically have specific POCs
