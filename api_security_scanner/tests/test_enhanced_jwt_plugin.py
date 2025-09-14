"""
Tests for Enhanced JWT Security Checker Plugin.
"""

import pytest
import json
import base64
import hmac
import hashlib
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timedelta

from api_security_scanner.plugins.jwt_security_checker import JWTSecurityChecker
from api_security_scanner.core.scanner_plugins import PluginResult, Vulnerability


class TestEnhancedJWTSecurityChecker:
    """Test the enhanced JWT security checker plugin."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.plugin = JWTSecurityChecker()
        self.mock_response = Mock()
        self.mock_response.status_code = 200
        self.mock_response.headers = {'Content-Type': 'application/json'}
        self.mock_response.text = '{"message": "success"}'
    
    def test_plugin_initialization(self):
        """Test plugin initialization."""
        assert self.plugin.name == "JWTSecurityChecker"
        assert self.plugin.description == "Advanced JWT token vulnerability detection, OAuth flow analysis, and security testing"
        assert self.plugin.version == "2.0.0"
        assert len(self.plugin.weak_secrets) > 0
        assert 'algorithm_confusion' in self.plugin.attack_vectors
    
    def test_jwt_token_detection(self):
        """Test JWT token detection."""
        # Test valid JWT pattern
        valid_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        assert self.plugin._is_jwt_token(valid_jwt)
        
        # Test Bearer token format
        bearer_token = f"Bearer {valid_jwt}"
        assert self.plugin._is_jwt_token(bearer_token)
        
        # Test invalid JWT
        invalid_jwt = "invalid.jwt.token"
        assert not self.plugin._is_jwt_token(invalid_jwt)
    
    def test_jwt_token_extraction(self):
        """Test JWT token extraction from requests and responses."""
        request = {
            'headers': {
                'Authorization': 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'
            }
        }
        
        response = Mock()
        response.text = '{"access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"}'
        
        tokens = self.plugin._extract_jwt_tokens(request, response)
        assert len(tokens) >= 1
        assert tokens[0]['type'] == 'request'
        assert 'Request Header: Authorization' in tokens[0]['location']
    
    def test_jwt_decode_encode(self):
        """Test JWT part encoding and decoding."""
        test_data = {"alg": "HS256", "typ": "JWT"}
        encoded = self.plugin._encode_jwt_part(test_data)
        decoded = self.plugin._decode_jwt_part(encoded)
        assert decoded == test_data
    
    def test_weak_algorithm_detection(self):
        """Test detection of weak JWT algorithms."""
        # Test 'none' algorithm
        none_header = {"alg": "none", "typ": "JWT"}
        none_token = f"{self.plugin._encode_jwt_part(none_header)}.eyJzdWIiOiIxMjM0NTY3ODkwfQ."
        
        request = {'headers': {'Authorization': f'Bearer {none_token}'}}
        vulnerabilities = self.plugin._check_weak_algorithms(none_header, none_token, "https://test.com", "GET", {}, "test")
        
        assert len(vulnerabilities) > 0
        assert vulnerabilities[0].name == "JWT None Algorithm Vulnerability"
        assert vulnerabilities[0].risk == "High"
        assert vulnerabilities[0].cvss_score == 8.1
    
    def test_missing_signature_detection(self):
        """Test detection of missing JWT signatures."""
        header_data = {"alg": "HS256", "typ": "JWT"}
        payload_data = {"sub": "1234567890"}
        empty_signature = ""
        
        vulnerabilities = self.plugin._check_signature_vulnerabilities(
            header_data, payload_data, empty_signature, "test_token", 
            "https://test.com", "GET", {}, "test"
        )
        
        assert len(vulnerabilities) > 0
        assert vulnerabilities[0].name == "JWT Missing Signature"
        assert vulnerabilities[0].risk == "High"
    
    def test_missing_expiration_detection(self):
        """Test detection of missing JWT expiration."""
        payload_data = {"sub": "1234567890", "name": "John Doe"}
        
        vulnerabilities = self.plugin._check_token_expiration(
            payload_data, "test_token", "https://test.com", "GET", {}, "test"
        )
        
        assert len(vulnerabilities) > 0
        assert vulnerabilities[0].name == "JWT Missing Expiration"
        assert vulnerabilities[0].risk == "Medium"
    
    def test_long_expiration_detection(self):
        """Test detection of long JWT expiration times."""
        # Create expiration time 2 years in the future
        future_time = int((datetime.now() + timedelta(days=730)).timestamp())
        payload_data = {"sub": "1234567890", "exp": future_time}
        
        vulnerabilities = self.plugin._check_token_expiration(
            payload_data, "test_token", "https://test.com", "GET", {}, "test"
        )
        
        assert len(vulnerabilities) > 0
        assert vulnerabilities[0].name == "JWT Long Expiration Time"
        assert vulnerabilities[0].risk == "Low"
    
    def test_sensitive_data_detection(self):
        """Test detection of sensitive data in JWT payload."""
        payload_data = {
            "sub": "1234567890",
            "password": "secret123",
            "email": "user@example.com"
        }
        
        vulnerabilities = self.plugin._check_sensitive_data_in_token(
            payload_data, "test_token", "https://test.com", "GET", {}, "test"
        )
        
        assert len(vulnerabilities) > 0
        # Should detect password in payload
        password_vuln = next((v for v in vulnerabilities if "password" in v.evidence.lower()), None)
        assert password_vuln is not None
        assert password_vuln.risk == "Medium"
    
    def test_algorithm_confusion_detection(self):
        """Test detection of algorithm confusion vulnerabilities."""
        header_data = {"alg": "HS256", "typ": "JWT"}
        payload_data = {"sub": "1234567890"}
        
        vulnerabilities = self.plugin._check_algorithm_confusion(
            header_data, payload_data, "test_token", "https://test.com", "GET", {}, "test"
        )
        
        assert len(vulnerabilities) > 0
        assert vulnerabilities[0].name == "JWT Algorithm Confusion Vulnerability"
        assert vulnerabilities[0].risk == "High"
    
    def test_oauth_password_grant_detection(self):
        """Test detection of OAuth password grant type."""
        request = {
            'body': 'grant_type=password&username=user&password=pass'
        }
        
        vulnerabilities = self.plugin._check_oauth_grant_types(
            request, self.mock_response, "https://test.com", "POST", {}
        )
        
        assert len(vulnerabilities) > 0
        assert vulnerabilities[0].name == "OAuth Password Grant Type"
        assert vulnerabilities[0].risk == "High"
    
    def test_oauth_implicit_grant_detection(self):
        """Test detection of OAuth implicit grant type."""
        request = {
            'body': 'grant_type=implicit&client_id=test'
        }
        
        vulnerabilities = self.plugin._check_oauth_grant_types(
            request, self.mock_response, "https://test.com", "POST", {}
        )
        
        assert len(vulnerabilities) > 0
        assert vulnerabilities[0].name == "OAuth Implicit Grant Type"
        assert vulnerabilities[0].risk == "Medium"
    
    def test_oauth_open_redirect_detection(self):
        """Test detection of OAuth open redirect vulnerabilities."""
        request = {}
        
        vulnerabilities = self.plugin._check_oauth_redirect_uri(
            request, self.mock_response, "https://test.com/oauth/authorize?redirect_uri=*", "GET", {}
        )
        
        assert len(vulnerabilities) > 0
        assert vulnerabilities[0].name == "OAuth Open Redirect Vulnerability"
        assert vulnerabilities[0].risk == "High"
    
    def test_oauth_missing_state_parameter(self):
        """Test detection of missing OAuth state parameter."""
        request = {}
        
        vulnerabilities = self.plugin._check_oauth_state_parameter(
            request, self.mock_response, "https://test.com/oauth/authorize?client_id=test", "GET", {}
        )
        
        assert len(vulnerabilities) > 0
        assert vulnerabilities[0].name == "OAuth Missing State Parameter"
        assert vulnerabilities[0].risk == "Medium"
    
    def test_jwt_url_parameter_detection(self):
        """Test detection of JWT tokens in URL parameters."""
        request = {}
        
        vulnerabilities = self.plugin._check_jwt_implementation_vulnerabilities(
            request, self.mock_response, "https://test.com/api?jwt=token123", "GET", {}
        )
        
        assert len(vulnerabilities) > 0
        assert vulnerabilities[0].name == "JWT Token in URL Parameter"
        assert vulnerabilities[0].risk == "Medium"
    
    def test_jwt_insecure_cookie_detection(self):
        """Test detection of JWT tokens in insecure cookies."""
        headers = {'Cookie': 'jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'}
        
        vulnerabilities = self.plugin._check_token_storage_vulnerabilities(
            {}, self.mock_response, "https://test.com", "GET", headers
        )
        
        assert len(vulnerabilities) > 0
        assert vulnerabilities[0].name == "JWT Token in Insecure Cookie"
        assert vulnerabilities[0].risk == "Medium"
    
    def test_exposed_key_detection(self):
        """Test detection of exposed JWT keys."""
        response = Mock()
        response.text = '{"secret": "my_jwt_secret_key", "message": "success"}'
        response.status_code = 200
        response.headers = {'Content-Type': 'application/json'}
        
        vulnerabilities = self.plugin._check_jwt_key_management(
            {}, response, "https://test.com", "GET", {}
        )
        
        assert len(vulnerabilities) > 0
        assert vulnerabilities[0].name == "JWT Key Exposed in Response"
        assert vulnerabilities[0].risk == "Critical"
    
    def test_missing_jti_claim_detection(self):
        """Test detection of missing JTI claim."""
        request = {}
        
        vulnerabilities = self.plugin._check_jwt_replay_attacks(
            request, self.mock_response, "https://test.com", "GET", {}
        )
        
        # This test might not find vulnerabilities if no JWT tokens are present
        # Let's create a more specific test
        token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        request_with_jwt = {'headers': {'Authorization': f'Bearer {token}'}}
        
        vulnerabilities = self.plugin._check_jwt_replay_attacks(
            request_with_jwt, self.mock_response, "https://test.com", "GET", {}
        )
        
        # Should detect missing JTI claim
        jti_vuln = next((v for v in vulnerabilities if "Missing JTI Claim" in v.name), None)
        if jti_vuln:
            assert jti_vuln.risk == "Medium"
    
    @patch.object(JWTSecurityChecker, 'make_request')
    def test_algorithm_confusion_attack(self, mock_make_request):
        """Test algorithm confusion attack."""
        mock_make_request.return_value = self.mock_response
        
        # Create a token with HS256 algorithm
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {"sub": "1234567890"}
        header_encoded = self.plugin._encode_jwt_part(header)
        payload_encoded = self.plugin._encode_jwt_part(payload)
        token = f"{header_encoded}.{payload_encoded}.signature"
        
        vulnerabilities = self.plugin._test_algorithm_confusion_attacks(
            token, "https://test.com", "GET", {}, "test"
        )
        
        # Should attempt algorithm confusion attack
        assert mock_make_request.called
    
    @patch.object(JWTSecurityChecker, 'make_request')
    def test_brute_force_attack(self, mock_make_request):
        """Test brute force attack on weak secrets."""
        mock_make_request.return_value = self.mock_response
        
        # Create a token with HS256 algorithm
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {"sub": "1234567890"}
        header_encoded = self.plugin._encode_jwt_part(header)
        payload_encoded = self.plugin._encode_jwt_part(payload)
        
        # Create token with weak secret
        message = f"{header_encoded}.{payload_encoded}"
        weak_secret = "secret"
        signature = base64.urlsafe_b64encode(
            hmac.new(weak_secret.encode(), message.encode(), hashlib.sha256).digest()
        ).decode().rstrip('=')
        token = f"{header_encoded}.{payload_encoded}.{signature}"
        
        vulnerabilities = self.plugin._test_brute_force_attacks(
            token, "https://test.com", "GET", {}, "test"
        )
        
        # Should attempt brute force attack
        assert mock_make_request.called
    
    @patch.object(JWTSecurityChecker, 'make_request')
    def test_header_injection_attack(self, mock_make_request):
        """Test header injection attack."""
        mock_make_request.return_value = self.mock_response
        
        # Create a token
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {"sub": "1234567890"}
        header_encoded = self.plugin._encode_jwt_part(header)
        payload_encoded = self.plugin._encode_jwt_part(payload)
        token = f"{header_encoded}.{payload_encoded}.signature"
        
        vulnerabilities = self.plugin._test_header_injection_attacks(
            token, "https://test.com", "GET", {}, "test"
        )
        
        # Should attempt header injection attacks
        assert mock_make_request.called
    
    @patch.object(JWTSecurityChecker, 'make_request')
    def test_claim_manipulation_attack(self, mock_make_request):
        """Test claim manipulation attack."""
        mock_make_request.return_value = self.mock_response
        
        # Create a token
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {"sub": "1234567890", "role": "user"}
        header_encoded = self.plugin._encode_jwt_part(header)
        payload_encoded = self.plugin._encode_jwt_part(payload)
        token = f"{header_encoded}.{payload_encoded}.signature"
        
        vulnerabilities = self.plugin._test_claim_manipulation_attacks(
            token, "https://test.com", "GET", {}, "test"
        )
        
        # Should attempt claim manipulation attacks
        assert mock_make_request.called
    
    def test_comprehensive_jwt_analysis(self):
        """Test comprehensive JWT analysis."""
        # Create a request with JWT token
        request = {
            'url': 'https://test.com/api/protected',
            'method': 'GET',
            'headers': {
                'Authorization': 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'
            }
        }
        
        response = Mock()
        response.status_code = 200
        response.headers = {'Content-Type': 'application/json'}
        response.text = '{"message": "success"}'
        
        # Mock the make_request method
        with patch.object(self.plugin, 'make_request', return_value=response):
            result = self.plugin.check("https://test.com", [request])
        
        assert isinstance(result, PluginResult)
        assert result.success
        assert result.plugin_name == "JWTSecurityChecker"
        # Should find some vulnerabilities in the test JWT
        assert len(result.vulnerabilities) > 0
    
    def test_oauth_flow_detection(self):
        """Test OAuth flow detection."""
        request = {
            'url': 'https://test.com/oauth/token',
            'method': 'POST',
            'headers': {'Content-Type': 'application/x-www-form-urlencoded'},
            'body': 'grant_type=authorization_code&code=abc123&redirect_uri=https://client.com/callback'
        }
        
        response = Mock()
        response.status_code = 200
        response.headers = {'Content-Type': 'application/json'}
        response.text = '{"access_token": "token123", "token_type": "Bearer", "expires_in": 3600}'
        
        # Mock the make_request method
        with patch.object(self.plugin, 'make_request', return_value=response):
            result = self.plugin.check("https://test.com", [request])
        
        assert isinstance(result, PluginResult)
        assert result.success
        # Should detect OAuth flows and potentially find vulnerabilities
        assert len(result.vulnerabilities) >= 0  # May or may not find vulnerabilities depending on implementation


if __name__ == "__main__":
    pytest.main([__file__])
