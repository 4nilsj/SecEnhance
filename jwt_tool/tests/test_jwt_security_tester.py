import pytest
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))
from jwt_security_tester import JWTSecurityTester

def test_validate_jwt_token_valid():
    tester = JWTSecurityTester()
    valid_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    assert tester.validate_jwt_token(valid_token)

def test_validate_jwt_token_invalid():
    tester = JWTSecurityTester()
    invalid_token = "not.a.jwt"
    assert not tester.validate_jwt_token(invalid_token)

def test_analyze_token_structure():
    tester = JWTSecurityTester()
    token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    result = tester.analyze_token_structure(token)
    assert 'header' in result and 'payload' in result

def test_cve_2015_2951_alg_none():
    tester = JWTSecurityTester()
    token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    result = tester.test_cve_2015_2951_alg_none(token)
    assert 'cve' in result and result['cve'] == 'CVE-2015-2951' 