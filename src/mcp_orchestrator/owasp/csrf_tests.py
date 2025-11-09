"""
Cross-Site Request Forgery (CSRF) Testing Vectors
Token bypass, SameSite bypass, type confusion
"""

from ..models import (
    TestVector, VulnerabilityType, TestVectorPosition as Position, PositionType,
    TestVectorPayload as PayloadTemplate, TestVectorEvidence as Evidence, 
    ConfidenceLevel, SensitivityLevel
)

CSRF_VECTORS = [
    TestVector(
        id="csrf-no-token-001",
        name="CSRF - Missing Token",
        description="CSRF attack when no CSRF token is present",
        vuln_type=VulnerabilityType.CSRF,
        position=Position(type=PositionType.BODY_FORM, name="csrf_token", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="",
            variants=["<missing>"],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["Action performed without token", "State change successful", "No CSRF protection"],
            confidence=ConfidenceLevel.CRITICAL
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Implement CSRF tokens. Use SameSite cookies. Verify Origin/Referer headers.",
        references=["https://owasp.org/www-community/attacks/csrf"],
        tags=["csrf", "missing-token"]
    ),
    
    TestVector(
        id="csrf-token-bypass-001",
        name="CSRF Token Bypass - Empty Value",
        description="Bypass CSRF protection with empty token",
        vuln_type=VulnerabilityType.CSRF,
        position=Position(type=PositionType.BODY_FORM, name="csrf_token", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="",
            variants=["", " ", "null", "undefined"],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["Empty token accepted", "Validation bypassed", "Action performed"],
            confidence=ConfidenceLevel.HIGH
        ),
        sensitivity=SensitivityLevel.HIGH,
        remediation="Validate token presence and value. Reject empty/null tokens. Use strong validation.",
        references=["https://portswigger.net/web-security/csrf"],
        tags=["csrf", "token-bypass", "empty-token"]
    ),
    
    TestVector(
        id="csrf-token-reuse-001",
        name="CSRF Token Reuse",
        description="Test if CSRF tokens can be reused across sessions",
        vuln_type=VulnerabilityType.CSRF,
        position=Position(type=PositionType.BODY_FORM, name="csrf_token", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="valid_token_from_different_session",
            variants=["valid_token_from_different_session", "old_expired_token"],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["Token accepted across sessions", "Token reuse successful", "Weak token binding"],
            confidence=ConfidenceLevel.HIGH
        ),
        sensitivity=SensitivityLevel.HIGH,
        remediation="Bind tokens to sessions. Implement one-time tokens. Validate token ownership.",
        references=["https://owasp.org/www-community/attacks/csrf"],
        tags=["csrf", "token-reuse", "session-binding"]
    ),
    
    TestVector(
        id="csrf-samesite-bypass-001",
        name="CSRF SameSite Cookie Bypass",
        description="Bypass SameSite cookie protection",
        vuln_type=VulnerabilityType.CSRF,
        position=Position(type=PositionType.HEADER, name="Cookie", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="session=valid_session_id; SameSite=None",
            variants=[
                "session=valid_session_id; SameSite=None",
                "session=valid_session_id"
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["SameSite bypassed", "Cross-origin cookie sent", "CSRF successful"],
            confidence=ConfidenceLevel.MEDIUM
        ),
        sensitivity=SensitivityLevel.MEDIUM,
        remediation="Use SameSite=Strict or Lax. Combine with CSRF tokens. Validate Origin header.",
        references=["https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions"],
        tags=["csrf", "samesite", "cookie-bypass"]
    ),
    
    TestVector(
        id="csrf-json-001",
        name="CSRF via JSON Content-Type",
        description="CSRF attack using JSON content type",
        vuln_type=VulnerabilityType.CSRF,
        position=Position(type=PositionType.BODY_JSON, name="action", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base='{"action":"delete_account"}',
            variants=[
                '{"action":"delete_account"}',
                '{"action":"transfer_funds","amount":1000}'
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["JSON CSRF successful", "Content-Type not validated", "State change occurred"],
            confidence=ConfidenceLevel.HIGH
        ),
        sensitivity=SensitivityLevel.HIGH,
        remediation="Validate Content-Type header. Require custom headers. Use CSRF tokens for JSON endpoints.",
        references=["https://portswigger.net/web-security/csrf"],
        tags=["csrf", "json", "content-type"]
    ),
    
    TestVector(
        id="csrf-method-override-001",
        name="CSRF via HTTP Method Override",
        description="CSRF using X-HTTP-Method-Override header",
        vuln_type=VulnerabilityType.CSRF,
        position=Position(type=PositionType.HEADER, name="X-HTTP-Method-Override", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="PUT",
            variants=["PUT", "DELETE", "PATCH"],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["Method override successful", "CSRF via GET/POST", "State change"],
            confidence=ConfidenceLevel.MEDIUM
        ),
        sensitivity=SensitivityLevel.MEDIUM,
        remediation="Validate method override headers. Require CSRF tokens. Implement proper CORS.",
        references=["https://owasp.org/www-community/attacks/csrf"],
        tags=["csrf", "method-override", "http-verb"]
    ),
    
    TestVector(
        id="csrf-referer-bypass-001",
        name="CSRF Referer Header Bypass",
        description="Bypass Referer-based CSRF protection",
        vuln_type=VulnerabilityType.CSRF,
        position=Position(type=PositionType.HEADER, name="Referer", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="",
            variants=["", "https://trusted-domain.com", "https://trusted-domain.com.evil.com"],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["Referer validation bypassed", "Missing referer accepted", "CSRF successful"],
            confidence=ConfidenceLevel.MEDIUM
        ),
        sensitivity=SensitivityLevel.MEDIUM,
        remediation="Don't rely solely on Referer. Use CSRF tokens. Validate Origin header.",
        references=["https://portswigger.net/web-security/csrf"],
        tags=["csrf", "referer-bypass", "header-validation"]
    ),
    
    TestVector(
        id="csrf-subdomain-001",
        name="CSRF from Subdomain",
        description="CSRF attack from trusted subdomain",
        vuln_type=VulnerabilityType.CSRF,
        position=Position(type=PositionType.HEADER, name="Origin", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="https://attacker.trusted-domain.com",
            variants=[
                "https://attacker.trusted-domain.com",
                "https://xss.trusted-domain.com"
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["Subdomain origin accepted", "CSRF from subdomain", "Trust boundary issue"],
            confidence=ConfidenceLevel.MEDIUM
        ),
        sensitivity=SensitivityLevel.MEDIUM,
        remediation="Validate exact origin. Don't trust all subdomains. Use CSRF tokens.",
        references=["https://owasp.org/www-community/attacks/csrf"],
        tags=["csrf", "subdomain", "trust-boundary"]
    ),
]

# Total vectors: 8
