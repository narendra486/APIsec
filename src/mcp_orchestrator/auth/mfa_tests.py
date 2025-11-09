"""
Multi-Factor Authentication (MFA) Bypass Testing Vectors
Token Reuse, Rate Limiting Bypass, Backup Code Enumeration
"""

from ..models import (
    TestVector, VulnerabilityType, TestVectorPosition as Position, PositionType,
    TestVectorPayload as PayloadTemplate, TestVectorEvidence as Evidence, 
    ConfidenceLevel, SensitivityLevel
)

MFA_TEST_VECTORS = [
    TestVector(
        id="mfa-bypass-001",
        name="MFA Token Reuse Attack",
        description="Tests if same MFA token/code can be used multiple times",
        vuln_type=VulnerabilityType.MFA_TOKEN_REUSE,
        position=Position(
            type=PositionType.BODY_JSON,
            name="mfa_code",
            value_prefix="",
            value_suffix=""
        ),
        payload=PayloadTemplate(
            base="<CAPTURED_MFA_CODE>",
            variants=[
                "<SAME_CODE_REUSED>"
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=[
                "Same MFA code accepted multiple times",
                "No token invalidation after use",
                "Multiple authentications with single code"
            ],
            false_positive_indicators=[
                "Code already used error",
                "Token invalidated after first use"
            ],
            confidence=ConfidenceLevel.CRITICAL
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="MFA codes must be single-use. Invalidate immediately after successful verification.",
        references=[
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/10-Testing_for_Weaker_Authentication_in_Alternative_Channel",
            "https://cwe.mitre.org/data/definitions/294.html"
        ],
        tags=["mfa", "token-reuse", "replay-attack"]
    ),
    
    TestVector(
        id="mfa-bypass-002",
        name="MFA Rate Limiting Bypass",
        description="Tests if MFA verification endpoint can be brute-forced",
        vuln_type=VulnerabilityType.MFA_RATE_LIMIT_BYPASS,
        position=Position(
            type=PositionType.BODY_JSON,
            name="mfa_code",
            value_prefix="",
            value_suffix=""
        ),
        payload=PayloadTemplate(
            base="000000",
            variants=[
                "000001", "000002", "000003", "000004", "000005",
                "111111", "123456", "654321", "999999"
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=[
                "No rate limiting on MFA verification",
                "Unlimited brute force attempts allowed",
                "No account lockout after failed attempts"
            ],
            false_positive_indicators=[
                "Rate limiting enforced",
                "Account locked after failures",
                "CAPTCHA required"
            ],
            confidence=ConfidenceLevel.HIGH
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Implement rate limiting (e.g., 3-5 attempts per minute). Lock account temporarily after failed attempts.",
        references=[
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/03-Testing_for_Weak_Lock_Out_Mechanism",
            "https://cwe.mitre.org/data/definitions/307.html"
        ],
        tags=["mfa", "rate-limit", "brute-force"]
    ),
    
    TestVector(
        id="mfa-bypass-003",
        name="MFA Backup Code Enumeration",
        description="Tests if backup codes can be enumerated without rate limiting",
        vuln_type=VulnerabilityType.MFA_BYPASS,
        position=Position(
            type=PositionType.BODY_JSON,
            name="backup_code",
            value_prefix="",
            value_suffix=""
        ),
        payload=PayloadTemplate(
            base="AAAA-BBBB-CCCC-DDDD",
            variants=[
                "0000-0000-0000-0001",
                "1111-1111-1111-1111",
                "AAAA-AAAA-AAAA-AAAA",
                "1234-5678-9012-3456"
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=[
                "Backup codes can be enumerated",
                "No rate limiting on backup code endpoint",
                "Predictable backup code generation"
            ],
            false_positive_indicators=[
                "Rate limiting active",
                "Random backup codes with high entropy"
            ],
            confidence=ConfidenceLevel.HIGH
        ),
        sensitivity=SensitivityLevel.HIGH,
        remediation="Use cryptographically random backup codes. Enforce rate limiting. Limit backup code attempts.",
        references=[
            "https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks",
            "https://cwe.mitre.org/data/definitions/330.html"
        ],
        tags=["mfa", "backup-codes", "enumeration"]
    ),
    
    TestVector(
        id="mfa-bypass-004",
        name="MFA Bypass via Parameter Manipulation",
        description="Tests if MFA can be bypassed by manipulating request parameters",
        vuln_type=VulnerabilityType.MFA_BYPASS,
        position=Position(
            type=PositionType.BODY_JSON,
            name="mfa_required",
            value_prefix="",
            value_suffix=""
        ),
        payload=PayloadTemplate(
            base="false",
            variants=[
                "false",
                "0",
                "null",
                "undefined",
                ""
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=[
                "MFA bypassed by setting mfa_required=false",
                "Authentication succeeds without MFA",
                "Client-side MFA enforcement"
            ],
            false_positive_indicators=[
                "MFA enforced server-side",
                "Parameter manipulation rejected"
            ],
            confidence=ConfidenceLevel.HIGH
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Enforce MFA server-side. Never trust client-provided MFA status.",
        references=[
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/",
            "https://cwe.mitre.org/data/definitions/602.html"
        ],
        tags=["mfa", "bypass", "parameter-manipulation"]
    ),
    
    TestVector(
        id="mfa-bypass-005",
        name="MFA Bypass via Status Code Manipulation",
        description="Tests if MFA can be bypassed by changing response status code",
        vuln_type=VulnerabilityType.MFA_BYPASS,
        position=Position(
            type=PositionType.HEADER,
            name="X-MFA-Status",
            value_prefix="",
            value_suffix=""
        ),
        payload=PayloadTemplate(
            base="verified",
            variants=[
                "verified",
                "success",
                "complete",
                "bypass"
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=[
                "Custom header bypasses MFA",
                "Status code manipulation works",
                "No server-side MFA verification"
            ],
            false_positive_indicators=[
                "Header ignored",
                "MFA still enforced"
            ],
            confidence=ConfidenceLevel.MEDIUM
        ),
        sensitivity=SensitivityLevel.HIGH,
        remediation="Implement server-side MFA state management. Don't rely on client headers.",
        references=[
            "https://cwe.mitre.org/data/definitions/602.html"
        ],
        tags=["mfa", "bypass", "status-manipulation"]
    ),
    
    TestVector(
        id="mfa-bypass-006",
        name="MFA Session Fixation",
        description="Tests if MFA session can be fixed before authentication",
        vuln_type=VulnerabilityType.MFA_BYPASS,
        position=Position(
            type=PositionType.COOKIE,
            name="mfa_session",
            value_prefix="",
            value_suffix=""
        ),
        payload=PayloadTemplate(
            base="<ATTACKER_CONTROLLED_SESSION>",
            variants=[
                "fixed_session_12345"
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=[
                "MFA session can be fixed",
                "Session not regenerated after MFA",
                "Attacker can hijack post-MFA session"
            ],
            false_positive_indicators=[
                "Session regenerated after MFA",
                "Session fixation prevented"
            ],
            confidence=ConfidenceLevel.HIGH
        ),
        sensitivity=SensitivityLevel.HIGH,
        remediation="Regenerate session ID after successful MFA. Implement session binding.",
        references=[
            "https://owasp.org/www-community/attacks/Session_fixation",
            "https://cwe.mitre.org/data/definitions/384.html"
        ],
        tags=["mfa", "session-fixation", "session-management"]
    ),
    
    TestVector(
        id="mfa-bypass-007",
        name="TOTP Time Window Exploitation",
        description="Tests if TOTP time window is too large allowing extended code validity",
        vuln_type=VulnerabilityType.MFA_BYPASS,
        position=Position(
            type=PositionType.BODY_JSON,
            name="totp_code",
            value_prefix="",
            value_suffix=""
        ),
        payload=PayloadTemplate(
            base="<TOTP_CODE_FROM_10_MINUTES_AGO>",
            variants=[
                "<OLD_TOTP_CODE>"
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=[
                "Old TOTP codes accepted",
                "Time window too large (>2 minutes)",
                "Extended code validity period"
            ],
            false_positive_indicators=[
                "Only current codes accepted",
                "Time window appropriate (±30-60s)"
            ],
            confidence=ConfidenceLevel.MEDIUM
        ),
        sensitivity=SensitivityLevel.MEDIUM,
        remediation="Limit TOTP time window to ±1 step (30-60 seconds). Track used codes.",
        references=[
            "https://tools.ietf.org/html/rfc6238",
            "https://cwe.mitre.org/data/definitions/613.html"
        ],
        tags=["mfa", "totp", "time-window"]
    ),
    
    TestVector(
        id="mfa-bypass-008",
        name="SMS MFA Code Interception Risk",
        description="Tests if SMS-based MFA is vulnerable to SS7 attacks or SIM swapping",
        vuln_type=VulnerabilityType.MFA_BYPASS,
        position=Position(
            type=PositionType.BODY_JSON,
            name="phone_number",
            value_prefix="+1",
            value_suffix=""
        ),
        payload=PayloadTemplate(
            base="<ATTACKER_PHONE>",
            variants=[
                "+1234567890"
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=[
                "Phone number can be changed without re-authentication",
                "SMS sent to new number without verification",
                "No SIM swap detection"
            ],
            false_positive_indicators=[
                "Phone change requires verification",
                "SIM swap detection active"
            ],
            confidence=ConfidenceLevel.MEDIUM
        ),
        sensitivity=SensitivityLevel.HIGH,
        remediation="Use authenticator apps instead of SMS. Implement SIM swap detection. Require verification for phone changes.",
        references=[
            "https://owasp.org/www-community/vulnerabilities/Insufficient_Authentication",
            "https://cwe.mitre.org/data/definitions/287.html"
        ],
        tags=["mfa", "sms", "sim-swap"]
    ),
    
    TestVector(
        id="mfa-bypass-009",
        name="MFA Remember Device Abuse",
        description="Tests if 'remember this device' feature can be abused",
        vuln_type=VulnerabilityType.MFA_BYPASS,
        position=Position(
            type=PositionType.COOKIE,
            name="mfa_remember_token",
            value_prefix="",
            value_suffix=""
        ),
        payload=PayloadTemplate(
            base="<STOLEN_REMEMBER_TOKEN>",
            variants=[
                "permanent_token_12345"
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=[
                "Remember token never expires",
                "Token works from different IP/browser",
                "No device fingerprinting"
            ],
            false_positive_indicators=[
                "Token expires after reasonable period",
                "Device fingerprinting enforced"
            ],
            confidence=ConfidenceLevel.MEDIUM
        ),
        sensitivity=SensitivityLevel.MEDIUM,
        remediation="Limit remember token lifetime (e.g., 30 days). Bind to device fingerprint. Allow user to revoke.",
        references=[
            "https://cwe.mitre.org/data/definitions/613.html"
        ],
        tags=["mfa", "remember-device", "token-abuse"]
    ),
    
    TestVector(
        id="mfa-bypass-010",
        name="MFA Not Enforced on All Endpoints",
        description="Tests if MFA can be bypassed by accessing unprotected endpoints",
        vuln_type=VulnerabilityType.MFA_BYPASS,
        position=Position(
            type=PositionType.PATH,
            name="endpoint",
            value_prefix="/",
            value_suffix=""
        ),
        payload=PayloadTemplate(
            base="/api/user/profile",
            variants=[
                "/api/v2/user/profile",
                "/internal/user/profile",
                "/admin/user/profile",
                "/user/profile.json",
                "/user/profile?format=xml"
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=[
                "Alternative endpoints bypass MFA",
                "API version bypasses MFA",
                "Inconsistent MFA enforcement"
            ],
            false_positive_indicators=[
                "MFA enforced on all endpoints",
                "Consistent authentication required"
            ],
            confidence=ConfidenceLevel.HIGH
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Enforce MFA consistently across all endpoints and API versions. Use centralized auth middleware.",
        references=[
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/",
            "https://cwe.mitre.org/data/definitions/284.html"
        ],
        tags=["mfa", "bypass", "inconsistent-enforcement"]
    ),
]

# Total vectors: 10
