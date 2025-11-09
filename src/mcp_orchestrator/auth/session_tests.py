"""
Advanced Session Management Security Testing Vectors
Session Fixation, Cookie Security Flags, Timeout Validation
"""

from ..models import (
    TestVector,
    VulnerabilityType,
    TestVectorPosition as Position,
    PositionType,
    TestVectorPayload as PayloadTemplate,
    TestVectorEvidence as Evidence,
    ConfidenceLevel,
    SensitivityLevel,
)

SESSION_TEST_VECTORS = [
    TestVector(
        id="session-fixation-001",
        name="Session Fixation Attack",
        description="Tests if session ID is regenerated after authentication",
        vuln_type=VulnerabilityType.SESSION_FIXATION,
        position=Position(
            type=PositionType.COOKIE, name="session_id", value_prefix="", value_suffix=""
        ),
        payload=PayloadTemplate(
            base="<ATTACKER_PROVIDED_SESSION_ID>",
            variants=["fixed_session_12345", "attacker_session_token"],
            encoding="none",
        ),
        expected_evidence=Evidence(
            indicators=[
                "Session ID not regenerated after login",
                "Pre-authentication session persists post-login",
                "Attacker-provided session ID accepted",
            ],
            false_positive_indicators=[
                "Session regenerated after authentication",
                "New session ID issued",
            ],
            confidence=ConfidenceLevel.CRITICAL,
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Regenerate session ID after authentication. Invalidate old session.",
        references=[
            "https://owasp.org/www-community/attacks/Session_fixation",
            "https://cwe.mitre.org/data/definitions/384.html",
        ],
        tags=["session", "fixation", "authentication"],
    ),
    TestVector(
        id="session-flags-001",
        name="Missing Secure Flag on Session Cookie",
        description="Tests if session cookie lacks Secure flag allowing transmission over HTTP",
        vuln_type=VulnerabilityType.SESSION_FLAG_MISSING,
        position=Position(
            type=PositionType.COOKIE, name="session_id", value_prefix="", value_suffix=""
        ),
        payload=PayloadTemplate(base="", variants=[], encoding="none"),  # Check Set-Cookie header
        expected_evidence=Evidence(
            indicators=[
                "Set-Cookie missing Secure flag",
                "Cookie transmitted over HTTP",
                "Session vulnerable to MITM",
            ],
            false_positive_indicators=["Secure flag present", "HTTPS-only transmission"],
            confidence=ConfidenceLevel.HIGH,
        ),
        sensitivity=SensitivityLevel.HIGH,
        remediation="Set Secure flag on all session cookies. Enforce HTTPS-only.",
        references=[
            "https://owasp.org/www-community/controls/SecureCookieAttribute",
            "https://cwe.mitre.org/data/definitions/614.html",
        ],
        tags=["session", "cookie", "secure-flag"],
    ),
    TestVector(
        id="session-flags-002",
        name="Missing HttpOnly Flag on Session Cookie",
        description="Tests if session cookie lacks HttpOnly flag allowing JavaScript access",
        vuln_type=VulnerabilityType.SESSION_FLAG_MISSING,
        position=Position(
            type=PositionType.COOKIE, name="session_id", value_prefix="", value_suffix=""
        ),
        payload=PayloadTemplate(base="", variants=[], encoding="none"),  # Check Set-Cookie header
        expected_evidence=Evidence(
            indicators=[
                "Set-Cookie missing HttpOnly flag",
                "document.cookie can access session",
                "XSS can steal session token",
            ],
            false_positive_indicators=["HttpOnly flag present", "JavaScript cannot access cookie"],
            confidence=ConfidenceLevel.HIGH,
        ),
        sensitivity=SensitivityLevel.HIGH,
        remediation="Set HttpOnly flag on all session cookies to prevent XSS-based theft.",
        references=[
            "https://owasp.org/www-community/HttpOnly",
            "https://cwe.mitre.org/data/definitions/1004.html",
        ],
        tags=["session", "cookie", "httponly-flag"],
    ),
    TestVector(
        id="session-flags-003",
        name="Missing SameSite Flag on Session Cookie",
        description="Tests if session cookie lacks SameSite flag allowing CSRF attacks",
        vuln_type=VulnerabilityType.SESSION_FLAG_MISSING,
        position=Position(
            type=PositionType.COOKIE, name="session_id", value_prefix="", value_suffix=""
        ),
        payload=PayloadTemplate(base="", variants=[], encoding="none"),  # Check Set-Cookie header
        expected_evidence=Evidence(
            indicators=[
                "Set-Cookie missing SameSite attribute",
                "Cookie sent with cross-site requests",
                "CSRF attacks possible",
            ],
            false_positive_indicators=[
                "SameSite=Strict or SameSite=Lax present",
                "CSRF protection active",
            ],
            confidence=ConfidenceLevel.HIGH,
        ),
        sensitivity=SensitivityLevel.HIGH,
        remediation="Set SameSite=Strict or SameSite=Lax on session cookies.",
        references=[
            "https://owasp.org/www-community/SameSite",
            "https://cwe.mitre.org/data/definitions/352.html",
        ],
        tags=["session", "cookie", "samesite-flag", "csrf"],
    ),
    TestVector(
        id="session-timeout-001",
        name="No Session Timeout Enforcement",
        description="Tests if sessions expire after reasonable inactivity period",
        vuln_type=VulnerabilityType.SESSION_VULN,
        position=Position(
            type=PositionType.COOKIE, name="session_id", value_prefix="", value_suffix=""
        ),
        payload=PayloadTemplate(
            base="<OLD_SESSION_TOKEN>", variants=["<SESSION_FROM_30_DAYS_AGO>"], encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=[
                "Old session still valid",
                "No inactivity timeout",
                "Session never expires",
            ],
            false_positive_indicators=["Session expired", "Timeout enforced"],
            confidence=ConfidenceLevel.HIGH,
        ),
        sensitivity=SensitivityLevel.MEDIUM,
        remediation="Implement session timeout (e.g., 15-30 minutes inactivity). Absolute timeout for sensitive apps.",
        references=[
            "https://owasp.org/www-community/Session_Timeout",
            "https://cwe.mitre.org/data/definitions/613.html",
        ],
        tags=["session", "timeout", "expiration"],
    ),
    TestVector(
        id="session-concurrent-001",
        name="Concurrent Session Hijacking",
        description="Tests if multiple concurrent sessions are allowed for same user",
        vuln_type=VulnerabilityType.SESSION_VULN,
        position=Position(
            type=PositionType.COOKIE, name="session_id", value_prefix="", value_suffix=""
        ),
        payload=PayloadTemplate(
            base="<SESSION_1>", variants=["<SESSION_2_CONCURRENT>"], encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=[
                "Multiple active sessions allowed",
                "No concurrent session limit",
                "Session hijacking risk",
            ],
            false_positive_indicators=["Old session invalidated", "Single active session enforced"],
            confidence=ConfidenceLevel.MEDIUM,
        ),
        sensitivity=SensitivityLevel.MEDIUM,
        remediation="Limit concurrent sessions or notify user of new login. Allow session management UI.",
        references=[
            "https://owasp.org/www-community/Session_Management_Cheat_Sheet",
            "https://cwe.mitre.org/data/definitions/384.html",
        ],
        tags=["session", "concurrent", "hijacking"],
    ),
    TestVector(
        id="session-token-001",
        name="Weak Session Token Entropy",
        description="Tests if session tokens have sufficient randomness",
        vuln_type=VulnerabilityType.SESSION_VULN,
        position=Position(
            type=PositionType.COOKIE, name="session_id", value_prefix="", value_suffix=""
        ),
        payload=PayloadTemplate(base="", variants=[], encoding="none"),  # Analyze generated tokens
        expected_evidence=Evidence(
            indicators=[
                "Sequential session IDs",
                "Predictable token generation",
                "Low entropy tokens (<128 bits)",
            ],
            false_positive_indicators=[
                "Cryptographically random tokens",
                "High entropy (≥128 bits)",
            ],
            confidence=ConfidenceLevel.MEDIUM,
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Use cryptographically secure random number generator (CSPRNG). Minimum 128-bit entropy.",
        references=[
            "https://owasp.org/www-community/vulnerabilities/Insufficient_Session-ID_Length",
            "https://cwe.mitre.org/data/definitions/330.html",
        ],
        tags=["session", "token", "entropy", "randomness"],
    ),
    TestVector(
        id="session-logout-001",
        name="Session Not Invalidated on Logout",
        description="Tests if session is properly invalidated server-side on logout",
        vuln_type=VulnerabilityType.SESSION_VULN,
        position=Position(
            type=PositionType.COOKIE, name="session_id", value_prefix="", value_suffix=""
        ),
        payload=PayloadTemplate(base="<SESSION_AFTER_LOGOUT>", variants=[], encoding="none"),
        expected_evidence=Evidence(
            indicators=[
                "Session still valid after logout",
                "Server-side invalidation missing",
                "Logout only clears client cookie",
            ],
            false_positive_indicators=[
                "Session invalidated server-side",
                "Token rejected after logout",
            ],
            confidence=ConfidenceLevel.HIGH,
        ),
        sensitivity=SensitivityLevel.HIGH,
        remediation="Invalidate session server-side on logout. Don't rely on client-side cookie deletion.",
        references=[
            "https://owasp.org/www-community/Session_Management_Cheat_Sheet",
            "https://cwe.mitre.org/data/definitions/613.html",
        ],
        tags=["session", "logout", "invalidation"],
    ),
    TestVector(
        id="session-prediction-001",
        name="Session ID Prediction Attack",
        description="Tests if session IDs follow predictable pattern",
        vuln_type=VulnerabilityType.SESSION_VULN,
        position=Position(
            type=PositionType.COOKIE, name="session_id", value_prefix="", value_suffix=""
        ),
        payload=PayloadTemplate(
            base="",  # Analyze multiple session IDs
            variants=["session_1", "session_2", "session_3"],
            encoding="none",
        ),
        expected_evidence=Evidence(
            indicators=[
                "Sequential session IDs detected",
                "Timestamp-based IDs",
                "Predictable pattern identified",
            ],
            false_positive_indicators=["No pattern detected", "Random session IDs"],
            confidence=ConfidenceLevel.HIGH,
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Use CSPRNG for session ID generation. Avoid timestamps, counters, or user-related data in IDs.",
        references=["https://cwe.mitre.org/data/definitions/340.html"],
        tags=["session", "prediction", "weak-generation"],
    ),
    TestVector(
        id="session-token-002",
        name="Session Token in URL",
        description="Tests if session token is transmitted in URL parameters",
        vuln_type=VulnerabilityType.SESSION_VULN,
        position=Position(
            type=PositionType.QUERY, name="session_id", value_prefix="", value_suffix=""
        ),
        payload=PayloadTemplate(base="<SESSION_TOKEN>", variants=[], encoding="none"),
        expected_evidence=Evidence(
            indicators=[
                "Session token in URL",
                "Token visible in logs/history",
                "Token in Referer header",
            ],
            false_positive_indicators=["Session only in cookie", "No token in URL"],
            confidence=ConfidenceLevel.HIGH,
        ),
        sensitivity=SensitivityLevel.HIGH,
        remediation="Never transmit session tokens in URLs. Use HttpOnly cookies or Authorization header.",
        references=[
            "https://owasp.org/www-community/vulnerabilities/Information_exposure_through_query_strings_in_url",
            "https://cwe.mitre.org/data/definitions/598.html",
        ],
        tags=["session", "token", "url-exposure"],
    ),
    TestVector(
        id="session-ip-binding-001",
        name="Session Not Bound to IP Address",
        description="Tests if session can be used from different IP addresses",
        vuln_type=VulnerabilityType.SESSION_VULN,
        position=Position(
            type=PositionType.HEADER, name="X-Forwarded-For", value_prefix="", value_suffix=""
        ),
        payload=PayloadTemplate(
            base="<DIFFERENT_IP>",
            variants=["192.168.1.100", "10.0.0.1", "attacker.ip.address"],
            encoding="none",
        ),
        expected_evidence=Evidence(
            indicators=[
                "Session works from different IP",
                "No IP binding validation",
                "Session hijacking possible",
            ],
            false_positive_indicators=[
                "IP change detected and rejected",
                "Re-authentication required",
            ],
            confidence=ConfidenceLevel.MEDIUM,
        ),
        sensitivity=SensitivityLevel.MEDIUM,
        remediation="Consider IP binding for high-security apps. Balance with mobile user experience.",
        references=[
            "https://owasp.org/www-community/Session_Management_Cheat_Sheet",
            "https://cwe.mitre.org/data/definitions/384.html",
        ],
        tags=["session", "ip-binding", "hijacking"],
    ),
    TestVector(
        id="session-device-binding-001",
        name="Session Not Bound to Device Fingerprint",
        description="Tests if session can be used from different devices/browsers",
        vuln_type=VulnerabilityType.SESSION_VULN,
        position=Position(
            type=PositionType.HEADER, name="User-Agent", value_prefix="", value_suffix=""
        ),
        payload=PayloadTemplate(
            base="<DIFFERENT_USER_AGENT>",
            variants=["Mozilla/5.0 (AttackerBrowser)", "curl/7.68.0", "PostmanRuntime/7.26.8"],
            encoding="none",
        ),
        expected_evidence=Evidence(
            indicators=[
                "Session works from different User-Agent",
                "No device fingerprinting",
                "Token theft effective",
            ],
            false_positive_indicators=["Device change detected", "Re-authentication required"],
            confidence=ConfidenceLevel.MEDIUM,
        ),
        sensitivity=SensitivityLevel.MEDIUM,
        remediation="Implement device fingerprinting. Alert user on suspicious device changes.",
        references=["https://owasp.org/www-community/Session_Management_Cheat_Sheet"],
        tags=["session", "device-binding", "fingerprinting"],
    ),
]

# Total vectors: 12
