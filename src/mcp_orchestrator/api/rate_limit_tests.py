"""
API Rate Limiting Bypass Testing Vectors
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

RATE_LIMIT_BYPASS_VECTORS = [
    TestVector(
        id="rate-limit-bypass-001",
        name="Rate Limit Bypass via X-Forwarded-For",
        description="Tests if rate limiting can be bypassed by changing X-Forwarded-For header",
        vuln_type=VulnerabilityType.API_RATE_LIMIT_BYPASS,
        position=Position(
            type=PositionType.HEADER, name="X-Forwarded-For", value_prefix="", value_suffix=""
        ),
        payload=PayloadTemplate(
            base="1.2.3.4", variants=["1.2.3.4", "5.6.7.8", "9.10.11.12"], encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["Rate limit bypassed", "Unlimited requests possible"],
            confidence=ConfidenceLevel.HIGH,
        ),
        sensitivity=SensitivityLevel.HIGH,
        remediation="Don't rely on client headers for rate limiting. Use authenticated identity.",
        references=["https://cwe.mitre.org/data/definitions/770.html"],
        tags=["rate-limit", "bypass", "x-forwarded-for"],
    ),
    TestVector(
        id="rate-limit-bypass-002",
        name="Rate Limit Bypass via User-Agent Rotation",
        description="Tests if rate limiting can be bypassed by rotating User-Agent",
        vuln_type=VulnerabilityType.API_RATE_LIMIT_BYPASS,
        position=Position(
            type=PositionType.HEADER, name="User-Agent", value_prefix="", value_suffix=""
        ),
        payload=PayloadTemplate(
            base="Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            variants=[
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
                "Mozilla/5.0 (X11; Linux x86_64)",
                "curl/7.68.0",
            ],
            encoding="none",
        ),
        expected_evidence=Evidence(
            indicators=["Rate limit reset with different UA", "Bypass successful"],
            confidence=ConfidenceLevel.MEDIUM,
        ),
        sensitivity=SensitivityLevel.MEDIUM,
        remediation="Use IP address or authenticated identity for rate limiting, not User-Agent.",
        references=[
            "https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/"
        ],
        tags=["rate-limit", "bypass", "user-agent"],
    ),
    TestVector(
        id="rate-limit-bypass-003",
        name="Rate Limit Bypass via Distributed Requests",
        description="Tests if rate limiting is per-IP or global",
        vuln_type=VulnerabilityType.API_RATE_LIMIT_BYPASS,
        position=Position(
            type=PositionType.HEADER, name="X-Real-IP", value_prefix="", value_suffix=""
        ),
        payload=PayloadTemplate(
            base="10.0.0.1",
            variants=["10.0.0.1", "10.0.0.2", "10.0.0.3", "192.168.1.1"],
            encoding="none",
        ),
        expected_evidence=Evidence(
            indicators=["Per-IP limit only", "No global limit", "Distributed attack possible"],
            confidence=ConfidenceLevel.MEDIUM,
        ),
        sensitivity=SensitivityLevel.MEDIUM,
        remediation="Implement both per-IP and global rate limits. Use authenticated rate limiting.",
        references=["https://cwe.mitre.org/data/definitions/770.html"],
        tags=["rate-limit", "distributed", "bypass"],
    ),
    TestVector(
        id="rate-limit-bypass-004",
        name="Rate Limit Bypass via Session Rotation",
        description="Tests if creating new sessions bypasses rate limits",
        vuln_type=VulnerabilityType.API_RATE_LIMIT_BYPASS,
        position=Position(
            type=PositionType.HEADER, name="Cookie", value_prefix="session=", value_suffix=""
        ),
        payload=PayloadTemplate(
            base="session1",
            variants=["session1", "session2", "session3", "newsession"],
            encoding="none",
        ),
        expected_evidence=Evidence(
            indicators=["Rate limit reset with new session", "Session rotation bypass"],
            confidence=ConfidenceLevel.HIGH,
        ),
        sensitivity=SensitivityLevel.HIGH,
        remediation="Apply rate limits per user account, not per session. Track anonymous users by IP.",
        references=[
            "https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/"
        ],
        tags=["rate-limit", "session", "bypass"],
    ),
    TestVector(
        id="rate-limit-bypass-005",
        name="Rate Limit Bypass via Header Manipulation",
        description="Tests if custom headers can bypass rate limiting",
        vuln_type=VulnerabilityType.API_RATE_LIMIT_BYPASS,
        position=Position(
            type=PositionType.HEADER, name="X-API-Key", value_prefix="", value_suffix=""
        ),
        payload=PayloadTemplate(
            base="key1", variants=["key1", "key2", "test", "bypass"], encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["Different keys get separate limits", "Header rotation bypass"],
            confidence=ConfidenceLevel.MEDIUM,
        ),
        sensitivity=SensitivityLevel.MEDIUM,
        remediation="Apply rate limits consistently across all authentication methods. Validate API keys.",
        references=["https://cwe.mitre.org/data/definitions/770.html"],
        tags=["rate-limit", "header-manipulation", "bypass"],
    ),
    TestVector(
        id="rate-limit-bypass-006",
        name="Rate Limit Bypass via HTTP Method Change",
        description="Tests if different HTTP methods have separate rate limits",
        vuln_type=VulnerabilityType.API_RATE_LIMIT_BYPASS,
        position=Position(
            type=PositionType.HEADER,
            name="X-HTTP-Method-Override",
            value_prefix="",
            value_suffix="",
        ),
        payload=PayloadTemplate(
            base="POST", variants=["POST", "PUT", "PATCH", "GET"], encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["Different methods have different limits", "Method override bypass"],
            confidence=ConfidenceLevel.MEDIUM,
        ),
        sensitivity=SensitivityLevel.MEDIUM,
        remediation="Apply rate limits per endpoint regardless of HTTP method. Block method override headers.",
        references=[
            "https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/"
        ],
        tags=["rate-limit", "http-method", "bypass"],
    ),
    TestVector(
        id="rate-limit-bypass-007",
        name="Rate Limit Bypass via Case Sensitivity",
        description="Tests if header case variations bypass rate limiting",
        vuln_type=VulnerabilityType.API_RATE_LIMIT_BYPASS,
        position=Position(
            type=PositionType.HEADER, name="x-forwarded-for", value_prefix="", value_suffix=""
        ),
        payload=PayloadTemplate(
            base="1.2.3.4",
            variants=[
                "1.2.3.4",  # x-forwarded-for
                "1.2.3.4",  # X-Forwarded-For
                "1.2.3.4",  # X-FORWARDED-FOR
            ],
            encoding="none",
        ),
        expected_evidence=Evidence(
            indicators=["Case-sensitive header handling", "Rate limit bypass via case"],
            confidence=ConfidenceLevel.LOW,
        ),
        sensitivity=SensitivityLevel.LOW,
        remediation="Normalize header names to lowercase. Handle headers case-insensitively.",
        references=["https://www.rfc-editor.org/rfc/rfc7230#section-3.2"],
        tags=["rate-limit", "case-sensitivity", "bypass"],
    ),
    TestVector(
        id="rate-limit-bypass-008",
        name="Rate Limit Bypass via Unicode Normalization",
        description="Tests if Unicode variations in parameters bypass rate limiting",
        vuln_type=VulnerabilityType.API_RATE_LIMIT_BYPASS,
        position=Position(
            type=PositionType.QUERY, name="username", value_prefix="", value_suffix=""
        ),
        payload=PayloadTemplate(
            base="admin",
            variants=[
                "admin",
                "аdmin",  # Cyrillic 'а'
                "adm‍in",  # Zero-width joiner
                "ａｄｍｉｎ",  # Fullwidth
            ],
            encoding="none",
        ),
        expected_evidence=Evidence(
            indicators=["Unicode normalization bypass", "Different rate limit counters"],
            confidence=ConfidenceLevel.LOW,
        ),
        sensitivity=SensitivityLevel.MEDIUM,
        remediation="Normalize input using Unicode normalization (NFC/NFKC). Apply rate limits after normalization.",
        references=["https://unicode.org/reports/tr15/"],
        tags=["rate-limit", "unicode", "normalization", "bypass"],
    ),
    TestVector(
        id="rate-limit-bypass-009",
        name="Rate Limit Bypass via Timing Manipulation",
        description="Tests if rate limit windows can be exploited via timing",
        vuln_type=VulnerabilityType.API_RATE_LIMIT_BYPASS,
        position=Position(
            type=PositionType.QUERY, name="delay", value_prefix="", value_suffix="ms"
        ),
        payload=PayloadTemplate(
            base="999", variants=["999", "500", "100"], encoding="none"  # Just under 1 second
        ),
        expected_evidence=Evidence(
            indicators=["Rate limit window edge exploitation", "Timing-based bypass"],
            confidence=ConfidenceLevel.LOW,
        ),
        sensitivity=SensitivityLevel.MEDIUM,
        remediation="Use sliding window rate limiting. Implement burst detection. Use token bucket algorithm.",
        references=["https://en.wikipedia.org/wiki/Token_bucket"],
        tags=["rate-limit", "timing", "bypass", "sliding-window"],
    ),
    TestVector(
        id="rate-limit-bypass-010",
        name="Rate Limit Bypass via Referer Spoofing",
        description="Tests if Referer header affects rate limiting",
        vuln_type=VulnerabilityType.API_RATE_LIMIT_BYPASS,
        position=Position(
            type=PositionType.HEADER, name="Referer", value_prefix="", value_suffix=""
        ),
        payload=PayloadTemplate(
            base="https://trusted.com",
            variants=["https://trusted.com", "https://example.com", "https://api.internal", ""],
            encoding="none",
        ),
        expected_evidence=Evidence(
            indicators=["Referer-based rate limit differentiation", "Bypass via referer spoofing"],
            confidence=ConfidenceLevel.LOW,
        ),
        sensitivity=SensitivityLevel.LOW,
        remediation="Don't use Referer for rate limiting. Client-controlled headers are unreliable.",
        references=["https://cwe.mitre.org/data/definitions/770.html"],
        tags=["rate-limit", "referer", "spoofing", "bypass"],
    ),
]

# Total vectors: 10
