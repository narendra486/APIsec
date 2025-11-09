"""
HTTP Security Headers Validation Vectors
CSP, HSTS, X-Frame-Options testing
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

SECURITY_HEADER_VECTORS = [
    TestVector(
        id="header-csp-001",
        name="Missing Content-Security-Policy Header",
        description="Tests if CSP header is missing allowing XSS attacks",
        vuln_type=VulnerabilityType.SECURITY_HEADER_MISSING,
        position=Position(
            type=PositionType.HEADER,
            name="Content-Security-Policy",
            value_prefix="",
            value_suffix="",
        ),
        payload=PayloadTemplate(base="", variants=[], encoding="none"),
        expected_evidence=Evidence(
            indicators=["CSP header absent", "Inline scripts allowed"],
            confidence=ConfidenceLevel.MEDIUM,
        ),
        sensitivity=SensitivityLevel.MEDIUM,
        remediation="Implement strict Content-Security-Policy header.",
        references=["https://owasp.org/www-project-secure-headers/"],
        tags=["security-headers", "csp", "xss-protection"],
    ),
    TestVector(
        id="header-hsts-001",
        name="Missing Strict-Transport-Security",
        description="Tests for absence or weak HSTS header",
        vuln_type=VulnerabilityType.SECURITY_HEADER_MISSING,
        position=Position(
            type=PositionType.HEADER,
            name="Strict-Transport-Security",
            value_prefix="",
            value_suffix="",
        ),
        payload=PayloadTemplate(
            base="", variants=["", "max-age=0", "max-age=300"], encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["No HSTS header", "Weak max-age", "Protocol downgrade possible"],
            confidence=ConfidenceLevel.HIGH,
        ),
        sensitivity=SensitivityLevel.LOW,
        remediation="Set HSTS with max-age >= 31536000; includeSubDomains; preload",
        references=[
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"
        ],
        tags=["security-headers", "hsts", "https"],
    ),
    TestVector(
        id="header-frame-001",
        name="Missing X-Frame-Options",
        description="Tests for absence of clickjacking protection",
        vuln_type=VulnerabilityType.SECURITY_HEADER_MISSING,
        position=Position(
            type=PositionType.HEADER, name="X-Frame-Options", value_prefix="", value_suffix=""
        ),
        payload=PayloadTemplate(base="", variants=["", "ALLOWALL"], encoding="none"),
        expected_evidence=Evidence(
            indicators=["No X-Frame-Options", "Framing allowed", "Clickjacking possible"],
            confidence=ConfidenceLevel.MEDIUM,
        ),
        sensitivity=SensitivityLevel.LOW,
        remediation="Set X-Frame-Options: DENY or SAMEORIGIN. Or use CSP frame-ancestors.",
        references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options"],
        tags=["security-headers", "clickjacking", "x-frame-options"],
    ),
    TestVector(
        id="header-nosniff-001",
        name="Missing X-Content-Type-Options",
        description="Tests for absence of MIME sniffing prevention",
        vuln_type=VulnerabilityType.SECURITY_HEADER_MISSING,
        position=Position(
            type=PositionType.HEADER,
            name="X-Content-Type-Options",
            value_prefix="",
            value_suffix="",
        ),
        payload=PayloadTemplate(base="", variants=[""], encoding="none"),
        expected_evidence=Evidence(
            indicators=[
                "No X-Content-Type-Options",
                "MIME sniffing enabled",
                "Content type confusion",
            ],
            confidence=ConfidenceLevel.MEDIUM,
        ),
        sensitivity=SensitivityLevel.LOW,
        remediation="Set X-Content-Type-Options: nosniff on all responses.",
        references=[
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"
        ],
        tags=["security-headers", "mime-sniffing", "content-type"],
    ),
    TestVector(
        id="header-referrer-001",
        name="Missing Referrer-Policy",
        description="Tests for absence of referrer policy header",
        vuln_type=VulnerabilityType.SECURITY_HEADER_MISSING,
        position=Position(
            type=PositionType.HEADER, name="Referrer-Policy", value_prefix="", value_suffix=""
        ),
        payload=PayloadTemplate(base="", variants=["", "unsafe-url"], encoding="none"),
        expected_evidence=Evidence(
            indicators=["No Referrer-Policy", "Full URL in referrer", "Data leakage"],
            confidence=ConfidenceLevel.LOW,
        ),
        sensitivity=SensitivityLevel.LOW,
        remediation="Set Referrer-Policy: no-referrer or strict-origin-when-cross-origin.",
        references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy"],
        tags=["security-headers", "referrer-policy", "privacy"],
    ),
    TestVector(
        id="header-permissions-001",
        name="Missing Permissions-Policy",
        description="Tests for absence of Permissions-Policy (formerly Feature-Policy)",
        vuln_type=VulnerabilityType.SECURITY_HEADER_MISSING,
        position=Position(
            type=PositionType.HEADER, name="Permissions-Policy", value_prefix="", value_suffix=""
        ),
        payload=PayloadTemplate(base="", variants=[""], encoding="none"),
        expected_evidence=Evidence(
            indicators=["No Permissions-Policy", "All features enabled", "Privacy risks"],
            confidence=ConfidenceLevel.LOW,
        ),
        sensitivity=SensitivityLevel.LOW,
        remediation="Set Permissions-Policy to restrict sensitive features (camera, microphone, geolocation).",
        references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy"],
        tags=["security-headers", "permissions-policy", "feature-policy"],
    ),
    TestVector(
        id="header-corp-001",
        name="Missing Cross-Origin-Resource-Policy",
        description="Tests for absence of CORP header",
        vuln_type=VulnerabilityType.SECURITY_HEADER_MISSING,
        position=Position(
            type=PositionType.HEADER,
            name="Cross-Origin-Resource-Policy",
            value_prefix="",
            value_suffix="",
        ),
        payload=PayloadTemplate(base="", variants=[""], encoding="none"),
        expected_evidence=Evidence(
            indicators=["No CORP header", "Cross-origin reads possible", "Spectre attack risk"],
            confidence=ConfidenceLevel.LOW,
        ),
        sensitivity=SensitivityLevel.LOW,
        remediation="Set Cross-Origin-Resource-Policy: same-origin or same-site.",
        references=[
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Resource-Policy"
        ],
        tags=["security-headers", "corp", "cross-origin"],
    ),
    TestVector(
        id="header-coep-001",
        name="Missing Cross-Origin-Embedder-Policy",
        description="Tests for absence of COEP/COOP headers",
        vuln_type=VulnerabilityType.SECURITY_HEADER_MISSING,
        position=Position(
            type=PositionType.HEADER,
            name="Cross-Origin-Embedder-Policy",
            value_prefix="",
            value_suffix="",
        ),
        payload=PayloadTemplate(base="", variants=[""], encoding="none"),
        expected_evidence=Evidence(
            indicators=["No COEP header", "No COOP header", "Process isolation missing"],
            confidence=ConfidenceLevel.LOW,
        ),
        sensitivity=SensitivityLevel.LOW,
        remediation="Set COEP: require-corp and COOP: same-origin for isolation.",
        references=[
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Embedder-Policy"
        ],
        tags=["security-headers", "coep", "coop", "isolation"],
    ),
    TestVector(
        id="header-expect-ct-001",
        name="Missing Expect-CT Header",
        description="Tests for absence of Certificate Transparency enforcement",
        vuln_type=VulnerabilityType.SECURITY_HEADER_MISSING,
        position=Position(
            type=PositionType.HEADER, name="Expect-CT", value_prefix="", value_suffix=""
        ),
        payload=PayloadTemplate(base="", variants=[""], encoding="none"),
        expected_evidence=Evidence(
            indicators=["No Expect-CT header", "Certificate transparency not enforced"],
            confidence=ConfidenceLevel.LOW,
        ),
        sensitivity=SensitivityLevel.LOW,
        remediation="Set Expect-CT: max-age=86400, enforce to require CT compliance.",
        references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Expect-CT"],
        tags=["security-headers", "expect-ct", "certificate-transparency"],
    ),
]

# Total vectors: 9
