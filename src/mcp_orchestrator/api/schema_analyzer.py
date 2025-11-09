"""
API Schema Security Analysis Vectors
OpenAPI/Swagger security validation
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

SCHEMA_ANALYZER_VECTORS = [
    TestVector(
        id="schema-exposure-001",
        name="OpenAPI Schema Exposure",
        description="Tests if API schema is publicly accessible",
        vuln_type=VulnerabilityType.API_SCHEMA_EXPOSURE,
        position=Position(type=PositionType.PATH, name="path", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="/swagger.json",
            variants=[
                "/swagger.json",
                "/openapi.json",
                "/api-docs",
                "/v2/api-docs",
                "/swagger-ui.html",
                "/api/swagger.json",
            ],
            encoding="none",
        ),
        expected_evidence=Evidence(
            indicators=["Schema document accessible", "API structure exposed"],
            confidence=ConfidenceLevel.MEDIUM,
        ),
        sensitivity=SensitivityLevel.MEDIUM,
        remediation="Restrict schema access to authenticated users. Remove from production.",
        references=["https://cwe.mitre.org/data/definitions/538.html"],
        tags=["api", "schema", "openapi", "information-disclosure"],
    ),
    TestVector(
        id="schema-security-001",
        name="OpenAPI Security Scheme Validation",
        description="Tests if API schema defines proper security schemes",
        vuln_type=VulnerabilityType.API_MISCONFIGURATION,
        position=Position(
            type=PositionType.HEADER, name="Accept", value_prefix="", value_suffix=""
        ),
        payload=PayloadTemplate(
            base="application/json", variants=["application/json"], encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=[
                "Missing security schemes",
                "No authentication defined",
                "Empty securitySchemes",
            ],
            confidence=ConfidenceLevel.MEDIUM,
        ),
        sensitivity=SensitivityLevel.HIGH,
        remediation="Define security schemes in OpenAPI spec. Enforce authentication on all endpoints.",
        references=["https://swagger.io/specification/#security-scheme-object"],
        tags=["api", "schema", "security-scheme", "authentication"],
    ),
    TestVector(
        id="schema-endpoint-001",
        name="Hidden Endpoint Discovery",
        description="Tests for undocumented endpoints not in API schema",
        vuln_type=VulnerabilityType.API_ENDPOINT_EXPOSURE,
        position=Position(type=PositionType.PATH, name="path", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="/api/internal",
            variants=[
                "/api/admin",
                "/api/debug",
                "/api/test",
                "/api/v1/internal",
                "/api/private",
                "/__api",
                "/api/hidden",
            ],
            encoding="none",
        ),
        expected_evidence=Evidence(
            indicators=["Endpoint exists but not in schema", "Undocumented API access"],
            confidence=ConfidenceLevel.MEDIUM,
        ),
        sensitivity=SensitivityLevel.HIGH,
        remediation="Document all endpoints. Disable debug/internal endpoints in production. Implement allowlist.",
        references=[
            "https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/"
        ],
        tags=["api", "hidden-endpoint", "discovery", "documentation"],
    ),
    TestVector(
        id="schema-param-001",
        name="Parameter Validation Check",
        description="Tests if API validates parameters according to schema",
        vuln_type=VulnerabilityType.API_PARAMETER_POLLUTION,
        position=Position(type=PositionType.QUERY, name="id", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="999999999999999999",
            variants=["-1", "0", "999999999999", "'OR'1'='1", "null", "undefined", "[]"],
            encoding="none",
        ),
        expected_evidence=Evidence(
            indicators=[
                "Invalid parameter accepted",
                "Type validation missing",
                "Range validation bypass",
            ],
            confidence=ConfidenceLevel.MEDIUM,
        ),
        sensitivity=SensitivityLevel.MEDIUM,
        remediation="Implement strict parameter validation. Use schema validation middleware. Enforce type constraints.",
        references=[
            "https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/"
        ],
        tags=["api", "parameter-validation", "schema-validation"],
    ),
    TestVector(
        id="schema-response-001",
        name="Response Schema Validation",
        description="Tests if API responses leak data not defined in schema",
        vuln_type=VulnerabilityType.API_EXCESSIVE_DATA_EXPOSURE,
        position=Position(
            type=PositionType.HEADER, name="X-Debug", value_prefix="", value_suffix=""
        ),
        payload=PayloadTemplate(base="true", variants=["true", "1", "verbose"], encoding="none"),
        expected_evidence=Evidence(
            indicators=["Extra fields in response", "Sensitive data exposed", "Schema mismatch"],
            confidence=ConfidenceLevel.MEDIUM,
        ),
        sensitivity=SensitivityLevel.HIGH,
        remediation="Implement response filtering. Validate responses against schema. Remove sensitive fields.",
        references=[
            "https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/"
        ],
        tags=["api", "response-validation", "data-exposure"],
    ),
    TestVector(
        id="schema-deprecated-001",
        name="Deprecated API Version Access",
        description="Tests if deprecated API versions are still accessible",
        vuln_type=VulnerabilityType.API_VERSIONING_ISSUE,
        position=Position(
            type=PositionType.PATH, name="version", value_prefix="/api/", value_suffix="/users"
        ),
        payload=PayloadTemplate(
            base="v0",
            variants=["v0", "v1", "v1.0", "beta", "alpha", "old", "deprecated"],
            encoding="none",
        ),
        expected_evidence=Evidence(
            indicators=[
                "Deprecated version accessible",
                "Old vulnerabilities exploitable",
                "Version marked deprecated in schema",
            ],
            confidence=ConfidenceLevel.MEDIUM,
        ),
        sensitivity=SensitivityLevel.MEDIUM,
        remediation="Sunset old API versions. Implement version deprecation policy. Redirect to current version.",
        references=[
            "https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/"
        ],
        tags=["api", "versioning", "deprecated", "lifecycle"],
    ),
    TestVector(
        id="schema-ratelimit-001",
        name="Rate Limit Configuration Check",
        description="Tests if rate limiting is properly configured in schema",
        vuln_type=VulnerabilityType.API_RATE_LIMIT_BYPASS,
        position=Position(
            type=PositionType.HEADER, name="X-Request-Count", value_prefix="", value_suffix=""
        ),
        payload=PayloadTemplate(base="1000", variants=["1000", "10000"], encoding="none"),
        expected_evidence=Evidence(
            indicators=[
                "No rate limit headers",
                "Missing X-RateLimit-* headers",
                "Unlimited requests allowed",
            ],
            confidence=ConfidenceLevel.LOW,
        ),
        sensitivity=SensitivityLevel.MEDIUM,
        remediation="Implement rate limiting. Add rate limit headers. Document limits in API schema.",
        references=[
            "https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/"
        ],
        tags=["api", "rate-limiting", "dos-protection"],
    ),
    TestVector(
        id="schema-cors-001",
        name="CORS Policy Validation",
        description="Tests if CORS policy is properly defined and restrictive",
        vuln_type=VulnerabilityType.API_CORS_MISCONFIGURATION,
        position=Position(
            type=PositionType.HEADER, name="Origin", value_prefix="", value_suffix=""
        ),
        payload=PayloadTemplate(
            base="https://evil.com",
            variants=["https://evil.com", "null", "http://localhost", "https://attacker.com"],
            encoding="none",
        ),
        expected_evidence=Evidence(
            indicators=[
                "Access-Control-Allow-Origin: *",
                "Reflected origin in CORS header",
                "Credentials allowed with wildcard",
            ],
            confidence=ConfidenceLevel.HIGH,
        ),
        sensitivity=SensitivityLevel.HIGH,
        remediation="Use specific origin allowlist. Avoid wildcard CORS. Don't allow credentials with wildcard.",
        references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS"],
        tags=["api", "cors", "misconfiguration", "cross-origin"],
    ),
]

# Total vectors: 8
