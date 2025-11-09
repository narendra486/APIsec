"""
REST API Security Testing Vectors
HTTP verb tampering, content-type confusion
"""

from ..models import (
    TestVector, VulnerabilityType, TestVectorPosition as Position, PositionType,
    TestVectorPayload as PayloadTemplate, TestVectorEvidence as Evidence, 
    ConfidenceLevel, SensitivityLevel
)

REST_SECURITY_VECTORS = [
    TestVector(
        id="rest-verb-tamper-001",
        name="REST API Verb Tampering",
        description="Tests if API accepts unexpected HTTP methods",
        vuln_type=VulnerabilityType.REST_VERB_TAMPERING,
        position=Position(type=PositionType.HEADER, name="method", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="HEAD",
            variants=["HEAD", "OPTIONS", "TRACE", "PUT", "DELETE"],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["Unexpected method accepted", "Security bypass"],
            confidence=ConfidenceLevel.MEDIUM
        ),
        sensitivity=SensitivityLevel.MEDIUM,
        remediation="Whitelist allowed HTTP methods per endpoint.",
        references=["https://cwe.mitre.org/data/definitions/650.html"],
        tags=["rest", "http-method", "verb-tampering"]
    ),
    
    TestVector(
        id="rest-head-001",
        name="REST HEAD Method State Change",
        description="Tests if HEAD method causes unintended state changes",
        vuln_type=VulnerabilityType.REST_VERB_TAMPERING,
        position=Position(type=PositionType.HEADER, name="X-HTTP-Method", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="HEAD",
            variants=["HEAD"],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["State modified by HEAD request", "Side effects from safe method"],
            confidence=ConfidenceLevel.HIGH
        ),
        sensitivity=SensitivityLevel.HIGH,
        remediation="Ensure HEAD requests are idempotent and safe. No state changes allowed.",
        references=["https://www.rfc-editor.org/rfc/rfc7231#section-4.3.2"],
        tags=["rest", "head-method", "safe-methods"]
    ),
    
    TestVector(
        id="rest-options-001",
        name="REST OPTIONS Information Disclosure",
        description="Tests if OPTIONS method reveals sensitive information",
        vuln_type=VulnerabilityType.REST_INFO_DISCLOSURE,
        position=Position(type=PositionType.HEADER, name="X-HTTP-Method", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="OPTIONS",
            variants=["OPTIONS"],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["Sensitive headers exposed", "Internal methods revealed", "Authentication details disclosed"],
            confidence=ConfidenceLevel.MEDIUM
        ),
        sensitivity=SensitivityLevel.MEDIUM,
        remediation="Limit OPTIONS response information. Remove sensitive headers. Require authentication.",
        references=["https://www.rfc-editor.org/rfc/rfc7231#section-4.3.7"],
        tags=["rest", "options-method", "information-disclosure"]
    ),
    
    TestVector(
        id="rest-trace-001",
        name="REST TRACE/TRACK XST Attack",
        description="Tests for Cross-Site Tracing via TRACE/TRACK methods",
        vuln_type=VulnerabilityType.REST_XST,
        position=Position(type=PositionType.HEADER, name="X-HTTP-Method", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="TRACE",
            variants=[
                "TRACE",
                "TRACK"
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["TRACE method enabled", "Request echoed in response", "Cookies reflected"],
            confidence=ConfidenceLevel.HIGH
        ),
        sensitivity=SensitivityLevel.HIGH,
        remediation="Disable TRACE and TRACK methods. Configure web server to reject these methods.",
        references=["https://owasp.org/www-community/attacks/Cross_Site_Tracing"],
        tags=["rest", "trace-method", "xst", "cross-site-tracing"]
    ),
    
    TestVector(
        id="rest-contenttype-001",
        name="REST Content-Type Confusion",
        description="Tests if API properly validates Content-Type header",
        vuln_type=VulnerabilityType.REST_CONTENT_TYPE_CONFUSION,
        position=Position(type=PositionType.HEADER, name="Content-Type", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="text/plain",
            variants=[
                "text/plain",
                "application/x-www-form-urlencoded",
                "multipart/form-data",
                "text/html",
                "application/xml"
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["Wrong content type accepted", "Parser confusion", "Security bypass"],
            confidence=ConfidenceLevel.MEDIUM
        ),
        sensitivity=SensitivityLevel.MEDIUM,
        remediation="Strictly validate Content-Type. Reject unexpected content types. Use allowlist.",
        references=["https://cwe.mitre.org/data/definitions/436.html"],
        tags=["rest", "content-type", "confusion", "validation"]
    ),
    
    TestVector(
        id="rest-accept-001",
        name="REST Accept Header Manipulation",
        description="Tests if Accept header manipulation exposes different data formats",
        vuln_type=VulnerabilityType.REST_HEADER_INJECTION,
        position=Position(type=PositionType.HEADER, name="Accept", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="application/xml",
            variants=[
                "application/xml",
                "text/html",
                "application/json",
                "*/*",
                "text/plain"
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["Sensitive data in XML format", "HTML with debug info", "Extra fields in different format"],
            confidence=ConfidenceLevel.MEDIUM
        ),
        sensitivity=SensitivityLevel.MEDIUM,
        remediation="Consistent data filtering across all formats. Validate Accept header values.",
        references=["https://www.rfc-editor.org/rfc/rfc7231#section-5.3.2"],
        tags=["rest", "accept-header", "content-negotiation"]
    ),
    
    TestVector(
        id="rest-charset-001",
        name="REST Charset Exploitation",
        description="Tests if charset manipulation bypasses input validation",
        vuln_type=VulnerabilityType.REST_CHARSET_CONFUSION,
        position=Position(type=PositionType.HEADER, name="Content-Type", value_prefix="application/json; charset=", value_suffix=""),
        payload=PayloadTemplate(
            base="utf-7",
            variants=[
                "utf-7",
                "utf-16",
                "utf-32",
                "iso-8859-1",
                "windows-1252"
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["Charset bypass", "Encoding confusion", "Validation bypass"],
            confidence=ConfidenceLevel.MEDIUM
        ),
        sensitivity=SensitivityLevel.MEDIUM,
        remediation="Enforce UTF-8 charset. Reject non-standard charsets. Normalize input.",
        references=["https://cwe.mitre.org/data/definitions/838.html"],
        tags=["rest", "charset", "encoding", "bypass"]
    ),
    
    TestVector(
        id="rest-put-001",
        name="REST PUT Method File Upload",
        description="Tests if PUT method allows arbitrary file upload",
        vuln_type=VulnerabilityType.REST_VERB_TAMPERING,
        position=Position(type=PositionType.PATH, name="path", value_prefix="/uploads/", value_suffix=""),
        payload=PayloadTemplate(
            base="shell.php",
            variants=[
                "shell.php",
                "../shell.php",
                "shell.jsp",
                "backdoor.aspx"
            ],
            encoding="url"
        ),
        expected_evidence=Evidence(
            indicators=["File uploaded via PUT", "Arbitrary file write", "Path traversal"],
            confidence=ConfidenceLevel.CRITICAL
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Disable PUT on file paths. Implement strict upload validation. Use POST for uploads.",
        references=["https://cwe.mitre.org/data/definitions/434.html"],
        tags=["rest", "put-method", "file-upload", "rce"]
    ),
    
    TestVector(
        id="rest-delete-001",
        name="REST DELETE Method Resource Removal",
        description="Tests if DELETE method lacks proper authorization",
        vuln_type=VulnerabilityType.REST_AUTHORIZATION_BYPASS,
        position=Position(type=PositionType.PATH, name="resource_id", value_prefix="/api/users/", value_suffix=""),
        payload=PayloadTemplate(
            base="1",
            variants=[
                "1",
                "admin",
                "999",
                "../users"
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["Unauthorized deletion", "Resource removed", "IDOR via DELETE"],
            confidence=ConfidenceLevel.CRITICAL
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Implement authorization checks on DELETE. Validate resource ownership. Use soft deletes.",
        references=["https://cwe.mitre.org/data/definitions/639.html"],
        tags=["rest", "delete-method", "authorization", "idor"]
    ),
    
    TestVector(
        id="rest-patch-001",
        name="REST PATCH Method Mass Assignment",
        description="Tests if PATCH allows modifying protected fields",
        vuln_type=VulnerabilityType.REST_MASS_ASSIGNMENT,
        position=Position(type=PositionType.BODY_JSON, name="field", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base='{"role":"admin"}',
            variants=[
                '{"role":"admin"}',
                '{"is_admin":true}',
                '{"permissions":["*"]}',
                '{"balance":999999}'
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["Protected field modified", "Privilege escalation", "Mass assignment vulnerability"],
            confidence=ConfidenceLevel.CRITICAL
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Use field allowlists for PATCH. Reject protected field modifications. Validate all inputs.",
        references=["https://cwe.mitre.org/data/definitions/915.html"],
        tags=["rest", "patch-method", "mass-assignment", "privilege-escalation"]
    ),
    
    TestVector(
        id="rest-header-injection-001",
        name="REST Custom Header Injection",
        description="Tests if custom headers can inject values or bypass security",
        vuln_type=VulnerabilityType.REST_HEADER_INJECTION,
        position=Position(type=PositionType.HEADER, name="X-Custom-Admin", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="true",
            variants=[
                "true",
                "1",
                "yes",
                "admin"
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["Custom header processed", "Authorization bypass", "Privilege escalation"],
            confidence=ConfidenceLevel.MEDIUM
        ),
        sensitivity=SensitivityLevel.HIGH,
        remediation="Ignore untrusted custom headers. Validate all header inputs. Use header allowlist.",
        references=["https://cwe.mitre.org/data/definitions/113.html"],
        tags=["rest", "header-injection", "custom-headers"]
    ),
    
    TestVector(
        id="rest-version-001",
        name="REST HTTP Version Downgrade",
        description="Tests if downgrading HTTP version bypasses security controls",
        vuln_type=VulnerabilityType.REST_PROTOCOL_DOWNGRADE,
        position=Position(type=PositionType.HEADER, name="protocol_version", value_prefix="HTTP/", value_suffix=""),
        payload=PayloadTemplate(
            base="1.0",
            variants=[
                "1.0",
                "0.9"
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["HTTP/1.0 accepted", "Security features disabled", "Protocol downgrade"],
            confidence=ConfidenceLevel.LOW
        ),
        sensitivity=SensitivityLevel.MEDIUM,
        remediation="Enforce minimum HTTP version. Require HTTP/1.1 or HTTP/2. Reject legacy versions.",
        references=["https://www.rfc-editor.org/rfc/rfc7230"],
        tags=["rest", "http-version", "downgrade"]
    ),
    
    TestVector(
        id="rest-override-001",
        name="HTTP Method Override Header Abuse",
        description="Tests for method override header manipulation (X-HTTP-Method-Override)",
        vuln_type=VulnerabilityType.REST_VERB_TAMPERING,
        position=Position(type=PositionType.HEADER, name="X-HTTP-Method-Override", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="DELETE",
            variants=["DELETE", "PUT", "PATCH", "ADMIN"],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["Method override accepted", "Authorization bypass", "Unintended action"],
            confidence=ConfidenceLevel.HIGH
        ),
        sensitivity=SensitivityLevel.MEDIUM,
        remediation="Validate method override headers. Enforce authorization on overridden methods.",
        references=["https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/"],
        tags=["rest", "method-override", "verb-tampering"]
    ),
    
    TestVector(
        id="rest-jsonp-001",
        name="JSONP Callback Injection",
        description="Tests for JSONP callback manipulation allowing XSS",
        vuln_type=VulnerabilityType.REST_INFO_DISCLOSURE,
        position=Position(type=PositionType.QUERY, name="callback", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="alert(1);//",
            variants=["alert(1);//", "<script>alert(1)</script>", "evilCallback"],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["Callback reflected", "XSS via JSONP", "Unvalidated callback"],
            confidence=ConfidenceLevel.HIGH
        ),
        sensitivity=SensitivityLevel.MEDIUM,
        remediation="Validate callback names against allowlist. Use CORS instead of JSONP.",
        references=["https://owasp.org/www-community/vulnerabilities/JSONP_Injection"],
        tags=["rest", "jsonp", "xss"]
    ),
]

# Total vectors: 14
