"""
OAuth 2.0 / OpenID Connect Security Testing Vectors
Based on competitive analysis of existing AI security tools
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

OAUTH_TEST_VECTORS = [
    # ============================================================================
    # REDIRECT_URI VALIDATION BYPASS
    # ============================================================================
    TestVector(
        id="oauth-redirect-uri-001",
        name="Open Redirect via redirect_uri - Subdomain Takeover Pattern",
        description="Tests if redirect_uri accepts attacker-controlled subdomains",
        vuln_type=VulnerabilityType.OAUTH_REDIRECT_URI_BYPASS,
        position=Position(
            type=PositionType.QUERY,
            name="redirect_uri",
            value_prefix="https://",
            value_suffix="/callback",
        ),
        payload=PayloadTemplate(
            base="https://evil.com/callback",
            variants=[
                "https://evil.com@target.com/callback",
                "https://target.com.evil.com/callback",
                "https://target.com%2F@evil.com/callback",
                "https://target.com\\@evil.com/callback",
                "https://target.com%00@evil.com/callback",
                "https://evil.com#@target.com/callback",
                "https://evil.com?@target.com/callback",
            ],
            encoding="url",
        ),
        expected_evidence=Evidence(
            indicators=[
                "Authorization code delivered to attacker domain",
                "302/301 redirect to evil.com",
                "Access token sent to attacker-controlled callback",
            ],
            false_positive_indicators=[
                "Redirect blocked by WAF",
                "Authorization code not present in attacker logs",
            ],
            confidence=ConfidenceLevel.HIGH,
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Validate redirect_uri against exact whitelist. Use strict string matching, not contains/startsWith.",
        references=[
            "https://oauth.net/2/redirect-uri-validation/",
            "https://cwe.mitre.org/data/definitions/601.html",
            "https://portswigger.net/web-security/oauth",
        ],
        tags=["oauth2", "openid-connect", "redirect-uri", "open-redirect"],
    ),
    TestVector(
        id="oauth-redirect-uri-002",
        name="Path Traversal in redirect_uri",
        description="Tests if redirect_uri validation can be bypassed using path traversal",
        vuln_type=VulnerabilityType.OAUTH_REDIRECT_URI_BYPASS,
        position=Position(
            type=PositionType.QUERY,
            name="redirect_uri",
            value_prefix="https://target.com",
            value_suffix="",
        ),
        payload=PayloadTemplate(
            base="https://target.com/callback/../../../evil.com",
            variants=[
                "https://target.com/callback/..%2F..%2F..%2Fevil.com",
                "https://target.com/callback/....//....//evil.com",
                "https://target.com/callback/.%2e/.%2e/.%2e/evil.com",
                "https://target.com/callback;@evil.com",
                "https://target.com:80@evil.com/callback",
                "https://target.com:443@evil.com/callback",
            ],
            encoding="double-url",
        ),
        expected_evidence=Evidence(
            indicators=[
                "Path traversal resolves to attacker domain",
                "Authorization server accepts malformed URI",
                "Callback executed on evil.com",
            ],
            false_positive_indicators=["URI normalized correctly", "Path traversal sanitized"],
            confidence=ConfidenceLevel.HIGH,
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Parse and normalize URIs before validation. Reject URIs with path traversal sequences.",
        references=[
            "https://tools.ietf.org/html/rfc6749#section-3.1.2",
            "https://cwe.mitre.org/data/definitions/22.html",
        ],
        tags=["oauth2", "redirect-uri", "path-traversal"],
    ),
    TestVector(
        id="oauth-redirect-uri-003",
        name="Open Redirect via Missing redirect_uri Validation",
        description="Tests if authorization server validates redirect_uri at all",
        vuln_type=VulnerabilityType.OAUTH_REDIRECT_URI_BYPASS,
        position=Position(
            type=PositionType.QUERY, name="redirect_uri", value_prefix="", value_suffix=""
        ),
        payload=PayloadTemplate(
            base="https://arbitrary-attacker-site.com/steal",
            variants=[
                "http://localhost:8080/steal",
                "http://127.0.0.1/steal",
                "http://[::1]/steal",
                "https://192.168.1.1/steal",
                "data:text/html,<script>alert(document.domain)</script>",
                "javascript:alert(document.domain)",
                "file:///etc/passwd",
            ],
            encoding="url",
        ),
        expected_evidence=Evidence(
            indicators=[
                "Arbitrary redirect_uri accepted",
                "No validation error returned",
                "Authorization code sent to unregistered callback",
            ],
            false_positive_indicators=["Invalid redirect_uri error", "Redirect blocked"],
            confidence=ConfidenceLevel.CRITICAL,
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Enforce strict whitelist validation. Reject any redirect_uri not pre-registered for the client.",
        references=[
            "https://tools.ietf.org/html/rfc6749#section-10.6",
            "https://cwe.mitre.org/data/definitions/601.html",
        ],
        tags=["oauth2", "redirect-uri", "validation-bypass"],
    ),
    # ============================================================================
    # STATE PARAMETER CSRF
    # ============================================================================
    TestVector(
        id="oauth-state-csrf-001",
        name="CSRF via Missing State Parameter",
        description="Tests if OAuth flow can be completed without state parameter",
        vuln_type=VulnerabilityType.OAUTH_STATE_CSRF,
        position=Position(type=PositionType.QUERY, name="state", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="",  # Empty/missing state
            variants=["", " ", "null", "undefined"],  # Empty string (omit parameter)  # Whitespace
            encoding="none",
        ),
        expected_evidence=Evidence(
            indicators=[
                "Authorization flow completes without state",
                "No state validation error",
                "Callback accepts missing state parameter",
            ],
            false_positive_indicators=["State required error", "Authorization flow blocked"],
            confidence=ConfidenceLevel.HIGH,
        ),
        sensitivity=SensitivityLevel.HIGH,
        remediation="Always require state parameter. Generate cryptographically random value. Validate on callback.",
        references=[
            "https://tools.ietf.org/html/rfc6749#section-10.12",
            "https://cwe.mitre.org/data/definitions/352.html",
        ],
        tags=["oauth2", "csrf", "state-parameter"],
    ),
    TestVector(
        id="oauth-state-csrf-002",
        name="CSRF via Predictable State Parameter",
        description="Tests if state parameter uses weak/predictable values",
        vuln_type=VulnerabilityType.OAUTH_STATE_CSRF,
        position=Position(type=PositionType.QUERY, name="state", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="123456",
            variants=[
                "1",
                "12345",
                "static_value",
                "test",
                "abc123",
                "00000000-0000-0000-0000-000000000000",
                "12345678-1234-1234-1234-123456789012",
            ],
            encoding="none",
        ),
        expected_evidence=Evidence(
            indicators=[
                "Sequential state values accepted",
                "Same state reused across sessions",
                "Predictable state generation pattern detected",
            ],
            false_positive_indicators=["Random state enforced", "State validation strict"],
            confidence=ConfidenceLevel.MEDIUM,
        ),
        sensitivity=SensitivityLevel.HIGH,
        remediation="Generate state using cryptographically secure random number generator (CSPRNG). Minimum 128 bits entropy.",
        references=[
            "https://tools.ietf.org/html/rfc6749#section-10.12",
            "https://datatracker.ietf.org/doc/html/rfc6749#section-10.10",
        ],
        tags=["oauth2", "csrf", "weak-randomness"],
    ),
    # ============================================================================
    # AUTHORIZATION CODE REUSE
    # ============================================================================
    TestVector(
        id="oauth-code-reuse-001",
        name="Authorization Code Reuse Attack",
        description="Tests if authorization code can be exchanged multiple times",
        vuln_type=VulnerabilityType.OAUTH_CODE_REUSE,
        position=Position(
            type=PositionType.BODY_JSON, name="code", value_prefix="", value_suffix=""
        ),
        payload=PayloadTemplate(
            base="<INTERCEPTED_AUTH_CODE>",  # Placeholder for captured code
            variants=["<SAME_CODE_SECOND_REQUEST>", "<SAME_CODE_THIRD_REQUEST>"],
            encoding="none",
        ),
        expected_evidence=Evidence(
            indicators=[
                "Same authorization code accepted multiple times",
                "Multiple access tokens generated from single code",
                "No code invalidation after first use",
            ],
            false_positive_indicators=["Code already used error", "Invalid authorization code"],
            confidence=ConfidenceLevel.CRITICAL,
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Authorization codes MUST be single-use. Invalidate immediately after first redemption. Revoke issued tokens if reuse detected.",
        references=[
            "https://tools.ietf.org/html/rfc6749#section-10.5",
            "https://cwe.mitre.org/data/definitions/294.html",
            "https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2",
        ],
        tags=["oauth2", "authorization-code", "replay-attack"],
    ),
    TestVector(
        id="oauth-code-reuse-002",
        name="Authorization Code Leakage via Referer Header",
        description="Tests if authorization code leaks through Referer header",
        vuln_type=VulnerabilityType.OAUTH_CODE_REUSE,
        position=Position(type=PositionType.QUERY, name="code", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="<AUTH_CODE>",
            variants=[
                # Check if code appears in logs, analytics, third-party scripts
            ],
            encoding="none",
        ),
        expected_evidence=Evidence(
            indicators=[
                "Authorization code visible in Referer header",
                "Code logged by analytics/tracking scripts",
                "Code transmitted to third-party domains",
            ],
            false_positive_indicators=[
                "Referer-Policy: no-referrer enforced",
                "Code transmitted via POST only",
            ],
            confidence=ConfidenceLevel.HIGH,
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Use POST for callback. Set Referrer-Policy: no-referrer. Use PKCE. Short-lived codes (<60s).",
        references=[
            "https://tools.ietf.org/html/rfc6749#section-10.5",
            "https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics",
        ],
        tags=["oauth2", "authorization-code", "leakage"],
    ),
    # ============================================================================
    # PKCE BYPASS
    # ============================================================================
    TestVector(
        id="oauth-pkce-bypass-001",
        name="PKCE Not Enforced for Public Clients",
        description="Tests if PKCE is optional for public clients (native/SPA apps)",
        vuln_type=VulnerabilityType.OAUTH_PKCE_BYPASS,
        position=Position(
            type=PositionType.QUERY, name="code_challenge", value_prefix="", value_suffix=""
        ),
        payload=PayloadTemplate(
            base="",  # Omit code_challenge
            variants=[
                "",  # Empty challenge (no PKCE parameters)
            ],
            encoding="none",
        ),
        expected_evidence=Evidence(
            indicators=[
                "Authorization succeeds without PKCE",
                "code_challenge not required",
                "Public client bypasses PKCE enforcement",
            ],
            false_positive_indicators=["PKCE required error", "Missing code_challenge error"],
            confidence=ConfidenceLevel.HIGH,
        ),
        sensitivity=SensitivityLevel.HIGH,
        remediation="Enforce PKCE for ALL public clients. Reject authorization requests without code_challenge.",
        references=[
            "https://tools.ietf.org/html/rfc7636",
            "https://oauth.net/2/pkce/",
            "https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics#section-2.1.1",
        ],
        tags=["oauth2", "pkce", "public-client"],
    ),
    TestVector(
        id="oauth-pkce-bypass-002",
        name="PKCE Downgrade to Plain Method",
        description="Tests if code_challenge_method can be downgraded from S256 to plain",
        vuln_type=VulnerabilityType.OAUTH_PKCE_BYPASS,
        position=Position(
            type=PositionType.QUERY, name="code_challenge_method", value_prefix="", value_suffix=""
        ),
        payload=PayloadTemplate(
            base="plain",
            variants=["plain", "PLAIN", "Plain", "", "none"],  # Empty (defaults to plain)
            encoding="none",
        ),
        expected_evidence=Evidence(
            indicators=[
                "Plain PKCE method accepted",
                "S256 not enforced",
                "Code verifier sent in plaintext",
            ],
            false_positive_indicators=["Only S256 method accepted", "Plain method rejected"],
            confidence=ConfidenceLevel.HIGH,
        ),
        sensitivity=SensitivityLevel.HIGH,
        remediation="Only accept code_challenge_method=S256. Reject 'plain' method for security.",
        references=[
            "https://tools.ietf.org/html/rfc7636#section-4.2",
            "https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics#section-2.1.1",
        ],
        tags=["oauth2", "pkce", "downgrade-attack"],
    ),
    TestVector(
        id="oauth-pkce-bypass-003",
        name="PKCE Code Verifier Not Validated",
        description="Tests if token endpoint validates code_verifier against code_challenge",
        vuln_type=VulnerabilityType.OAUTH_PKCE_BYPASS,
        position=Position(
            type=PositionType.BODY_FORM, name="code_verifier", value_prefix="", value_suffix=""
        ),
        payload=PayloadTemplate(
            base="wrong_verifier_12345678901234567890123456789012",
            variants=[
                "incorrect_verifier",
                "",
                "a" * 43,  # Minimum length
                "z" * 128,  # Maximum length
                "attacker_controlled_verifier_123456789012",
            ],
            encoding="none",
        ),
        expected_evidence=Evidence(
            indicators=[
                "Token issued with incorrect code_verifier",
                "No code_verifier validation",
                "Any verifier accepted",
            ],
            false_positive_indicators=["Invalid code_verifier error", "PKCE validation failed"],
            confidence=ConfidenceLevel.CRITICAL,
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Validate code_verifier matches SHA256(code_challenge). Reject mismatches.",
        references=[
            "https://tools.ietf.org/html/rfc7636#section-4.6",
            "https://cwe.mitre.org/data/definitions/346.html",
        ],
        tags=["oauth2", "pkce", "validation-bypass"],
    ),
    # ============================================================================
    # SCOPE ESCALATION
    # ============================================================================
    TestVector(
        id="oauth-scope-escalation-001",
        name="Unauthorized Scope Addition",
        description="Tests if additional scopes can be injected beyond what user consented to",
        vuln_type=VulnerabilityType.OAUTH_SCOPE_ESCALATION,
        position=Position(
            type=PositionType.QUERY, name="scope", value_prefix="read", value_suffix=""
        ),
        payload=PayloadTemplate(
            base="read write admin",
            variants=[
                "read write delete",
                "read admin",
                "write admin delete",
                "openid profile email admin",
                "user:read admin:write",
                "api:* admin:*",
                "scope1 scope2 scope3 admin root superuser",
            ],
            encoding="url",
        ),
        expected_evidence=Evidence(
            indicators=[
                "Unauthorized scope present in access token",
                "Admin scope granted without consent",
                "Token contains scopes not in authorization request",
            ],
            false_positive_indicators=[
                "Only authorized scopes in token",
                "Scope validation enforced",
            ],
            confidence=ConfidenceLevel.HIGH,
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Validate requested scopes against user permissions. Never trust client-provided scope. Store consent.",
        references=[
            "https://tools.ietf.org/html/rfc6749#section-3.3",
            "https://cwe.mitre.org/data/definitions/269.html",
        ],
        tags=["oauth2", "scope", "privilege-escalation"],
    ),
    TestVector(
        id="oauth-scope-escalation-002",
        name="Scope Manipulation in Token Request",
        description="Tests if scope can be modified during token exchange",
        vuln_type=VulnerabilityType.OAUTH_SCOPE_ESCALATION,
        position=Position(
            type=PositionType.BODY_FORM, name="scope", value_prefix="", value_suffix=""
        ),
        payload=PayloadTemplate(
            base="admin delete write",
            variants=["admin", "root", "superuser", "*", "all", "full_access"],
            encoding="url",
        ),
        expected_evidence=Evidence(
            indicators=[
                "Scope modified during token exchange",
                "Token endpoint accepts new scopes",
                "Privilege escalation via scope manipulation",
            ],
            false_positive_indicators=[
                "Scope frozen at authorization",
                "Token scope matches authorization scope",
            ],
            confidence=ConfidenceLevel.HIGH,
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Token endpoint must ignore scope parameter. Use scope from authorization code.",
        references=[
            "https://tools.ietf.org/html/rfc6749#section-4.1.3",
            "https://datatracker.ietf.org/doc/html/rfc6749#section-3.3",
        ],
        tags=["oauth2", "scope", "token-exchange"],
    ),
    TestVector(
        id="oauth-scope-escalation-003",
        name="Wildcard Scope Injection",
        description="Tests if wildcard scopes can be used to gain broad access",
        vuln_type=VulnerabilityType.OAUTH_SCOPE_ESCALATION,
        position=Position(type=PositionType.QUERY, name="scope", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="*",
            variants=[
                "*",
                "**",
                ".*",
                "api:*",
                "user:*",
                "admin:*",
                "read:* write:* delete:*",
                "%2A",  # URL-encoded *
                "*/*",
            ],
            encoding="url",
        ),
        expected_evidence=Evidence(
            indicators=[
                "Wildcard scope accepted",
                "All permissions granted via * scope",
                "Unrestricted API access",
            ],
            false_positive_indicators=["Wildcard rejected", "Specific scopes required"],
            confidence=ConfidenceLevel.HIGH,
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Reject wildcard scopes. Require explicit scope enumeration. Implement least privilege.",
        references=[
            "https://tools.ietf.org/html/rfc6749#section-3.3",
            "https://cwe.mitre.org/data/definitions/269.html",
        ],
        tags=["oauth2", "scope", "wildcard"],
    ),
    # ============================================================================
    # CLIENT AUTHENTICATION BYPASS
    # ============================================================================
    TestVector(
        id="oauth-client-auth-001",
        name="Client Secret Not Required for Confidential Clients",
        description="Tests if token endpoint requires client authentication",
        vuln_type=VulnerabilityType.AUTHN_BYPASS,
        position=Position(
            type=PositionType.BODY_FORM, name="client_secret", value_prefix="", value_suffix=""
        ),
        payload=PayloadTemplate(
            base="", variants=["", " ", "null"], encoding="none"  # Omit client_secret
        ),
        expected_evidence=Evidence(
            indicators=[
                "Token issued without client_secret",
                "Client authentication bypassed",
                "Confidential client treated as public",
            ],
            false_positive_indicators=[
                "Client authentication required error",
                "Invalid client error",
            ],
            confidence=ConfidenceLevel.CRITICAL,
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Enforce client authentication for confidential clients. Require client_secret or certificate.",
        references=[
            "https://tools.ietf.org/html/rfc6749#section-2.3",
            "https://cwe.mitre.org/data/definitions/287.html",
        ],
        tags=["oauth2", "client-authentication", "bypass"],
    ),
    TestVector(
        id="oauth-client-auth-002",
        name="Client Credential Brute Force",
        description="Tests if client_secret is vulnerable to brute force attacks",
        vuln_type=VulnerabilityType.AUTHN_BYPASS,
        position=Position(
            type=PositionType.BODY_FORM, name="client_secret", value_prefix="", value_suffix=""
        ),
        payload=PayloadTemplate(
            base="password123",
            variants=[
                "password",
                "123456",
                "secret",
                "admin",
                "client_secret",
                "changeme",
                "default",
            ],
            encoding="none",
        ),
        expected_evidence=Evidence(
            indicators=[
                "No rate limiting on token endpoint",
                "Weak client_secret accepted",
                "No account lockout after failed attempts",
            ],
            false_positive_indicators=["Rate limiting enforced", "Account locked after failures"],
            confidence=ConfidenceLevel.MEDIUM,
        ),
        sensitivity=SensitivityLevel.HIGH,
        remediation="Implement rate limiting. Use strong client secrets (min 32 chars, high entropy). Monitor failed attempts.",
        references=[
            "https://tools.ietf.org/html/rfc6749#section-10.4",
            "https://cwe.mitre.org/data/definitions/307.html",
        ],
        tags=["oauth2", "client-authentication", "brute-force"],
    ),
    # ============================================================================
    # IMPLICIT FLOW VULNERABILITIES
    # ============================================================================
    TestVector(
        id="oauth-implicit-001",
        name="Token Leakage via Browser History - Implicit Flow",
        description="Tests if access token is exposed in browser history via fragment",
        vuln_type=VulnerabilityType.OAUTH_VULN,
        position=Position(
            type=PositionType.QUERY, name="response_type", value_prefix="", value_suffix=""
        ),
        payload=PayloadTemplate(
            base="token", variants=["token", "token id_token", "id_token token"], encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=[
                "Implicit flow enabled",
                "Access token in URL fragment",
                "Token visible in browser history/logs",
            ],
            false_positive_indicators=[
                "Implicit flow disabled",
                "Authorization code flow enforced",
            ],
            confidence=ConfidenceLevel.HIGH,
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Disable implicit flow. Use authorization code flow with PKCE for SPAs.",
        references=[
            "https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics#section-2.1.2",
            "https://tools.ietf.org/html/rfc6749#section-10.3",
        ],
        tags=["oauth2", "implicit-flow", "token-leakage"],
    ),
    # ============================================================================
    # REFRESH TOKEN VULNERABILITIES
    # ============================================================================
    TestVector(
        id="oauth-refresh-001",
        name="Refresh Token Not Rotated",
        description="Tests if refresh token is rotated on each use",
        vuln_type=VulnerabilityType.OAUTH_VULN,
        position=Position(
            type=PositionType.BODY_FORM, name="refresh_token", value_prefix="", value_suffix=""
        ),
        payload=PayloadTemplate(
            base="<REFRESH_TOKEN>", variants=["<SAME_REFRESH_TOKEN_REUSED>"], encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=[
                "Same refresh token works multiple times",
                "No token rotation implemented",
                "Refresh token never expires",
            ],
            false_positive_indicators=[
                "New refresh token issued each time",
                "Old token invalidated",
            ],
            confidence=ConfidenceLevel.HIGH,
        ),
        sensitivity=SensitivityLevel.HIGH,
        remediation="Implement refresh token rotation. Issue new refresh token and invalidate old one on each use.",
        references=[
            "https://tools.ietf.org/html/rfc6749#section-10.4",
            "https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics#section-4.13",
        ],
        tags=["oauth2", "refresh-token", "rotation"],
    ),
    TestVector(
        id="oauth-refresh-002",
        name="Refresh Token Bound to Wrong Client",
        description="Tests if refresh token can be used by different client",
        vuln_type=VulnerabilityType.OAUTH_VULN,
        position=Position(
            type=PositionType.BODY_FORM, name="client_id", value_prefix="", value_suffix=""
        ),
        payload=PayloadTemplate(
            base="malicious_client_id",
            variants=["different_client_123", "attacker_client_456", "*"],
            encoding="none",
        ),
        expected_evidence=Evidence(
            indicators=[
                "Refresh token works with different client_id",
                "No client binding validation",
                "Token hijacking possible",
            ],
            false_positive_indicators=["Invalid client error", "Client binding enforced"],
            confidence=ConfidenceLevel.CRITICAL,
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Bind refresh token to client. Validate client_id matches token-issuing client.",
        references=[
            "https://tools.ietf.org/html/rfc6749#section-10.4",
            "https://cwe.mitre.org/data/definitions/346.html",
        ],
        tags=["oauth2", "refresh-token", "client-binding"],
    ),
]

# Total vectors: 20
