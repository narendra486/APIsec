"""
OWASP Top 10 2025: A03 - Software Supply Chain Failures
"""

from ..models import (
    TestVector,
    VulnerabilityType,
    TestVectorPayload,
    TestVectorEvidence,
    ConfidenceLevel,
    SensitivityLevel,
    TestVectorPosition,
    PositionType,
)

SUPPLY_CHAIN_FAILURE_VECTORS = [
    TestVector(
        id="A03-2025-001",
        name="Malicious Dependency Injection",
        description="Test for malicious code in third-party dependencies.",
        vuln_type=VulnerabilityType.SOFTWARE_SUPPLY_CHAIN_FAILURES,
        position=TestVectorPosition(type=PositionType.BODY_JSON, name="dependency"),
        payload=TestVectorPayload(base="Install a dependency with known malicious code."),
        expected_evidence=TestVectorEvidence(
            indicators=["Unexpected network connections", "Malicious process execution"],
            confidence=ConfidenceLevel.HIGH,
        ),
        sensitivity=SensitivityLevel.HIGH,
        remediation="Use trusted sources, verify package signatures, and monitor SBOM.",
        references=["https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/"],
        tags=["supply chain", "dependency", "malware"],
    ),
    TestVector(
        id="A03-2025-002",
        name="Typosquatting Attack",
        description="Test for typosquatted package installation.",
        vuln_type=VulnerabilityType.SOFTWARE_SUPPLY_CHAIN_FAILURES,
        position=TestVectorPosition(type=PositionType.BODY_JSON, name="package"),
        payload=TestVectorPayload(base="Install a package with a name similar to a popular one."),
        expected_evidence=TestVectorEvidence(
            indicators=["Unexpected package behavior", "Telemetry exfiltration"],
            confidence=ConfidenceLevel.MEDIUM,
        ),
        sensitivity=SensitivityLevel.MEDIUM,
        remediation="Validate package names and sources before installation.",
        references=["https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/"],
        tags=["supply chain", "typosquatting"],
    ),
    TestVector(
        id="A03-2025-003",
        name="Compromised Build Pipeline",
        description="Test for tampering in CI/CD pipeline artifacts.",
        vuln_type=VulnerabilityType.SOFTWARE_SUPPLY_CHAIN_FAILURES,
        position=TestVectorPosition(type=PositionType.BODY_JSON, name="artifact"),
        payload=TestVectorPayload(base="Inject code during build process."),
        expected_evidence=TestVectorEvidence(
            indicators=["Unexpected code in build artifacts"], confidence=ConfidenceLevel.HIGH
        ),
        sensitivity=SensitivityLevel.HIGH,
        remediation="Secure CI/CD, use signed artifacts, and monitor build logs.",
        references=["https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/"],
        tags=["supply chain", "cicd", "build"],
    ),
    TestVector(
        id="A03-2025-004",
        name="Unpinned Dependency Versions",
        description="Test for use of unpinned or floating dependency versions.",
        vuln_type=VulnerabilityType.SOFTWARE_SUPPLY_CHAIN_FAILURES,
        position=TestVectorPosition(type=PositionType.BODY_JSON, name="dependency"),
        payload=TestVectorPayload(base="Install dependencies without version pinning."),
        expected_evidence=TestVectorEvidence(
            indicators=["Unexpected dependency updates"], confidence=ConfidenceLevel.MEDIUM
        ),
        sensitivity=SensitivityLevel.MEDIUM,
        remediation="Pin dependency versions and use lock files.",
        references=["https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/"],
        tags=["supply chain", "dependencies"],
    ),
    TestVector(
        id="A03-2025-005",
        name="Unsigned Third-Party Artifacts",
        description="Test for use of unsigned or unverified third-party artifacts.",
        vuln_type=VulnerabilityType.SOFTWARE_SUPPLY_CHAIN_FAILURES,
        position=TestVectorPosition(type=PositionType.BODY_JSON, name="artifact"),
        payload=TestVectorPayload(base="Install unsigned third-party binaries or packages."),
        expected_evidence=TestVectorEvidence(
            indicators=["Lack of signature verification"], confidence=ConfidenceLevel.MEDIUM
        ),
        sensitivity=SensitivityLevel.MEDIUM,
        remediation="Require signature verification for all third-party artifacts.",
        references=["https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/"],
        tags=["supply chain", "signing"],
    ),
]
