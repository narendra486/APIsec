"""
OWASP Top 10 2025: A10 - Mishandling of Exceptional Conditions
"""
from ..models import TestVector, VulnerabilityType, TestVectorPayload, TestVectorEvidence, ConfidenceLevel, SensitivityLevel, TestVectorPosition, PositionType

EXCEPTIONAL_CONDITIONS_VECTORS = [
    TestVector(
        id="A10-2025-001",
        name="Uncaught Exception Disclosure",
        description="Test for uncaught exceptions leaking stack traces or sensitive info.",
        vuln_type=VulnerabilityType.MISHANDLING_OF_EXCEPTIONAL_CONDITIONS,
        position=TestVectorPosition(type=PositionType.BODY_JSON, name="input"),
        payload=TestVectorPayload(base="Trigger an error to cause an uncaught exception."),
        expected_evidence=TestVectorEvidence(indicators=["Stack trace in response", "Sensitive info in error message"], confidence=ConfidenceLevel.HIGH),
        sensitivity=SensitivityLevel.HIGH,
        remediation="Handle all exceptions and sanitize error messages.",
        references=["https://owasp.org/Top10/2025/A10_2025-Mishandling_of_Exceptional_Conditions/"],
        tags=["exception", "error handling", "stack trace"]
    ),
    TestVector(
        id="A10-2025-002",
        name="Fail-Open Authentication",
        description="Test for authentication logic that fails open on error.",
        vuln_type=VulnerabilityType.MISHANDLING_OF_EXCEPTIONAL_CONDITIONS,
        position=TestVectorPosition(type=PositionType.BODY_JSON, name="auth"),
        payload=TestVectorPayload(base="Cause an error in authentication logic (e.g., DB down)."),
        expected_evidence=TestVectorEvidence(indicators=["Access granted on error"], confidence=ConfidenceLevel.HIGH),
        sensitivity=SensitivityLevel.HIGH,
        remediation="Ensure authentication fails closed on all errors.",
        references=["https://owasp.org/Top10/2025/A10_2025-Mishandling_of_Exceptional_Conditions/"],
        tags=["exception", "fail-open", "auth"]
    ),
    TestVector(
        id="A10-2025-003",
        name="Improper Error Logging",
        description="Test for sensitive data written to logs on error.",
        vuln_type=VulnerabilityType.MISHANDLING_OF_EXCEPTIONAL_CONDITIONS,
        position=TestVectorPosition(type=PositionType.BODY_JSON, name="log"),
        payload=TestVectorPayload(base="Trigger an error and inspect logs for sensitive data."),
        expected_evidence=TestVectorEvidence(indicators=["Sensitive data in logs"], confidence=ConfidenceLevel.MEDIUM),
        sensitivity=SensitivityLevel.HIGH,
        remediation="Sanitize logs and avoid logging sensitive data.",
        references=["https://owasp.org/Top10/2025/A10_2025-Mishandling_of_Exceptional_Conditions/"],
        tags=["exception", "logging"]
    ),
    TestVector(
        id="A10-2025-004",
        name="Silent Failure",
        description="Test for errors that are silently ignored, causing undefined behavior.",
        vuln_type=VulnerabilityType.MISHANDLING_OF_EXCEPTIONAL_CONDITIONS,
        position=TestVectorPosition(type=PositionType.BODY_JSON, name="input"),
        payload=TestVectorPayload(base="Cause an error and observe if it is silently ignored."),
        expected_evidence=TestVectorEvidence(indicators=["No error reported, undefined behavior"], confidence=ConfidenceLevel.MEDIUM),
        sensitivity=SensitivityLevel.MEDIUM,
        remediation="Log and handle all errors explicitly.",
        references=["https://owasp.org/Top10/2025/A10_2025-Mishandling_of_Exceptional_Conditions/"],
        tags=["exception", "silent failure"]
    ),
    TestVector(
        id="A10-2025-005",
        name="Improper Input Validation on Exception",
        description="Test for input validation bypasses due to exception mishandling.",
        vuln_type=VulnerabilityType.MISHANDLING_OF_EXCEPTIONAL_CONDITIONS,
        position=TestVectorPosition(type=PositionType.BODY_JSON, name="input"),
        payload=TestVectorPayload(base="Send malformed input to trigger exception and bypass validation."),
        expected_evidence=TestVectorEvidence(indicators=["Validation bypass on error"], confidence=ConfidenceLevel.MEDIUM),
        sensitivity=SensitivityLevel.MEDIUM,
        remediation="Validate input before processing and handle exceptions securely.",
        references=["https://owasp.org/Top10/2025/A10_2025-Mishandling_of_Exceptional_Conditions/"],
        tags=["exception", "input validation"]
    ),
]
