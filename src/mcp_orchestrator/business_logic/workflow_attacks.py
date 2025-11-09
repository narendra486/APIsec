"""
Business Logic Workflow Attack Testing Vectors
Step skipping, race conditions, state manipulation
"""

from ..models import (
    TestVector, VulnerabilityType, TestVectorPosition as Position, PositionType,
    TestVectorPayload as PayloadTemplate, TestVectorEvidence as Evidence, 
    ConfidenceLevel, SensitivityLevel
)

WORKFLOW_ATTACK_VECTORS = [
    TestVector(
        id="workflow-step-skip-001",
        name="Multi-Step Workflow Step Skipping",
        description="Tests if workflow steps can be skipped (e.g., cart -> complete without payment)",
        vuln_type=VulnerabilityType.BUSINESS_LOGIC_STEP_SKIP,
        position=Position(type=PositionType.PATH, name="endpoint", value_prefix="/", value_suffix=""),
        payload=PayloadTemplate(
            base="checkout/complete",
            variants=["/checkout/complete", "/order/finalize", "/payment/success"],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["Order completed without payment", "Workflow step bypassed"],
            confidence=ConfidenceLevel.CRITICAL
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Validate workflow state server-side. Enforce step sequence.",
        references=["https://cwe.mitre.org/data/definitions/840.html"],
        tags=["business-logic", "workflow", "step-skipping"]
    ),
    
    TestVector(
        id="workflow-race-001",
        name="Race Condition in Transaction",
        description="Tests for race conditions allowing duplicate operations",
        vuln_type=VulnerabilityType.BUSINESS_LOGIC_RACE_CONDITION,
        position=Position(type=PositionType.BODY_JSON, name="amount", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base='{"amount":100}',  # Send multiple simultaneous requests
            variants=[],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["Duplicate withdrawal", "Negative balance", "Race condition exploited"],
            confidence=ConfidenceLevel.HIGH
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Implement transaction locking. Use database transactions with proper isolation.",
        references=["https://cwe.mitre.org/data/definitions/362.html"],
        tags=["business-logic", "race-condition", "concurrency"]
    ),
    
    TestVector(
        id="workflow-order-001",
        name="Workflow Order Manipulation",
        description="Tests if workflow steps can be executed out of order",
        vuln_type=VulnerabilityType.BUSINESS_LOGIC_WORKFLOW_BYPASS,
        position=Position(type=PositionType.BODY_JSON, name="step", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base='{"step":5}',
            variants=['{"step":5}', '{"step":99}', '{"step":-1}'],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["Steps executed out of order", "Workflow state corruption"],
            confidence=ConfidenceLevel.HIGH
        ),
        sensitivity=SensitivityLevel.HIGH,
        remediation="Enforce strict step sequence server-side. Validate current state before each step.",
        references=["https://cwe.mitre.org/data/definitions/840.html"],
        tags=["business-logic", "workflow", "order-manipulation"]
    ),
    
    TestVector(
        id="workflow-state-001",
        name="Workflow State Tampering",
        description="Tests if workflow state can be manipulated client-side",
        vuln_type=VulnerabilityType.BUSINESS_LOGIC_STATE_MANIPULATION,
        position=Position(type=PositionType.BODY_JSON, name="state", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base='{"state":"completed"}',
            variants=['{"state":"completed"}', '{"state":"approved"}', '{"state":"paid"}'],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["State change accepted", "Workflow bypass", "Unauthorized state transition"],
            confidence=ConfidenceLevel.CRITICAL
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Store workflow state server-side. Don't trust client-provided state. Use state machine.",
        references=["https://cwe.mitre.org/data/definitions/602.html"],
        tags=["business-logic", "state-tampering", "workflow"]
    ),
    
    TestVector(
        id="workflow-idempotency-001",
        name="Idempotency Bypass",
        description="Tests if operations can be repeated when they shouldn't be",
        vuln_type=VulnerabilityType.BUSINESS_LOGIC_IDEMPOTENCY,
        position=Position(type=PositionType.HEADER, name="Idempotency-Key", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="",
            variants=["", "new-key-each-time"],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["Duplicate operation succeeded", "Idempotency not enforced"],
            confidence=ConfidenceLevel.HIGH
        ),
        sensitivity=SensitivityLevel.HIGH,
        remediation="Implement idempotency keys for critical operations. Track operation IDs.",
        references=["https://datatracker.ietf.org/doc/html/draft-ietf-httpapi-idempotency-key-header"],
        tags=["business-logic", "idempotency", "duplicate-processing"]
    ),
    
    TestVector(
        id="workflow-payment-001",
        name="Payment Flow Manipulation",
        description="Tests if payment confirmation can be bypassed",
        vuln_type=VulnerabilityType.BUSINESS_LOGIC_PAYMENT_BYPASS,
        position=Position(type=PositionType.BODY_JSON, name="payment_status", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base='{"payment_status":"success"}',
            variants=['{"payment_status":"success"}', '{"paid":true}', '{"payment_confirmed":true}'],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["Payment bypass", "Order processed without payment"],
            confidence=ConfidenceLevel.CRITICAL
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Verify payment server-side. Use payment gateway callbacks. Never trust client payment status.",
        references=["https://cwe.mitre.org/data/definitions/840.html"],
        tags=["business-logic", "payment", "bypass"]
    ),
    
    TestVector(
        id="workflow-approval-001",
        name="Approval Process Bypass",
        description="Tests if approval steps can be skipped",
        vuln_type=VulnerabilityType.BUSINESS_LOGIC_APPROVAL_BYPASS,
        position=Position(type=PositionType.BODY_JSON, name="approved", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base='{"approved":true}',
            variants=['{"approved":true}', '{"approval_status":"approved"}', '{"needs_approval":false}'],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["Approval bypassed", "Unauthorized action approved"],
            confidence=ConfidenceLevel.CRITICAL
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Enforce approval workflow server-side. Track approval status independently.",
        references=["https://cwe.mitre.org/data/definitions/285.html"],
        tags=["business-logic", "approval", "bypass"]
    ),
    
    TestVector(
        id="workflow-session-001",
        name="Session Fixation in Workflow",
        description="Tests for session fixation during workflow transitions",
        vuln_type=VulnerabilityType.BUSINESS_LOGIC_SESSION_FIXATION,
        position=Position(type=PositionType.HEADER, name="Cookie", value_prefix="session=", value_suffix=""),
        payload=PayloadTemplate(
            base="fixed_session_id",
            variants=["fixed_session_id", "attacker_session"],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["Session not regenerated", "Session fixation possible"],
            confidence=ConfidenceLevel.HIGH
        ),
        sensitivity=SensitivityLevel.HIGH,
        remediation="Regenerate session ID after authentication and privilege changes.",
        references=["https://cwe.mitre.org/data/definitions/384.html"],
        tags=["business-logic", "session-fixation", "workflow"]
    ),
    
    TestVector(
        id="workflow-parallel-001",
        name="Parallel Request Abuse",
        description="Tests for vulnerabilities when processing parallel requests",
        vuln_type=VulnerabilityType.BUSINESS_LOGIC_RACE_CONDITION,
        position=Position(type=PositionType.BODY_JSON, name="action", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base='{"action":"claim_reward"}',
            variants=['{"action":"claim_reward"}'],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["Multiple parallel claims successful", "Race condition in reward system"],
            confidence=ConfidenceLevel.HIGH
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Use database locking. Implement atomic operations. Add request deduplication.",
        references=["https://cwe.mitre.org/data/definitions/362.html"],
        tags=["business-logic", "race-condition", "parallel-requests"]
    ),
    
    TestVector(
        id="workflow-rollback-001",
        name="Transaction Rollback Exploitation",
        description="Tests if transaction rollbacks can be exploited",
        vuln_type=VulnerabilityType.BUSINESS_LOGIC_TRANSACTION_INTEGRITY,
        position=Position(type=PositionType.BODY_JSON, name="force_error", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base='{"amount":100,"trigger_error_after":true}',
            variants=['{"amount":100,"trigger_error_after":true}'],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["Partial transaction committed", "Inconsistent state"],
            confidence=ConfidenceLevel.HIGH
        ),
        sensitivity=SensitivityLevel.HIGH,
        remediation="Use proper transaction boundaries. Implement all-or-nothing semantics.",
        references=["https://cwe.mitre.org/data/definitions/662.html"],
        tags=["business-logic", "transaction", "rollback"]
    ),
    
    TestVector(
        id="workflow-async-001",
        name="Asynchronous Operation Abuse",
        description="Tests for race conditions in async workflows",
        vuln_type=VulnerabilityType.BUSINESS_LOGIC_ASYNC_RACE,
        position=Position(type=PositionType.BODY_JSON, name="async_op", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base='{"operation":"transfer","async":true}',
            variants=['{"operation":"transfer","async":true}'],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["Async race condition", "State inconsistency", "Duplicate processing"],
            confidence=ConfidenceLevel.MEDIUM
        ),
        sensitivity=SensitivityLevel.HIGH,
        remediation="Implement eventual consistency checks. Use message queues with deduplication.",
        references=["https://cwe.mitre.org/data/definitions/362.html"],
        tags=["business-logic", "async", "race-condition"]
    ),
    
    TestVector(
        id="workflow-cart-001",
        name="Shopping Cart Manipulation",
        description="Tests if shopping cart can be manipulated for price bypass",
        vuln_type=VulnerabilityType.BUSINESS_LOGIC_PRICE_MANIPULATION,
        position=Position(type=PositionType.BODY_JSON, name="items", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base='{"items":[{"id":1,"price":0.01}]}',
            variants=[
                '{"items":[{"id":1,"price":0.01}]}',
                '{"items":[{"id":1,"quantity":-1}]}',
                '{"items":[],"total":0}'
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["Client price accepted", "Cart total manipulation"],
            confidence=ConfidenceLevel.CRITICAL
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Calculate prices server-side. Never trust client-provided prices or totals.",
        references=["https://cwe.mitre.org/data/definitions/840.html"],
        tags=["business-logic", "shopping-cart", "price-manipulation"]
    ),
    
    TestVector(
        id="workflow-coupon-001",
        name="Coupon Stacking Exploit",
        description="Tests if multiple coupons/discounts can be stacked improperly",
        vuln_type=VulnerabilityType.BUSINESS_LOGIC_DISCOUNT_ABUSE,
        position=Position(type=PositionType.BODY_JSON, name="coupons", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base='{"coupons":["SAVE50","SAVE50","SAVE50"]}',
            variants=[
                '{"coupons":["SAVE50","SAVE50","SAVE50"]}',
                '{"coupons":["EXPIRED_CODE","USED_CODE"]}'
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["Coupon stacking allowed", "Discount abuse", "Negative total"],
            confidence=ConfidenceLevel.HIGH
        ),
        sensitivity=SensitivityLevel.HIGH,
        remediation="Validate coupon combinations. Enforce one-time use. Check expiration dates.",
        references=["https://cwe.mitre.org/data/definitions/840.html"],
        tags=["business-logic", "coupon", "discount-stacking"]
    ),
    
    TestVector(
        id="workflow-loyalty-001",
        name="Loyalty Points Manipulation",
        description="Tests if loyalty points can be manipulated or generated",
        vuln_type=VulnerabilityType.BUSINESS_LOGIC_POINTS_MANIPULATION,
        position=Position(type=PositionType.BODY_JSON, name="points", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base='{"earned_points":99999}',
            variants=[
                '{"earned_points":99999}',
                '{"points_balance":99999}',
                '{"redeem_points":-1000}'
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["Points manipulation accepted", "Artificial points generation"],
            confidence=ConfidenceLevel.CRITICAL
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Calculate points server-side. Validate point transactions. Implement audit trail.",
        references=["https://cwe.mitre.org/data/definitions/840.html"],
        tags=["business-logic", "loyalty-points", "manipulation"]
    ),
    
    TestVector(
        id="workflow-mfa-001",
        name="MFA Bypass via Session Fixation",
        description="Tests for MFA bypass by fixing session before authentication",
        vuln_type=VulnerabilityType.BUSINESS_LOGIC_SESSION_FIXATION,
        position=Position(type=PositionType.HEADER, name="Cookie", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="SESSIONID=attacker_controlled_session",
            variants=[
                "SESSIONID=attacker_controlled_session",
                "session_id=fixed_value",
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["Session accepted pre-authentication", "MFA bypassed", "Session not regenerated"],
            confidence=ConfidenceLevel.HIGH
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Regenerate session after authentication. Invalidate pre-auth sessions.",
        references=["https://cwe.mitre.org/data/definitions/384.html"],
        tags=["business-logic", "session-fixation", "mfa-bypass"]
    ),
    
    TestVector(
        id="workflow-captcha-001",
        name="CAPTCHA Bypass via Workflow Manipulation",
        description="Tests for CAPTCHA bypass by skipping validation step",
        vuln_type=VulnerabilityType.BUSINESS_LOGIC_STEP_SKIP,
        position=Position(type=PositionType.BODY_JSON, name="captcha_validated", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="true",
            variants=["true", "1"],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["CAPTCHA bypassed", "Validation step skipped", "Automated abuse possible"],
            confidence=ConfidenceLevel.HIGH
        ),
        sensitivity=SensitivityLevel.MEDIUM,
        remediation="Validate CAPTCHA server-side. Use session tracking. Don't trust client flags.",
        references=["https://cwe.mitre.org/data/definitions/840.html"],
        tags=["business-logic", "captcha-bypass", "automation"]
    ),
]

# Total vectors: 16
