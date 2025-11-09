"""
Financial Logic Testing Vectors
Price manipulation, integer overflow/underflow
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

FINANCIAL_TEST_VECTORS = [
    TestVector(
        id="price-manip-001",
        name="Negative Price Manipulation",
        description="Tests if negative prices can be submitted",
        vuln_type=VulnerabilityType.BUSINESS_LOGIC_PRICE_MANIPULATION,
        position=Position(
            type=PositionType.BODY_JSON, name="price", value_prefix="", value_suffix=""
        ),
        payload=PayloadTemplate(base="-100", variants=["-100", "-0.01", "-99999"], encoding="none"),
        expected_evidence=Evidence(
            indicators=["Negative price accepted", "Credit instead of charge"],
            confidence=ConfidenceLevel.CRITICAL,
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Validate price/amount is positive. Use server-side pricing.",
        references=["https://cwe.mitre.org/data/definitions/840.html"],
        tags=["financial", "price-manipulation", "business-logic"],
    ),
    TestVector(
        id="price-quantity-001",
        name="Negative Quantity Manipulation",
        description="Tests if negative quantities bypass validation",
        vuln_type=VulnerabilityType.BUSINESS_LOGIC_QUANTITY_MANIPULATION,
        position=Position(
            type=PositionType.BODY_JSON, name="quantity", value_prefix="", value_suffix=""
        ),
        payload=PayloadTemplate(base="-1", variants=["-1", "-100", "-99999"], encoding="none"),
        expected_evidence=Evidence(
            indicators=["Negative quantity accepted", "Reverse transaction", "Account credited"],
            confidence=ConfidenceLevel.CRITICAL,
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Validate quantity is positive. Use unsigned integers. Server-side validation.",
        references=["https://cwe.mitre.org/data/definitions/840.html"],
        tags=["financial", "quantity", "negative-values"],
    ),
    TestVector(
        id="price-overflow-001",
        name="Integer Overflow in Price Calculation",
        description="Tests for integer overflow in financial calculations",
        vuln_type=VulnerabilityType.BUSINESS_LOGIC_INTEGER_OVERFLOW,
        position=Position(
            type=PositionType.BODY_JSON, name="amount", value_prefix="", value_suffix=""
        ),
        payload=PayloadTemplate(
            base="2147483647",
            variants=["2147483647", "9999999999999999", "99999999999999999999"],
            encoding="none",
        ),
        expected_evidence=Evidence(
            indicators=["Integer overflow", "Wrap-around to negative", "Price calculation error"],
            confidence=ConfidenceLevel.HIGH,
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Use safe math libraries. Validate numeric ranges. Use appropriate data types (Decimal).",
        references=["https://cwe.mitre.org/data/definitions/190.html"],
        tags=["financial", "integer-overflow", "calculation"],
    ),
    TestVector(
        id="price-underflow-001",
        name="Integer Underflow Attack",
        description="Tests for integer underflow vulnerabilities",
        vuln_type=VulnerabilityType.BUSINESS_LOGIC_INTEGER_UNDERFLOW,
        position=Position(
            type=PositionType.BODY_JSON, name="discount", value_prefix="", value_suffix=""
        ),
        payload=PayloadTemplate(
            base="2147483648", variants=["2147483648", "-2147483648"], encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["Integer underflow", "Negative result becomes large positive"],
            confidence=ConfidenceLevel.HIGH,
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Validate subtraction operations. Use checked arithmetic. Handle underflow explicitly.",
        references=["https://cwe.mitre.org/data/definitions/191.html"],
        tags=["financial", "integer-underflow", "arithmetic"],
    ),
    TestVector(
        id="price-conversion-001",
        name="Currency Conversion Manipulation",
        description="Tests if currency conversion can be exploited",
        vuln_type=VulnerabilityType.BUSINESS_LOGIC_CURRENCY_MANIPULATION,
        position=Position(
            type=PositionType.BODY_JSON, name="currency", value_prefix="", value_suffix=""
        ),
        payload=PayloadTemplate(
            base='{"amount":100,"from":"USD","to":"USD","rate":999}',
            variants=[
                '{"amount":100,"from":"USD","to":"USD","rate":999}',
                '{"amount":100,"currency":"XXX"}',
                '{"amount":100,"rate":0.001}',
            ],
            encoding="none",
        ),
        expected_evidence=Evidence(
            indicators=["Custom exchange rate accepted", "Currency manipulation"],
            confidence=ConfidenceLevel.CRITICAL,
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Use server-side exchange rates. Fetch rates from trusted sources. Don't trust client rates.",
        references=["https://cwe.mitre.org/data/definitions/840.html"],
        tags=["financial", "currency", "exchange-rate"],
    ),
    TestVector(
        id="price-discount-001",
        name="Discount Stacking Abuse",
        description="Tests if discounts can be stacked beyond limits",
        vuln_type=VulnerabilityType.BUSINESS_LOGIC_DISCOUNT_ABUSE,
        position=Position(
            type=PositionType.BODY_JSON, name="discounts", value_prefix="", value_suffix=""
        ),
        payload=PayloadTemplate(
            base='{"discounts":[{"type":"percent","value":50},{"type":"percent","value":50}]}',
            variants=[
                '{"discounts":[{"type":"percent","value":50},{"type":"percent","value":50}]}',
                '{"discount_percent":150}',
                '{"discount_amount":99999}',
            ],
            encoding="none",
        ),
        expected_evidence=Evidence(
            indicators=["Excessive discount applied", "Negative total", "Discount stacking"],
            confidence=ConfidenceLevel.HIGH,
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Validate total discount. Cap maximum discount percentage. Server-side calculation.",
        references=["https://cwe.mitre.org/data/definitions/840.html"],
        tags=["financial", "discount", "stacking-abuse"],
    ),
    TestVector(
        id="price-refund-001",
        name="Refund Process Abuse",
        description="Tests for refund amount manipulation",
        vuln_type=VulnerabilityType.BUSINESS_LOGIC_REFUND_ABUSE,
        position=Position(
            type=PositionType.BODY_JSON, name="refund_amount", value_prefix="", value_suffix=""
        ),
        payload=PayloadTemplate(
            base="99999", variants=["99999", "original_price * 2", "-100"], encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["Excessive refund amount", "Refund exceeds purchase", "Negative refund"],
            confidence=ConfidenceLevel.CRITICAL,
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Validate refund <= original amount. Track partial refunds. Server-side validation.",
        references=["https://cwe.mitre.org/data/definitions/840.html"],
        tags=["financial", "refund", "abuse"],
    ),
    TestVector(
        id="price-credit-001",
        name="Credit/Balance Manipulation",
        description="Tests if account credit can be manipulated",
        vuln_type=VulnerabilityType.BUSINESS_LOGIC_BALANCE_MANIPULATION,
        position=Position(
            type=PositionType.BODY_JSON, name="add_credit", value_prefix="", value_suffix=""
        ),
        payload=PayloadTemplate(
            base="99999", variants=["99999", "-1000", "2147483647"], encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["Arbitrary credit added", "Balance manipulation"],
            confidence=ConfidenceLevel.CRITICAL,
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Validate credit sources. Implement transaction verification. Audit all balance changes.",
        references=["https://cwe.mitre.org/data/definitions/840.html"],
        tags=["financial", "credit", "balance-manipulation"],
    ),
    TestVector(
        id="price-decimal-001",
        name="Decimal Precision Exploitation",
        description="Tests for floating point precision issues",
        vuln_type=VulnerabilityType.BUSINESS_LOGIC_PRECISION_ERROR,
        position=Position(
            type=PositionType.BODY_JSON, name="price", value_prefix="", value_suffix=""
        ),
        payload=PayloadTemplate(
            base="0.00000001",
            variants=["0.00000001", "1.23456789012345", "999.999999999999"],
            encoding="none",
        ),
        expected_evidence=Evidence(
            indicators=["Precision loss", "Rounding errors exploited", "Free transactions"],
            confidence=ConfidenceLevel.MEDIUM,
        ),
        sensitivity=SensitivityLevel.HIGH,
        remediation="Use Decimal type for currency. Store amounts as cents (integers). Avoid floating point.",
        references=["https://cwe.mitre.org/data/definitions/682.html"],
        tags=["financial", "decimal", "precision", "floating-point"],
    ),
    TestVector(
        id="price-rounding-001",
        name="Rounding Error Abuse",
        description="Tests if rounding can be exploited for profit",
        vuln_type=VulnerabilityType.BUSINESS_LOGIC_ROUNDING_ERROR,
        position=Position(
            type=PositionType.BODY_JSON, name="items", value_prefix="", value_suffix=""
        ),
        payload=PayloadTemplate(
            base='{"items":[{"price":0.001,"quantity":1000}]}',
            variants=[
                '{"items":[{"price":0.001,"quantity":1000}]}',
                '{"price":0.333,"quantity":3}',
                '{"split_payment":[0.01,0.01,0.01]}',
            ],
            encoding="none",
        ),
        expected_evidence=Evidence(
            indicators=[
                "Rounding in user's favor",
                "Accumulated rounding errors",
                "Salami slicing",
            ],
            confidence=ConfidenceLevel.MEDIUM,
        ),
        sensitivity=SensitivityLevel.MEDIUM,
        remediation="Round consistently. Use banker's rounding. Validate final totals. Store exact values.",
        references=["https://en.wikipedia.org/wiki/Salami_slicing"],
        tags=["financial", "rounding", "salami-slicing"],
    ),
    TestVector(
        id="financial-tax-001",
        name="Tax Calculation Manipulation",
        description="Tests for tax calculation bypass or manipulation",
        vuln_type=VulnerabilityType.BUSINESS_LOGIC_PRICE_MANIPULATION,
        position=Position(
            type=PositionType.BODY_JSON, name="tax_rate", value_prefix="", value_suffix=""
        ),
        payload=PayloadTemplate(base="0", variants=["0", "-0.1", "0.0000001"], encoding="none"),
        expected_evidence=Evidence(
            indicators=["Tax removed", "Negative tax applied", "Order total reduced"],
            confidence=ConfidenceLevel.HIGH,
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Calculate tax server-side. Don't trust client tax inputs. Validate tax rates.",
        references=["https://cwe.mitre.org/data/definitions/840.html"],
        tags=["business-logic", "tax-manipulation", "financial"],
    ),
]

# Total vectors: 11
