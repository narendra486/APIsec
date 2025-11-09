"""
MCP-Orchestrator - Comprehensive API Security Testing Framework
Version 2.0.0 - Enhanced with 229+ New Test Vectors from Competitive Analysis

Total Coverage:
- Authentication & Authorization: 75 vectors (OAuth, SAML, MFA, Sessions, RBAC)
- Injection Attacks: 52 vectors (SSTI, NoSQL, LDAP, Command Injection)
- API Security: 42 vectors (GraphQL, Schema Analysis, Rate Limiting, REST)
- Business Logic: 40 vectors (Workflow, Financial, File Upload)
- OWASP Top 10: 20 vectors (Headers, Misconfiguration)
- Existing: 23 JWT vectors + SQLi/XSS/XXE/SSRF models

TOTAL: 250+ Comprehensive Security Test Vectors
"""

__version__ = "2.0.0"

# Import registry for easy access
from .test_vector_registry import (
    get_registry,
    get_vector,
    get_vectors_by_type,
    get_vectors_by_tag,
    get_all_vectors,
    print_registry_stats,
)

# Import models
from .models import (
    TestVector,
    VulnerabilityType,
    Position,
    PositionType,
    PayloadTemplate,
    Evidence,
    ConfidenceLevel,
    SensitivityLevel,
)

__all__ = [
    # Registry functions
    "get_registry",
    "get_vector",
    "get_vectors_by_type",
    "get_vectors_by_tag",
    "get_all_vectors",
    "print_registry_stats",
    # Models
    "TestVector",
    "VulnerabilityType",
    "Position",
    "PositionType",
    "PayloadTemplate",
    "Evidence",
    "ConfidenceLevel",
    "SensitivityLevel",
]
