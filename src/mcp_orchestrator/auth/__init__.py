"""
Authentication & Authorization Testing Module
Comprehensive test vectors for OAuth, SAML, MFA, Sessions, and Authorization
"""

from .oauth_tests import OAUTH_TEST_VECTORS
from .saml_tests import SAML_TEST_VECTORS
from .mfa_tests import MFA_TEST_VECTORS
from .session_tests import SESSION_TEST_VECTORS
from .authorization_tests import AUTHORIZATION_TEST_VECTORS

__all__ = [
    "OAUTH_TEST_VECTORS",
    "SAML_TEST_VECTORS",
    "MFA_TEST_VECTORS",
    "SESSION_TEST_VECTORS",
    "AUTHORIZATION_TEST_VECTORS",
]

# Total auth/authz vectors: 20 + 15 + 10 + 12 + 18 = 75 vectors
