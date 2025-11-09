"""
OWASP Top 10 Testing Module
Security headers, misconfiguration, CSRF, Open Redirect testing
"""

from .security_headers import SECURITY_HEADER_VECTORS
from .misconfig_tests import MISCONFIGURATION_VECTORS
from .csrf_tests import CSRF_VECTORS
from .open_redirect_tests import OPEN_REDIRECT_VECTORS

__all__ = [
    'SECURITY_HEADER_VECTORS',
    'MISCONFIGURATION_VECTORS',
    'CSRF_VECTORS',
    'OPEN_REDIRECT_VECTORS',
]

# Total OWASP vectors: 9 + 14 + 8 + 6 = 37 vectors
