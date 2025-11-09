"""
OWASP Top 10 Testing Module
Security headers, misconfiguration, CSRF, Open Redirect testing
"""

from .security_headers import SECURITY_HEADER_VECTORS
from .misconfig_tests import MISCONFIGURATION_VECTORS
from .csrf_tests import CSRF_VECTORS
from .open_redirect_tests import OPEN_REDIRECT_VECTORS
from .supply_chain_failures import SUPPLY_CHAIN_FAILURE_VECTORS
from .exceptional_conditions import EXCEPTIONAL_CONDITIONS_VECTORS

__all__ = [
    'SECURITY_HEADER_VECTORS',
    'MISCONFIGURATION_VECTORS',
    'CSRF_VECTORS',
    'OPEN_REDIRECT_VECTORS',
    'SUPPLY_CHAIN_FAILURE_VECTORS',
    'EXCEPTIONAL_CONDITIONS_VECTORS',
]

# Total OWASP vectors: 9 + 14 + 8 + 6 = 37 vectors
