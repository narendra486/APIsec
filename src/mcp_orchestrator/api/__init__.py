"""
API Security Testing Module
GraphQL, Schema Analysis, Rate Limiting, REST Security, WebSocket, Cache Poisoning, HPP
"""

from .graphql_advanced import GRAPHQL_ADVANCED_VECTORS
from .schema_analyzer import SCHEMA_ANALYZER_VECTORS
from .rate_limit_tests import RATE_LIMIT_BYPASS_VECTORS
from .rest_security import REST_SECURITY_VECTORS
from .websocket_tests import WEBSOCKET_VECTORS
from .cache_poisoning_tests import CACHE_POISONING_VECTORS
from .hpp_tests import HPP_VECTORS

__all__ = [
    'GRAPHQL_ADVANCED_VECTORS',
    'SCHEMA_ANALYZER_VECTORS',
    'RATE_LIMIT_BYPASS_VECTORS',
    'REST_SECURITY_VECTORS',
    'WEBSOCKET_VECTORS',
    'CACHE_POISONING_VECTORS',
    'HPP_VECTORS',
]

# Total API security vectors: 12 + 8 + 10 + 14 + 5 + 5 + 4 = 58 vectors
