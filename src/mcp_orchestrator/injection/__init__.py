"""
Injection Attack Testing Module
SQL, XSS, SSTI, NoSQL, LDAP, Command, SSRF, XXE, Deserialization, XPath, XSLT, CRLF, Prototype Pollution, EL
"""

from .ssti_tests import SSTI_TEST_VECTORS
from .nosql_tests import NOSQL_TEST_VECTORS
from .ldap_tests import LDAP_TEST_VECTORS
from .command_advanced import COMMAND_INJECTION_ADVANCED_VECTORS
from .sql_tests import SQL_INJECTION_VECTORS
from .xss_tests import XSS_VECTORS
from .ssrf_tests import SSRF_VECTORS
from .xxe_tests import XXE_VECTORS
from .deserialization_tests import DESERIALIZATION_VECTORS
from .xpath_tests import XPATH_INJECTION_VECTORS
from .xslt_tests import XSLT_INJECTION_VECTORS
from .crlf_tests import CRLF_INJECTION_VECTORS
from .prototype_pollution_tests import PROTOTYPE_POLLUTION_VECTORS
from .el_injection_tests import EL_INJECTION_VECTORS

__all__ = [
    "SSTI_TEST_VECTORS",
    "NOSQL_TEST_VECTORS",
    "LDAP_TEST_VECTORS",
    "COMMAND_INJECTION_ADVANCED_VECTORS",
    "SQL_INJECTION_VECTORS",
    "XSS_VECTORS",
    "SSRF_VECTORS",
    "XXE_VECTORS",
    "DESERIALIZATION_VECTORS",
    "XPATH_INJECTION_VECTORS",
    "XSLT_INJECTION_VECTORS",
    "CRLF_INJECTION_VECTORS",
    "PROTOTYPE_POLLUTION_VECTORS",
    "EL_INJECTION_VECTORS",
]

# Total injection vectors: 13 + 13 + 11 + 15 + 15 + 15 + 10 + 8 + 8 + 5 + 3 + 5 + 5 + 4 = 130 vectors
