"""
Business Logic Testing Module
Workflow Attacks, Financial Logic, File Upload Bypass
"""

from .workflow_attacks import WORKFLOW_ATTACK_VECTORS
from .financial_tests import FINANCIAL_TEST_VECTORS
from .file_upload_bypass import FILE_UPLOAD_BYPASS_VECTORS

__all__ = [
    "WORKFLOW_ATTACK_VECTORS",
    "FINANCIAL_TEST_VECTORS",
    "FILE_UPLOAD_BYPASS_VECTORS",
]

# Total business logic vectors: 15 + 10 + 15 = 40 vectors
