"""
Master Test Vector Registry
Centralized registry of all security testing vectors from competitive analysis

Total Coverage:
- Authentication & Authorization: 67 vectors
- Injection Attacks: 130 vectors (SQL, XSS, SSRF, XXE, Deserialization, XPath, XSLT, CRLF, Prototype Pollution, EL, SSTI, NoSQL, LDAP, Command)
- API Security: 58 vectors (GraphQL, Schema, Rate Limit, REST, WebSocket, Cache Poisoning, HPP)
- Business Logic: 44 vectors
- OWASP Top 10: 39 vectors (CSRF, Open Redirect, Security Headers, Misconfiguration, Supply Chain, Exceptional Conditions)
- TOTAL VECTORS: 339 vectors

COMPREHENSIVE OWASP TOP 10 + EXTENDED COVERAGE ACHIEVED
"""

from typing import List, Dict
from .models import TestVector, VulnerabilityType

# Import all test vector collections
from .auth import (
    OAUTH_TEST_VECTORS,
    SAML_TEST_VECTORS,
    MFA_TEST_VECTORS,
    SESSION_TEST_VECTORS,
    AUTHORIZATION_TEST_VECTORS
)

from .injection import (
    SSTI_TEST_VECTORS,
    NOSQL_TEST_VECTORS,
    LDAP_TEST_VECTORS,
    COMMAND_INJECTION_ADVANCED_VECTORS,
    SQL_INJECTION_VECTORS,
    XSS_VECTORS,
    SSRF_VECTORS,
    XXE_VECTORS,
    DESERIALIZATION_VECTORS,
    XPATH_INJECTION_VECTORS,
    XSLT_INJECTION_VECTORS,
    CRLF_INJECTION_VECTORS,
    PROTOTYPE_POLLUTION_VECTORS,
    EL_INJECTION_VECTORS
)

from .api import (
    GRAPHQL_ADVANCED_VECTORS,
    SCHEMA_ANALYZER_VECTORS,
    RATE_LIMIT_BYPASS_VECTORS,
    REST_SECURITY_VECTORS,
    WEBSOCKET_VECTORS,
    CACHE_POISONING_VECTORS,
    HPP_VECTORS
)

from .business_logic import (
    WORKFLOW_ATTACK_VECTORS,
    FINANCIAL_TEST_VECTORS,
    FILE_UPLOAD_BYPASS_VECTORS
)

from .owasp import (
    SECURITY_HEADER_VECTORS,
    MISCONFIGURATION_VECTORS,
    CSRF_VECTORS,
    OPEN_REDIRECT_VECTORS,
    SUPPLY_CHAIN_FAILURE_VECTORS,
    EXCEPTIONAL_CONDITIONS_VECTORS
)


class TestVectorRegistry:
    """Central registry for all security test vectors"""
    
    def __init__(self):
        self._vectors: Dict[str, TestVector] = {}
        self._register_all_vectors()
    
    def _register_all_vectors(self):
        """Register all test vectors from all modules"""
        
        # Authentication & Authorization (67 vectors)
        self._register_collection(OAUTH_TEST_VECTORS, "OAuth 2.0/OIDC")
        self._register_collection(SAML_TEST_VECTORS, "SAML 2.0")
        self._register_collection(MFA_TEST_VECTORS, "Multi-Factor Auth")
        self._register_collection(SESSION_TEST_VECTORS, "Session Management")
        self._register_collection(AUTHORIZATION_TEST_VECTORS, "Authorization Bypass")
        
        # Injection Attacks (130 vectors) - OWASP A03:2021
        self._register_collection(SQL_INJECTION_VECTORS, "SQL Injection")
        self._register_collection(XSS_VECTORS, "Cross-Site Scripting (XSS)")
        self._register_collection(SSRF_VECTORS, "Server-Side Request Forgery")
        self._register_collection(XXE_VECTORS, "XML External Entity (XXE)")
        self._register_collection(DESERIALIZATION_VECTORS, "Insecure Deserialization")
        self._register_collection(XPATH_INJECTION_VECTORS, "XPath Injection")
        self._register_collection(XSLT_INJECTION_VECTORS, "XSLT Injection")
        self._register_collection(CRLF_INJECTION_VECTORS, "CRLF Injection")
        self._register_collection(PROTOTYPE_POLLUTION_VECTORS, "Prototype Pollution")
        self._register_collection(EL_INJECTION_VECTORS, "Expression Language Injection")
        self._register_collection(SSTI_TEST_VECTORS, "Server-Side Template Injection")
        self._register_collection(NOSQL_TEST_VECTORS, "NoSQL Injection")
        self._register_collection(LDAP_TEST_VECTORS, "LDAP Injection")
        self._register_collection(COMMAND_INJECTION_ADVANCED_VECTORS, "Advanced Command Injection")
        
        # API Security (58 vectors)
        self._register_collection(GRAPHQL_ADVANCED_VECTORS, "Advanced GraphQL")
        self._register_collection(SCHEMA_ANALYZER_VECTORS, "API Schema Analysis")
        self._register_collection(RATE_LIMIT_BYPASS_VECTORS, "Rate Limiting Bypass")
        self._register_collection(REST_SECURITY_VECTORS, "REST API Security")
        self._register_collection(WEBSOCKET_VECTORS, "WebSocket Security")
        self._register_collection(CACHE_POISONING_VECTORS, "Cache Poisoning")
        self._register_collection(HPP_VECTORS, "HTTP Parameter Pollution")
        
        # Business Logic (44 vectors)
        self._register_collection(WORKFLOW_ATTACK_VECTORS, "Workflow Attacks")
        self._register_collection(FINANCIAL_TEST_VECTORS, "Financial Logic")
        self._register_collection(FILE_UPLOAD_BYPASS_VECTORS, "File Upload Bypass")
        
        # OWASP Top 10 (add new 2025 categories)
        self._register_collection(CSRF_VECTORS, "Cross-Site Request Forgery")
        self._register_collection(OPEN_REDIRECT_VECTORS, "Open Redirect")
        self._register_collection(SECURITY_HEADER_VECTORS, "Security Headers")
        self._register_collection(MISCONFIGURATION_VECTORS, "Security Misconfiguration")
        self._register_collection(SUPPLY_CHAIN_FAILURE_VECTORS, "Software Supply Chain Failures")
        self._register_collection(EXCEPTIONAL_CONDITIONS_VECTORS, "Mishandling of Exceptional Conditions")
    
    def _register_collection(self, vectors: List[TestVector], category: str):
        """Register a collection of test vectors"""
        for vector in vectors:
            if vector.id in self._vectors:
                raise ValueError(f"Duplicate test vector ID: {vector.id}")
            self._vectors[vector.id] = vector
        print(f"✓ Registered {len(vectors)} {category} test vectors")
    
    def get_vector(self, vector_id: str) -> TestVector:
        """Get a specific test vector by ID"""
        return self._vectors.get(vector_id)
    
    def get_vectors_by_type(self, vuln_type: VulnerabilityType) -> List[TestVector]:
        """Get all vectors for a specific vulnerability type"""
        return [v for v in self._vectors.values() if v.vuln_type == vuln_type]
    
    def get_vectors_by_tag(self, tag: str) -> List[TestVector]:
        """Get all vectors matching a specific tag"""
        return [v for v in self._vectors.values() if tag in v.tags]
    
    def get_all_vectors(self) -> List[TestVector]:
        """Get all registered test vectors"""
        return list(self._vectors.values())
    
    def get_statistics(self) -> Dict[str, int]:
        """Get registry statistics"""
        return {
            "total_vectors": len(self._vectors),
            "oauth_vectors": len(OAUTH_TEST_VECTORS),
            "saml_vectors": len(SAML_TEST_VECTORS),
            "mfa_vectors": len(MFA_TEST_VECTORS),
            "session_vectors": len(SESSION_TEST_VECTORS),
            "authorization_vectors": len(AUTHORIZATION_TEST_VECTORS),
            "ssti_vectors": len(SSTI_TEST_VECTORS),
            "nosql_vectors": len(NOSQL_TEST_VECTORS),
            "ldap_vectors": len(LDAP_TEST_VECTORS),
            "command_adv_vectors": len(COMMAND_INJECTION_ADVANCED_VECTORS),
            "graphql_vectors": len(GRAPHQL_ADVANCED_VECTORS),
            "schema_vectors": len(SCHEMA_ANALYZER_VECTORS),
            "rate_limit_vectors": len(RATE_LIMIT_BYPASS_VECTORS),
            "rest_vectors": len(REST_SECURITY_VECTORS),
            "workflow_vectors": len(WORKFLOW_ATTACK_VECTORS),
            "financial_vectors": len(FINANCIAL_TEST_VECTORS),
            "file_upload_vectors": len(FILE_UPLOAD_BYPASS_VECTORS),
            "security_header_vectors": len(SECURITY_HEADER_VECTORS),
            "misconfiguration_vectors": len(MISCONFIGURATION_VECTORS),
            "supply_chain_failure_vectors": len(SUPPLY_CHAIN_FAILURE_VECTORS),
            "exceptional_conditions_vectors": len(EXCEPTIONAL_CONDITIONS_VECTORS),
        }


# Global registry instance
registry = TestVectorRegistry()


def get_registry() -> TestVectorRegistry:
    """Get the global test vector registry"""
    return registry


# Convenience functions
def get_vector(vector_id: str) -> TestVector:
    """Get a test vector by ID"""
    return registry.get_vector(vector_id)


def get_vectors_by_type(vuln_type: VulnerabilityType) -> List[TestVector]:
    """Get all vectors for a vulnerability type"""
    return registry.get_vectors_by_type(vuln_type)


def get_vectors_by_tag(tag: str) -> List[TestVector]:
    """Get all vectors matching a tag"""
    return registry.get_vectors_by_tag(tag)


def get_all_vectors() -> List[TestVector]:
    """Get all test vectors"""
    return registry.get_all_vectors()


def print_registry_stats():
    """Print registry statistics"""
    stats = registry.get_statistics()
    print("\n" + "="*60)
    print("MCP-ORCHESTRATOR TEST VECTOR REGISTRY")
    print("="*60)
    print(f"\n📊 TOTAL TEST VECTORS: {stats['total_vectors']}")
    print("\n🔐 AUTHENTICATION & AUTHORIZATION:")
    print(f"   • OAuth 2.0/OIDC:        {stats['oauth_vectors']} vectors")
    print(f"   • SAML 2.0:              {stats['saml_vectors']} vectors")
    print(f"   • Multi-Factor Auth:     {stats['mfa_vectors']} vectors")
    print(f"   • Session Management:    {stats['session_vectors']} vectors")
    print(f"   • Authorization Bypass:  {stats['authorization_vectors']} vectors")
    print(f"   SUBTOTAL: {stats['oauth_vectors'] + stats['saml_vectors'] + stats['mfa_vectors'] + stats['session_vectors'] + stats['authorization_vectors']} vectors")
    
    print("\n💉 INJECTION ATTACKS:")
    print(f"   • Template Injection:    {stats['ssti_vectors']} vectors")
    print(f"   • NoSQL Injection:       {stats['nosql_vectors']} vectors")
    print(f"   • LDAP Injection:        {stats['ldap_vectors']} vectors")
    print(f"   • Command Injection:     {stats['command_adv_vectors']} vectors")
    print(f"   SUBTOTAL: {stats['ssti_vectors'] + stats['nosql_vectors'] + stats['ldap_vectors'] + stats['command_adv_vectors']} vectors")
    
    print("\n🌐 API SECURITY:")
    print(f"   • GraphQL Advanced:      {stats['graphql_vectors']} vectors")
    print(f"   • Schema Analysis:       {stats['schema_vectors']} vectors")
    print(f"   • Rate Limit Bypass:     {stats['rate_limit_vectors']} vectors")
    print(f"   • REST Security:         {stats['rest_vectors']} vectors")
    print(f"   SUBTOTAL: {stats['graphql_vectors'] + stats['schema_vectors'] + stats['rate_limit_vectors'] + stats['rest_vectors']} vectors")
    
    print("\n💼 BUSINESS LOGIC:")
    print(f"   • Workflow Attacks:      {stats['workflow_vectors']} vectors")
    print(f"   • Financial Logic:       {stats['financial_vectors']} vectors")
    print(f"   • File Upload Bypass:    {stats['file_upload_vectors']} vectors")
    print(f"   SUBTOTAL: {stats['workflow_vectors'] + stats['financial_vectors'] + stats['file_upload_vectors']} vectors")
    
    print("\n🛡️ OWASP TOP 10:")
    print(f"   • Security Headers:      {stats['security_header_vectors']} vectors")
    print(f"   • Misconfiguration:      {stats['misconfiguration_vectors']} vectors")
    print(f"   • Supply Chain Failures: {stats['supply_chain_failure_vectors']} vectors")
    print(f"   • Exceptional Conditions: {stats['exceptional_conditions_vectors']} vectors")
    print(f"   SUBTOTAL: {stats['security_header_vectors'] + stats['misconfiguration_vectors'] + stats['supply_chain_failure_vectors'] + stats['exceptional_conditions_vectors']} vectors")
    
    print("\n" + "="*60)
    print("✅ All test vectors successfully registered!")
    print("="*60 + "\n")


# Auto-print stats on import
if __name__ != "__main__":
    print_registry_stats()
