#!/usr/bin/env python3
"""
Quick vector count verification script
"""
import sys

sys.path.insert(0, "/Users/narendra/Documents/APISec/src")

from mcp_orchestrator.auth import (
    OAUTH_TEST_VECTORS,
    SAML_TEST_VECTORS,
    MFA_TEST_VECTORS,
    SESSION_TEST_VECTORS,
    AUTHORIZATION_TEST_VECTORS,
)

from mcp_orchestrator.injection import (
    SSTI_TEST_VECTORS,
    NOSQL_TEST_VECTORS,
    LDAP_TEST_VECTORS,
    COMMAND_INJECTION_ADVANCED_VECTORS,
)

from mcp_orchestrator.api import (
    GRAPHQL_ADVANCED_VECTORS,
    SCHEMA_ANALYZER_VECTORS,
    RATE_LIMIT_BYPASS_VECTORS,
    REST_SECURITY_VECTORS,
)

from mcp_orchestrator.business_logic import (
    WORKFLOW_ATTACK_VECTORS,
    FINANCIAL_TEST_VECTORS,
    FILE_UPLOAD_BYPASS_VECTORS,
)

from mcp_orchestrator.owasp import SECURITY_HEADER_VECTORS, MISCONFIGURATION_VECTORS

# Count all vectors
counts = {
    "OAuth 2.0": len(OAUTH_TEST_VECTORS),
    "SAML 2.0": len(SAML_TEST_VECTORS),
    "MFA": len(MFA_TEST_VECTORS),
    "Session Management": len(SESSION_TEST_VECTORS),
    "Authorization": len(AUTHORIZATION_TEST_VECTORS),
    "SSTI": len(SSTI_TEST_VECTORS),
    "NoSQL": len(NOSQL_TEST_VECTORS),
    "LDAP": len(LDAP_TEST_VECTORS),
    "Command Injection": len(COMMAND_INJECTION_ADVANCED_VECTORS),
    "GraphQL": len(GRAPHQL_ADVANCED_VECTORS),
    "API Schema": len(SCHEMA_ANALYZER_VECTORS),
    "Rate Limiting": len(RATE_LIMIT_BYPASS_VECTORS),
    "REST Security": len(REST_SECURITY_VECTORS),
    "Workflow Attacks": len(WORKFLOW_ATTACK_VECTORS),
    "Financial Logic": len(FINANCIAL_TEST_VECTORS),
    "File Upload": len(FILE_UPLOAD_BYPASS_VECTORS),
    "Security Headers": len(SECURITY_HEADER_VECTORS),
    "Misconfiguration": len(MISCONFIGURATION_VECTORS),
}

print("=" * 70)
print("MCP-ORCHESTRATOR TEST VECTOR COUNT")
print("=" * 70)
print()
print("AUTHENTICATION & AUTHORIZATION:")
print(f"  OAuth 2.0:             {counts['OAuth 2.0']:3d} vectors")
print(f"  SAML 2.0:              {counts['SAML 2.0']:3d} vectors")
print(f"  MFA:                   {counts['MFA']:3d} vectors")
print(f"  Session Management:    {counts['Session Management']:3d} vectors")
print(f"  Authorization:         {counts['Authorization']:3d} vectors")
auth_total = sum(
    [counts[k] for k in ["OAuth 2.0", "SAML 2.0", "MFA", "Session Management", "Authorization"]]
)
print(f"  Subtotal:              {auth_total:3d} vectors")
print()

print("INJECTION ATTACKS:")
print(f"  SSTI:                  {counts['SSTI']:3d} vectors")
print(f"  NoSQL:                 {counts['NoSQL']:3d} vectors")
print(f"  LDAP:                  {counts['LDAP']:3d} vectors")
print(f"  Command Injection:     {counts['Command Injection']:3d} vectors")
injection_total = sum([counts[k] for k in ["SSTI", "NoSQL", "LDAP", "Command Injection"]])
print(f"  Subtotal:              {injection_total:3d} vectors")
print()

print("API SECURITY:")
print(f"  GraphQL:               {counts['GraphQL']:3d} vectors")
print(f"  API Schema:            {counts['API Schema']:3d} vectors")
print(f"  Rate Limiting:         {counts['Rate Limiting']:3d} vectors")
print(f"  REST Security:         {counts['REST Security']:3d} vectors")
api_total = sum([counts[k] for k in ["GraphQL", "API Schema", "Rate Limiting", "REST Security"]])
print(f"  Subtotal:              {api_total:3d} vectors")
print()

print("BUSINESS LOGIC:")
print(f"  Workflow Attacks:      {counts['Workflow Attacks']:3d} vectors")
print(f"  Financial Logic:       {counts['Financial Logic']:3d} vectors")
print(f"  File Upload:           {counts['File Upload']:3d} vectors")
business_total = sum([counts[k] for k in ["Workflow Attacks", "Financial Logic", "File Upload"]])
print(f"  Subtotal:              {business_total:3d} vectors")
print()

print("OWASP TOP 10:")
print(f"  Security Headers:      {counts['Security Headers']:3d} vectors")
print(f"  Misconfiguration:      {counts['Misconfiguration']:3d} vectors")
owasp_total = sum([counts[k] for k in ["Security Headers", "Misconfiguration"]])
print(f"  Subtotal:              {owasp_total:3d} vectors")
print()

grand_total = sum(counts.values())
print("=" * 70)
print(f"GRAND TOTAL:           {grand_total:3d} vectors")
print("=" * 70)
print()

if grand_total >= 229:
    print(f"✅ SUCCESS: {grand_total} vectors >= 229 target!")
else:
    print(f"⚠️  WARNING: {grand_total} vectors < 229 target (need {229-grand_total} more)")
