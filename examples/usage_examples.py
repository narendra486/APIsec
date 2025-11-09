"""
Example: Testing OpenAPI endpoint with MCP-Orchestrator
"""

import json

# Example 1: Ingest OpenAPI specification
ingest_request = {
    "tool": "ingest_api",
    "arguments": {
        "content": open("examples/sample-api.json").read(),
        "descriptor_type": "openapi",
        "base_url": "https://api.example.com"
    }
}

print("=" * 80)
print("EXAMPLE 1: Ingest OpenAPI Specification")
print("=" * 80)
print(json.dumps(ingest_request, indent=2))
print()

# Example 2: Generate test plan with top 10 tests
test_plan_request = {
    "tool": "generate_test_plan",
    "arguments": {
        "max_tests": 100,
        "focus_vulnerabilities": ["sqli", "xss", "jwt-vuln", "idor"],
        "top_n_preview": 10
    }
}

print("=" * 80)
print("EXAMPLE 2: Generate Prioritized Test Plan")
print("=" * 80)
print(json.dumps(test_plan_request, indent=2))
print()

# Example 3: Execute tests in safe mode
execute_request = {
    "tool": "execute_tests",
    "arguments": {
        "mode": "safe",
        "max_concurrency": 5,
        "time_budget_seconds": 300
    }
}

print("=" * 80)
print("EXAMPLE 3: Execute Security Tests (Safe Mode)")
print("=" * 80)
print(json.dumps(execute_request, indent=2))
print()

# Example 4: Configure scanner scope
config_request = {
    "tool": "configure_scanner",
    "arguments": {
        "mode": "safe",
        "allowlist": [
            "https://api.example.com/*",
            "https://staging-api.example.com/*"
        ],
        "denylist": [
            "*/admin/delete*",
            "*/payment/*"
        ],
        "max_concurrency": 5,
        "requests_per_second": 10,
        "oob_callback_url": "http://your-oob-listener.example.com/callback",
        "sensitivity_level": "high",
        "destructive_tests": False
    }
}

print("=" * 80)
print("EXAMPLE 4: Configure Scanner")
print("=" * 80)
print(json.dumps(config_request, indent=2))
print()

# Example 5: Generate report
report_request = {
    "tool": "generate_report",
    "arguments": {
        "formats": ["json", "markdown", "html"],
        "output_dir": "./reports",
        "include_low_confidence": False
    }
}

print("=" * 80)
print("EXAMPLE 5: Generate Security Report")
print("=" * 80)
print(json.dumps(report_request, indent=2))
print()

# Example 6: Test cURL command
curl_example = '''curl -X POST https://api.example.com/api/users \\
  -H "Content-Type: application/json" \\
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \\
  -d '{"username":"test","email":"test@example.com"}'
'''

curl_request = {
    "tool": "ingest_api",
    "arguments": {
        "content": curl_example,
        "descriptor_type": "curl",
        "base_url": "https://api.example.com"
    }
}

print("=" * 80)
print("EXAMPLE 6: Test cURL Command")
print("=" * 80)
print("cURL command:")
print(curl_example)
print("\nMCP Request:")
print(json.dumps(curl_request, indent=2))
print()

# Example 7: Test GraphQL endpoint
graphql_query = {
    "query": "query { __schema { types { name } } }"
}

graphql_request = {
    "tool": "ingest_api",
    "arguments": {
        "content": json.dumps(graphql_query),
        "descriptor_type": "graphql",
        "base_url": "https://api.example.com/graphql"
    }
}

print("=" * 80)
print("EXAMPLE 7: Test GraphQL Endpoint")
print("=" * 80)
print(json.dumps(graphql_request, indent=2))
print()

# Example 8: Expected output format for top priority tests
example_output = {
    "test_plan_id": "plan-20231109-abc123",
    "target": "https://api.example.com",
    "top_tests": [
        {
            "priority": 1,
            "endpoint": "/api/users/{id}",
            "method": "GET",
            "position": {
                "type": "path",
                "name": "id",
                "inferred_type": "integer",
                "sensitivity": "high"
            },
            "test_type": "idor",
            "payload": "../admin/1",
            "expected_signal": "Unauthorized access to admin user data",
            "rationale": "Path parameter on sensitive user endpoint without documented authorization check. High risk of IDOR vulnerability."
        },
        {
            "priority": 2,
            "endpoint": "/api/auth/token",
            "method": "POST",
            "position": {
                "type": "header",
                "name": "Authorization",
                "inferred_type": "jwt"
            },
            "test_type": "jwt-vuln",
            "payload": "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsImV4cCI6OTk5OTk5OTk5OX0.",
            "expected_signal": "Accepted token with none algorithm",
            "rationale": "JWT endpoint susceptible to algorithm confusion (alg=none). 23 test vectors available for comprehensive JWT testing."
        },
        {
            "priority": 3,
            "endpoint": "/api/users",
            "method": "GET",
            "position": {
                "type": "query",
                "name": "q",
                "inferred_type": "string"
            },
            "test_type": "sqli",
            "payload": "test' OR '1'='1",
            "expected_signal": "SQL error message or unexpected data exposure",
            "rationale": "User-facing search parameter without type constraints. Classic SQL injection entry point."
        },
        {
            "priority": 4,
            "endpoint": "/api/users",
            "method": "POST",
            "position": {
                "type": "body-json",
                "path": "$.username",
                "inferred_type": "string"
            },
            "test_type": "xss",
            "payload": "\"><script>alert(1)</script>",
            "expected_signal": "Reflected or stored XSS in response",
            "rationale": "User-controllable field that may be rendered in HTML context without proper encoding."
        },
        {
            "priority": 5,
            "endpoint": "/admin/users/{id}",
            "method": "DELETE",
            "position": {
                "type": "path",
                "name": "id",
                "inferred_type": "integer"
            },
            "test_type": "authz-bypass",
            "payload": "1",
            "expected_signal": "Successful deletion without admin privileges",
            "rationale": "Admin-only endpoint - test with low-privilege token to check for horizontal/vertical privilege escalation."
        }
    ]
}

print("=" * 80)
print("EXAMPLE OUTPUT: Top 5 Priority Tests")
print("=" * 80)
print(json.dumps(example_output, indent=2))
