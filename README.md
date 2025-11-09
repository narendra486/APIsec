# Analyzer usage (snippet)

This project includes a small analyzer tool to run test vectors against login endpoints and collect structured findings.

Important: By default the analyzer will skip requests to demo.testfire.net. The skip rule is enforced in code: if the Analyzer is constructed with a base URL whose host appears in the --skip-hosts list (default contains 'demo.testfire.net'), the analyzer will not send any network traffic and will return a 'skipped_by_policy' result.

Quick example (CLI):

```
python3 scripts/run_analyzer.py --url http://example.local/doLogin --vectors-file vectors.json --concurrency 2
```

If you need to override the skip list, pass --skip-hosts with a comma-separated list. Note: demo.testfire.net is included by default to avoid accidental scanning of the demo host.
# MCP-Orchestrator

**Modular, adaptive API & web-application security testing server with behavior analysis**

A comprehensive Model Context Protocol (MCP) server for automated security testing of REST, SOAP, GraphQL, and arbitrary HTTP flows. Features behavior-driven analysis, position-aware testing (Burp-style), self-evolving payload libraries, and prioritized vulnerability reporting.

## Features

### 🎯 Core Capabilities

- **Multi-Protocol Support**: REST, SOAP, GraphQL, raw HTTP
- **Position-Based Testing**: Burp Suite-style positional attack surface mapping
- **Behavior Analysis**: Response timing, error patterns, OOB interactions
- **Adaptive Learning**: Self-evolving payload selection based on success patterns
- **Comprehensive Auth Testing**: OAuth2, JWT (20+ vectors), SAML, session management

### 🔍 Vulnerability Coverage

- SQL Injection (error-based, boolean, time-based, stacked queries)
- XSS (reflected, stored, DOM-based)
- XXE & XML attacks
- GraphQL-specific (introspection, injection, DoS)
- Authorization bypass (IDOR, privilege escalation)
- SSRF with OOB detection
- Command injection, path traversal, deserialization
- Session & authentication vulnerabilities

### 🧠 Intelligence Features

- **Dynamic Payload Updates**: Auto-fetch from GitHub/RSS/curated sources
- **CVE Onboarding**: Auto-generate test recipes from new vulnerabilities
- **Learning Engine**: Per-field success tracking and mutation strategies
- **Confidence Scoring**: Multi-factor analysis for low false-positive rates

### 📊 Reporting & Integration

- Multiple formats: JSON, Markdown, HTML, Burp-compatible
- OWASP-mapped remediation guidance with code examples
- Integrations: Slack, Jira, GitHub Issues, SIEM export

## Installation

```bash
# Clone repository
cd APISec

# Install dependencies
pip install -e .

# Or with development dependencies
pip install -e ".[dev]"
```

## Quick Start

### As MCP Server

Add to your MCP client configuration:

```json
{
  "mcpServers": {
    "mcp-orchestrator": {
      "command": "python",
      "args": ["-m", "mcp_orchestrator.server"],
      "env": {}
    }
  }
}
```

### MCP Tools Available

1. **ingest_api** - Parse OpenAPI/Swagger/WSDL/GraphQL/HAR/cURL
2. **discover_positions** - Extract and analyze input positions
3. **generate_test_plan** - Create prioritized security test plan
4. **execute_tests** - Run non-destructive security tests
5. **generate_report** - Produce comprehensive vulnerability report
6. **update_payloads** - Fetch latest payload signatures
7. **configure_scanner** - Set scope, rate limits, OOB listener

## Usage Examples

### 1. Scan OpenAPI Endpoint

```python
# Via MCP tool call
{
  "tool": "ingest_api",
  "arguments": {
    "type": "openapi",
    "source": "https://api.example.com/openapi.json",
    "auth": {
      "type": "bearer",
      "token": "your-token"
    }
  }
}

# Returns: Parsed API model with endpoints and auth flows
```

### 2. Generate Test Plan

```python
{
  "tool": "generate_test_plan",
  "arguments": {
    "target": "https://api.example.com",
    "sensitivity": "high",
    "max_tests": 100
  }
}

# Returns: Top 10 highest-priority tests with rationale
```

### 3. Execute Security Tests

```python
{
  "tool": "execute_tests",
  "arguments": {
    "plan_id": "test-plan-abc123",
    "mode": "safe",
    "max_concurrency": 5,
    "time_budget_seconds": 300
  }
}

# Returns: Real-time findings with evidence and PoCs
```

## Architecture

```
mcp_orchestrator/
├── server.py              # MCP server entry point
├── models/                # Pydantic data models
│   ├── position.py
│   ├── test_case.py
│   ├── finding.py
│   └── config.py
├── ingest/                # Input parsers
│   ├── openapi_parser.py
│   ├── graphql_parser.py
│   ├── har_parser.py
│   └── curl_parser.py
├── discovery/             # Position extraction
│   ├── position_extractor.py
│   └── type_inference.py
├── auth/                  # Auth/AuthZ testing
│   ├── oauth_tests.py
│   ├── jwt_tests.py
│   └── session_tests.py
├── vulnerabilities/       # Vulnerability tests
│   ├── sqli.py
│   ├── xss.py
│   ├── graphql.py
│   └── idor.py
├── behavior/              # Behavior analysis
│   ├── analyzer.py
│   └── confidence.py
├── adaptive/              # Learning engine
│   ├── mutation.py
│   └── learning_table.py
├── payloads/              # Payload management
│   ├── updater.py
│   └── library.py
├── reporting/             # Report generation
│   ├── json_reporter.py
│   ├── markdown_reporter.py
│   └── burp_exporter.py
└── utils/                 # Utilities
    ├── encoding.py
    ├── http_client.py
    └── oob_listener.py
```

## Configuration

Create `config.yaml`:

```yaml
mode: safe  # safe | aggressive | custom
destructive_tests: false
max_concurrency: 5
time_budget_ms: 300000

oob_listener:
  dns_server: "your-dns.example.com"
  http_server: "http://your-callback.example.com"

scope:
  allowlist:
    - "https://api.example.com/*"
  denylist:
    - "*/admin/delete*"
  
rate_limit:
  requests_per_second: 10
  burst_size: 20

sensitivity_level: high  # low | medium | high | critical

payload_sources:
  - type: github
    url: "https://github.com/danielmiessler/SecLists"
    enabled: true
  - type: github
    url: "https://github.com/swisskyrepo/PayloadsAllTheThings"
    enabled: true

adaptive:
  enabled: true
  confidence_threshold: 0.7
  mutation_budget: 50
  learn_across_targets: false

reporting:
  formats: [json, markdown, html]
  output_dir: "./reports"
  redact_secrets: true

integrations:
  slack:
    webhook_url: "https://hooks.slack.com/..."
  jira:
    url: "https://your-jira.atlassian.net"
    project: "SEC"
```

## Safeguards

- ✅ Non-destructive mode by default
- ✅ Scope enforcement (allowlist/denylist)
- ✅ Rate limiting and throttling
- ✅ Secret redaction in logs/reports
- ✅ No credential brute-forcing
- ✅ Respect for robots.txt (configurable)
- ✅ Sandbox validation for new payloads

## Test Vectors Included

### JWT Tests (20+ vectors)
- Algorithm confusion (none, HS256→RS256)
- Expired/invalid tokens
- Claim tampering (sub, aud, iss, exp)
- KID manipulation
- Weak HMAC secrets

### SQL Injection
- Error-based (MySQL, PostgreSQL, MSSQL, Oracle)
- Boolean blind
- Time-based blind
- Stacked queries
- Union-based extraction

### XSS Patterns
- Reflected XSS in headers, query, body
- Attribute injection
- JavaScript context escape
- Event handler injection
- DOM-based sinks

## API Examples

### Test Plan Output

```json
{
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
        "inferred_type": "integer"
      },
      "test_type": "idor",
      "payload": "../../admin/1",
      "expected_signal": "Unauthorized access or privilege escalation",
      "rationale": "Path parameter on sensitive user endpoint with no documented authz check"
    },
    {
      "priority": 2,
      "endpoint": "/api/auth/token",
      "method": "POST",
      "position": {
        "type": "body-json",
        "path": "$.token",
        "inferred_type": "jwt"
      },
      "test_type": "jwt-vuln",
      "payload": "<modified JWT with alg=none>",
      "expected_signal": "Accepted token with none algorithm",
      "rationale": "JWT endpoint susceptible to algorithm confusion attack"
    }
  ]
}
```

### Finding Output

```json
{
  "id": "finding-sqli-001",
  "vulnerability_type": "sqli",
  "severity": "critical",
  "confidence": "high",
  "title": "SQL Injection in search parameter",
  "endpoint": "/api/search",
  "evidence": {
    "request": {
      "method": "GET",
      "url": "/api/search?q=test' OR '1'='1",
      "curl": "curl -X GET 'https://api.example.com/api/search?q=test%27%20OR%20%271%27%3D%271'"
    },
    "response": {
      "status_code": 200,
      "timing_delta": 0.15,
      "error_strings": ["SQL syntax error", "mysql_fetch_array()"]
    },
    "confidence_level": "high",
    "anomaly_score": 0.92
  },
  "remediation": {
    "summary": "Use parameterized queries or prepared statements",
    "code_examples": [
      {
        "language": "python",
        "secure": "cursor.execute('SELECT * FROM users WHERE name = ?', (user_input,))"
      }
    ]
  }
}
```

## Development

```bash
# Run tests
pytest

# Format code
black src/

# Type check
mypy src/

# Lint
ruff check src/
```

## License

MIT

## Contributing

Contributions welcome! Please ensure:
- Tests pass
- Code formatted with Black
- Type hints included
- Security implications considered

## Roadmap

- [ ] WebSocket testing support
- [ ] gRPC/Protobuf support
- [ ] Distributed scanning mode
- [ ] Machine learning for payload optimization
- [ ] Browser automation for DOM XSS
- [ ] Custom test recipe DSL

---

**⚠️ Disclaimer**: This tool is for authorized security testing only. Unauthorized testing is illegal. Always obtain proper authorization before testing.
