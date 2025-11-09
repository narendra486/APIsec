# MCP-Orchestrator Usage Guide

## Quick Start

### 1. Installation

```bash
cd /Users/narendra/Documents/APISec
pip install -e .
```

### 2. Configure Your MCP Client

Add to your MCP client configuration (e.g., Claude Desktop, Cline):

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

### 3. Basic Workflow

## Tool Reference

### 1. `ingest_api` - Parse API Descriptor

**Purpose**: Parse and normalize various API descriptor formats

**Supported Formats**:
- OpenAPI/Swagger (v2, v3)
- GraphQL SDL / Introspection
- HAR (HTTP Archive)
- cURL commands
- Raw HTTP requests
- Auto-detection

**Example**:
```json
{
  "tool": "ingest_api",
  "arguments": {
    "content": "<OpenAPI JSON or YAML>",
    "descriptor_type": "openapi",
    "base_url": "https://api.example.com"
  }
}
```

**Returns**:
- Normalized endpoint list
- Detected auth flows (OAuth2, JWT, etc.)
- Content types and request/response schemas

### 2. `discover_positions` - Extract Input Positions

**Purpose**: Identify all testable input positions with metadata

**Position Types**:
- Path parameters (`/users/{id}`)
- Query parameters (`?search=`)
- Headers (including auth headers)
- Cookies
- JSON body fields (with JSONPath)
- XML body fields (with XPath)
- GraphQL variables, operations, directives
- Multipart form fields

**Example**:
```json
{
  "tool": "discover_positions",
  "arguments": {
    "include_endpoints": ["/api/users", "/api/auth"]
  }
}
```

**Returns**:
- Position ID and location
- Inferred data type (string, integer, UUID, email, etc.)
- Validation constraints (pattern, min/max, enum)
- Sensitivity level (low → critical)
- Benign filler values

### 3. `generate_test_plan` - Create Prioritized Tests

**Purpose**: Generate ranked security tests based on risk

**Prioritization Factors**:
1. Auth/AuthZ endpoints (highest)
2. Sensitive resource operations (CRUD on users, payments)
3. User-facing input (search, filters)
4. Admin-only endpoints
5. File upload/download endpoints
6. Generic API endpoints (lowest)

**Example**:
```json
{
  "tool": "generate_test_plan",
  "arguments": {
    "max_tests": 100,
    "focus_vulnerabilities": ["sqli", "xss", "jwt-vuln", "idor"],
    "top_n_preview": 10
  }
}
```

**Returns**:
```json
{
  "test_plan_id": "plan-001",
  "total_tests": 100,
  "top_tests": [
    {
      "priority": 1,
      "endpoint": "/api/users/{id}",
      "method": "GET",
      "position": {"type": "path", "name": "id"},
      "test_type": "idor",
      "payload": "../admin/1",
      "expected_signal": "Unauthorized access",
      "rationale": "Path param on sensitive resource"
    }
  ]
}
```

### 4. `execute_tests` - Run Security Tests

**Purpose**: Execute tests with live HTTP requests and behavior analysis

**Behavior Signals Captured**:
- Response timing (for blind SQLi, SSRF)
- Error messages and stack traces
- Status code anomalies
- New cookies or session changes
- OOB (out-of-band) interactions (DNS, HTTP callbacks)
- Redirect chains
- Created resource IDs

**Modes**:
- **safe**: Non-destructive only (GET, POST non-modifying)
- **aggressive**: Include PUT/PATCH, careful DELETE
- **custom**: Fine-grained control

**Example**:
```json
{
  "tool": "execute_tests",
  "arguments": {
    "plan_id": "plan-001",
    "mode": "safe",
    "max_concurrency": 5,
    "time_budget_seconds": 300
  }
}
```

**Returns**:
- Findings with confidence levels
- Evidence (request, response, timing)
- PoC reproduction steps

### 5. `generate_report` - Create Reports

**Purpose**: Generate comprehensive vulnerability reports

**Formats**:
- **JSON**: Machine-readable, full detail
- **Markdown**: Human-readable, GitHub-friendly
- **HTML**: Interactive, with charts
- **Burp**: Import into Burp Suite

**Report Sections**:
- Executive summary
- Severity distribution (Critical → Info)
- Confidence levels (Confirmed → Minimal)
- Detailed findings with:
  - Description and impact
  - PoC steps (cURL, raw HTTP)
  - Remediation guidance
  - Code examples (vulnerable vs secure)
  - OWASP/CWE mappings
  - CVSS scores

**Example**:
```json
{
  "tool": "generate_report",
  "arguments": {
    "formats": ["json", "markdown", "html"],
    "output_dir": "./reports",
    "include_low_confidence": false
  }
}
```

### 6. `configure_scanner` - Set Scope & Limits

**Purpose**: Configure scanner behavior and safety constraints

**Key Settings**:

```json
{
  "tool": "configure_scanner",
  "arguments": {
    "mode": "safe",
    "allowlist": ["https://api.example.com/*"],
    "denylist": ["*/admin/delete*", "*/payment/*"],
    "max_concurrency": 5,
    "requests_per_second": 10,
    "oob_callback_url": "http://your-listener.com/callback",
    "sensitivity_level": "high",
    "destructive_tests": false
  }
}
```

**Safety Features**:
- **Allowlist**: Only test matching URLs
- **Denylist**: Never test these patterns
- **Rate limiting**: Prevent server overload
- **Destructive tests**: Disabled by default
- **Secret redaction**: Auto-redact tokens in logs

### 7. `update_payloads` - Fetch Latest Signatures

**Purpose**: Update vulnerability test payloads from trusted sources

**Default Sources**:
- SecLists (GitHub)
- PayloadsAllTheThings (GitHub)
- OWASP Testing Guide

**Features**:
- Sandbox validation before production merge
- CVE-to-test-recipe pipeline
- Changelog tracking

**Example**:
```json
{
  "tool": "update_payloads",
  "arguments": {
    "sources": ["seclists", "payloadsallthethings"],
    "force_update": false
  }
}
```

## Vulnerability Coverage

### 🔐 Authentication & Authorization

#### JWT (23 Test Vectors)
1. Algorithm confusion (`alg=none`, `alg=NONE`, `alg=nOnE`)
2. Expired tokens
3. Future `nbf` (not before)
4. Claim tampering (sub, role, aud, iss)
5. Empty/missing signature
6. KID manipulation (null, path traversal, SQLi)
7. Weak HMAC secrets (empty, "password")
8. RS256 → HS256 confusion (public key as HMAC)
9. Invalid JSON in header/payload
10. JTI replay
11. X5U injection (remote cert fetch → SSRF)
12. JKU injection (remote JWK set → SSRF)
13. Embedded JWK with attacker key

#### OAuth2
- Token replay
- Scope escalation
- Refresh token misuse
- Implicit flow vulnerabilities
- Authorization code interception

#### Session Management
- Session fixation
- Cookie scope issues (domain/path)
- Missing HttpOnly/Secure flags
- Session timeout bypass

#### Access Control
- IDOR (Insecure Direct Object References)
- Horizontal privilege escalation
- Vertical privilege escalation
- Forced browsing
- Parameter tampering

### 💉 Injection Attacks

#### SQL Injection
- Error-based
- Boolean-based blind
- Time-based blind
- Stacked queries
- Union-based
- DB-specific (MySQL, PostgreSQL, MSSQL, Oracle)

#### XSS (Cross-Site Scripting)
- Reflected XSS
- Stored XSS
- DOM-based XSS
- Attribute injection
- JavaScript context escape
- Event handler injection

#### XXE (XML External Entity)
- DOCTYPE injection
- Parameter entity attacks
- File disclosure
- SSRF via XXE

#### Command Injection
- Shell metacharacters
- Command chaining (`;`, `|`, `&`)
- Inline execution

#### GraphQL-Specific
- Introspection abuse
- Query depth/complexity DoS
- Injection in filters/where clauses
- Batching attacks

### 🌐 SSRF & OOB

- HTTP/HTTPS callbacks
- DNS exfiltration
- Internal port scanning
- Cloud metadata endpoints (AWS, Azure, GCP)

### 📁 Path Traversal
- `../` sequences
- Absolute paths
- Encoding variants (URL, double-URL, Unicode)

## Example Workflow

### Scenario: Test a REST API

```bash
# Step 1: Ingest OpenAPI spec
Request: ingest_api
  content: <openapi.json contents>
  base_url: https://api.example.com

Response:
  ✓ 15 endpoints discovered
  ✓ JWT auth flow detected
  ✓ OAuth2 endpoints found

# Step 2: Generate test plan
Request: generate_test_plan
  max_tests: 100
  top_n_preview: 10

Response:
  Top 10 Tests:
  1. IDOR on /users/{id} (CRITICAL)
  2. JWT alg=none on /auth/token (CRITICAL)
  3. SQLi in search param (HIGH)
  4. XSS in username field (HIGH)
  5. Admin authz bypass (HIGH)
  ...

# Step 3: Execute tests
Request: execute_tests
  mode: safe
  max_concurrency: 5

Response:
  ✓ 100 tests executed
  ⚠ 5 findings:
    - 2 CRITICAL (IDOR, JWT vuln)
    - 2 HIGH (SQLi, authz bypass)
    - 1 MEDIUM (info disclosure)

# Step 4: Generate report
Request: generate_report
  formats: [json, markdown, html]

Response:
  ✓ reports/report-20231109-001.json
  ✓ reports/report-20231109-001.md
  ✓ reports/report-20231109-001.html
```

## Best Practices

### 1. Scope Control
Always set strict allowlist/denylist:
```yaml
scope:
  allowlist: ["https://api.example.com/*"]
  denylist: ["*/delete*", "*/remove*"]
```

### 2. Rate Limiting
Respect target capacity:
```yaml
rate_limit:
  requests_per_second: 10  # Conservative
  burst_size: 20
```

### 3. Authentication
Provide valid credentials:
- Prevents false positives from auth failures
- Tests actual authz logic
- Discovers privilege escalation

### 4. OOB Listener
Set up callback server for blind vulnerabilities:
```yaml
oob_listener:
  callback: http://your-unique-id.oob-listener.com
```

### 5. Incremental Testing
Start small, expand gradually:
1. Single endpoint → full API
2. Safe mode → aggressive mode
3. High confidence → include low confidence

## Troubleshooting

### Issue: Too many false positives
**Solution**: Increase confidence threshold
```yaml
adaptive:
  confidence_threshold: 0.8  # Higher = fewer false positives
```

### Issue: Tests too slow
**Solution**: Increase concurrency, reduce scope
```json
{
  "max_concurrency": 10,
  "time_budget_seconds": 600
}
```

### Issue: Blocked by WAF/rate limiter
**Solution**: Reduce rate, add delays
```yaml
rate_limit:
  requests_per_second: 2  # Very conservative
```

## Advanced Features

### Adaptive Learning
System learns successful payloads per-target:
- Tracks success rates
- Prioritizes effective mutations
- Avoids false-positive patterns

### CVE Onboarding
Auto-generates tests for new CVEs:
1. Monitor vulnerability feeds
2. Extract PoC code
3. Generate test recipe
4. Sandbox validation
5. Production deployment

### Custom Payload Sources
Add your own payload repositories:
```yaml
payload_sources:
  - type: github
    url: https://github.com/your-org/custom-payloads
    path: sql-injection
    enabled: true
```

## Legal & Ethics

⚠️ **CRITICAL**: Only test systems you own or have explicit written authorization to test.

Unauthorized security testing is **illegal** under:
- Computer Fraud and Abuse Act (CFAA) - USA
- Computer Misuse Act - UK
- Similar laws worldwide

**Always**:
1. Get written authorization
2. Define scope clearly
3. Respect rate limits
4. Avoid destructive tests without approval
5. Disclose findings responsibly

## Support

- **Issues**: File on GitHub
- **Documentation**: See `/docs`
- **Examples**: See `/examples`

---

**Version**: 1.0.0  
**License**: MIT
