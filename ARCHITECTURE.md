# MCP-Orchestrator Architecture

## System Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         MCP-Orchestrator Server                          │
│                     (Model Context Protocol Interface)                   │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                    ┌───────────────┼───────────────┐
                    │               │               │
                    ▼               ▼               ▼
        ┌───────────────┐  ┌───────────────┐  ┌───────────────┐
        │  Ingest       │  │  Discovery    │  │  Test Engine  │
        │  Module       │  │  Module       │  │               │
        └───────────────┘  └───────────────┘  └───────────────┘
                │                  │                  │
                ▼                  ▼                  ▼
        ┌───────────────────────────────────────────────────┐
        │              Position Extractor                    │
        │  • Path params    • Query params   • Headers      │
        │  • Cookies        • Body fields    • GraphQL vars │
        └───────────────────────────────────────────────────┘
                                    │
                                    ▼
        ┌─────────────────────────────────────────────────────┐
        │            Vulnerability Test Library                │
        │  ┌──────────────┐  ┌──────────────┐  ┌──────────┐  │
        │  │  Auth Tests  │  │  Injection   │  │  GraphQL │  │
        │  │  • JWT (23)  │  │  • SQLi      │  │  Tests   │  │
        │  │  • OAuth2    │  │  • XSS       │  │          │  │
        │  │  • SAML      │  │  • XXE       │  │          │  │
        │  │  • Session   │  │  • SSRF      │  │          │  │
        │  └──────────────┘  └──────────────┘  └──────────┘  │
        └─────────────────────────────────────────────────────┘
                                    │
                                    ▼
        ┌─────────────────────────────────────────────────────┐
        │             Behavior Analyzer                        │
        │  • Response timing    • Error patterns               │
        │  • Status anomalies   • OOB interactions            │
        │  • Header changes     • Cookie modifications        │
        │  • Confidence scoring • Anomaly detection           │
        └─────────────────────────────────────────────────────┘
                                    │
                    ┌───────────────┼───────────────┐
                    ▼               ▼               ▼
        ┌───────────────┐  ┌───────────────┐  ┌───────────────┐
        │  Adaptive     │  │  Payload      │  │  Reporting    │
        │  Engine       │  │  Updater      │  │  Module       │
        │  • Learning   │  │  • GitHub     │  │  • JSON       │
        │  • Mutation   │  │  • RSS feeds  │  │  • Markdown   │
        │  • Pivoting   │  │  • CVE intake │  │  • HTML       │
        └───────────────┘  └───────────────┘  └───────────────┘
```

## Module Responsibilities

### 1. MCP Server (`server.py`)
- Exposes 7 MCP tools via stdio
- Handles tool invocation and response marshalling
- Manages global state (config, test plans, findings)
- Provides JSON-formatted responses

### 2. Ingest Module (`ingest.py`)
**Parsers**:
- `OpenAPIParser`: OpenAPI v2/v3, Swagger
- `GraphQLParser`: SDL, introspection results
- `HARParser`: HTTP Archive files
- `CurlParser`: cURL commands
- `RawHTTPParser`: Raw HTTP requests
- `IngestOrchestrator`: Auto-detection and routing

**Outputs**:
- Normalized `EndpointInfo` list
- Discovered `AuthFlow` objects
- Metadata and warnings

### 3. Discovery Module (`discovery.py`)
**Position Extractor**:
- Analyzes endpoint parameters
- Infers data types (string, int, UUID, email, etc.)
- Extracts validation constraints
- Assigns sensitivity levels
- Generates benign filler values

**Position Types**:
- Path parameters
- Query parameters
- Headers
- Cookies
- JSON body fields (JSONPath)
- XML body fields (XPath)
- GraphQL variables/operations/directives
- Multipart form fields

### 4. Auth Testing (`auth/jwt_tests.py`)
**JWT Test Vectors (23)**:
1-3. Algorithm confusion (none, NONE, nOnE)
4. Expired token
5. Future nbf
6-7. Claim tampering (sub, role)
8-9. Empty/missing signature
10-12. KID attacks (null, traversal, SQLi)
13-14. Weak HMAC secrets
15. RS256→HS256 confusion
16-17. Malformed tokens
18-19. Audience/issuer tampering
20. JTI replay
21-22. X5U/JKU injection (SSRF)
23. Embedded JWK

**OAuth2 Tests**:
- Token replay
- Scope escalation
- Refresh token misuse
- Flow-specific vulnerabilities

### 5. Vulnerability Tests (`vulnerabilities/`)
**SQL Injection**:
- Error-based (DB fingerprinting)
- Boolean blind (conditional logic)
- Time-based blind (sleep/benchmark)
- Stacked queries
- Union-based extraction
- DB-specific payloads

**XSS**:
- Reflected XSS
- Stored XSS
- DOM-based XSS
- Context-aware payloads
- Filter bypass techniques

**XXE**:
- External entity injection
- Parameter entity attacks
- Protocol handlers (file://, http://)
- DTD attacks

**GraphQL**:
- Introspection abuse
- Depth/complexity DoS
- Batching attacks
- Injection in arguments

**SSRF**:
- HTTP/HTTPS callbacks
- DNS exfiltration
- Cloud metadata endpoints
- Internal port scanning

### 6. Behavior Analyzer (`behavior/analyzer.py`)
**Signals Captured**:
- Request/response timestamps
- Timing deltas (for blind attacks)
- Status codes
- Error messages and stack traces
- Header modifications
- Cookie changes
- Redirect chains
- Created resource IDs
- OOB interactions (DNS, HTTP)

**Confidence Scoring**:
- Minimal: Weak indicators
- Low: Some evidence
- Medium: Multiple correlated signals
- High: Strong evidence
- Confirmed: Definitive proof

**Anomaly Detection**:
- Baseline timing comparison
- Error pattern matching
- Status code deviation
- Header injection detection

### 7. Adaptive Engine (`adaptive/`)
**Learning Table**:
- Per-position payload success rates
- False positive tracking
- Schema breaker detection
- Timing optimization

**Mutation Strategies**:
- Prefix injection
- Suffix injection
- Infix injection (mid-string)
- Full replacement
- Wrapper injection

**Beam Search**:
- Maintain top-K candidates
- Mutation scoring
- Budget-constrained exploration

### 8. Payload Updater (`payloads/`)
**Sources**:
- GitHub repositories (SecLists, PayloadsAllTheThings)
- RSS/Atom feeds (security blogs)
- CVE databases
- OWASP Testing Guide

**Workflow**:
1. Fetch from sources (with etag caching)
2. Parse new payloads
3. Sandbox validation (safe test environment)
4. Production merge (if validated)
5. Changelog generation

### 9. CVE Onboarding (`cve_pipeline.py`)
**Auto-generation**:
1. Monitor CVE feeds
2. Extract vulnerability details
3. Generate test recipe
4. Create smoke tests (non-destructive)
5. Create full tests (controlled)
6. Assign severity and tags

### 10. Reporting (`reporting/`)
**Formats**:
- **JSON**: Full machine-readable
- **Markdown**: GitHub-friendly
- **HTML**: Interactive with charts
- **Burp**: Import into Burp Suite

**Content**:
- Executive summary
- Severity distribution
- Detailed findings
- Remediation guidance
- Code examples
- OWASP/CWE mappings
- CVSS scores

### 11. Integrations (`integrations/`)
**Slack**: Webhook notifications
**Jira**: Automatic issue creation
**GitHub**: Issue/PR creation
**SIEM**: Event export (JSON, CEF)

## Data Flow

### Test Execution Flow

```
1. Ingest API Descriptor
   ↓
2. Parse & Normalize
   ↓
3. Extract Positions
   ↓
4. Generate Test Plan (prioritized)
   ↓
5. Execute Tests
   │
   ├─→ Build HTTP request
   │   ↓
   ├─→ Inject payload
   │   ↓
   ├─→ Send request
   │   ↓
   ├─→ Capture response
   │   ↓
   ├─→ Analyze behavior
   │   ↓
   └─→ Score confidence
   ↓
6. Collect Findings
   ↓
7. Adaptive Learning
   ↓
8. Generate Report
   ↓
9. Integrate (Slack/Jira/etc.)
```

### Adaptive Learning Loop

```
Test Execution
   ↓
Capture Result (success/fail/inconclusive)
   ↓
Update Learning Table
   ↓
If inconclusive:
   ├─→ Generate mutations
   ├─→ Score mutations
   ├─→ Select top K
   └─→ Re-test
   ↓
If confident: Record finding
```

## Security & Safety

### Scope Enforcement
- Allowlist: Must match at least one pattern
- Denylist: Must not match any pattern
- Regex/wildcard support

### Rate Limiting
- Token bucket algorithm
- Per-host tracking
- Configurable burst

### Non-Destructive Mode
- GET, POST (non-modifying)
- No DELETE, no state changes
- Read-only operations

### Secret Redaction
- Auto-detect tokens/keys
- Redact in logs and reports
- Preserve for replay

## Extensibility

### Adding New Tests
1. Create payload templates
2. Define expected signals
3. Add to vulnerability library
4. Register with test engine

### Custom Parsers
1. Implement `Parser` interface
2. Return `IngestResult`
3. Register with orchestrator

### Custom Reports
1. Implement `Reporter` interface
2. Generate from `SecurityReport`
3. Register format

## Performance

### Optimization Strategies
- Concurrent request execution
- Connection pooling
- Response streaming
- Lazy evaluation
- Caching (positions, baseline responses)

### Scalability
- Stateless design (except learning table)
- Horizontal scaling (multiple workers)
- Queue-based distribution

## Configuration

### Environment Variables
- `MCP_ORCHESTRATOR_CONFIG`: Config file path
- `MCP_ORCHESTRATOR_LOG_LEVEL`: Logging level
- `MCP_ORCHESTRATOR_OOB_URL`: OOB callback URL

### Config Precedence
1. CLI arguments (highest)
2. Environment variables
3. Config file
4. Defaults (lowest)

## Future Enhancements

### Planned Features
- [ ] WebSocket testing
- [ ] gRPC/Protobuf support
- [ ] Browser automation (Selenium/Playwright)
- [ ] Distributed scanning
- [ ] ML-based payload optimization
- [ ] Custom DSL for test recipes
- [ ] Real-time dashboard
- [ ] Continuous monitoring mode

### Research Areas
- Deep learning for anomaly detection
- Graph neural networks for API modeling
- Reinforcement learning for adaptive testing
- Fuzzing integration
