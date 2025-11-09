# 🚀 GETTING STARTED - MCP-Orchestrator

**System Status**: ✅ **INSTALLED AND READY**

---

## ✅ What's Done

1. ✅ Python 3.11 installed
2. ✅ Virtual environment created (`.venv`)
3. ✅ All dependencies installed (MCP SDK, Pydantic, httpx, etc.)
4. ✅ MCP-Orchestrator package installed in editable mode
5. ✅ Configuration file created (`config.yaml`)
6. ✅ Integration tests passed (4/5 - 80%)

---

## 📋 Next Steps

### Step 1: Configure MCP Client

You need to connect an MCP-compatible client to use the security testing tools.

#### Option A: Claude Desktop (Recommended)

Edit `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "mcp-orchestrator": {
      "command": "/usr/local/Homebrew/bin/python3.11",
      "args": ["-m", "mcp_orchestrator.server"],
      "env": {
        "MCP_ORCHESTRATOR_CONFIG": "/Users/narendra/Documents/APISec/config.yaml"
      }
    }
  }
}
```

**Then restart Claude Desktop.**

#### Option B: Cline (VS Code Extension)

1. Install Cline extension in VS Code
2. Open Cline Settings (⚙️ icon)
3. Go to "MCP Servers"
4. Add new server:

```json
{
  "mcp-orchestrator": {
    "command": "/usr/local/Homebrew/bin/python3.11",
    "args": ["-m", "mcp_orchestrator.server"],
    "env": {
      "MCP_ORCHESTRATOR_CONFIG": "/Users/narendra/Documents/APISec/config.yaml"
    }
  }
}
```

5. Restart VS Code

---

### Step 2: Test the Installation

After configuring your MCP client, test with these commands:

#### Test 1: Ingest Sample API

In Claude/Cline, ask:

```
Use ingest_api to parse the sample API in examples/sample-api.json
```

**Expected Result**: List of 4-5 endpoints with JWT auth flow detected

#### Test 2: Generate Test Plan

```
Use generate_test_plan to create a security test plan with max_tests=50 
focusing on jwt-vuln, idor, and sqli
```

**Expected Result**: Prioritized list of 50 security tests

#### Test 3: View JWT Test Vectors

```
Show me the JWT test vectors available for testing
```

**Expected Result**: List of 23 JWT vulnerability test vectors

---

### Step 3: Test Your Own API

#### From OpenAPI Spec

```
Use ingest_api with this OpenAPI spec:
<paste your OpenAPI JSON/YAML>
```

#### From cURL Command

```
Use ingest_api with descriptor_type=curl and this cURL command:
curl -X POST https://api.example.com/login \
  -H "Content-Type: application/json" \
  -d '{"username":"test","password":"test123"}'
```

#### From HAR File

```
Use ingest_api with descriptor_type=har and the contents of my HAR file
```

---

## 🛠️ Manual Testing (Terminal)

### Activate Environment

```bash
cd /Users/narendra/Documents/APISec
source .venv/bin/activate
```

### Test Python Import

```bash
python -c "from mcp_orchestrator.server import app; print('✓ Working!')"
```

### Test JWT Vectors

```bash
python -c "
from mcp_orchestrator.auth.jwt_tests import JWTTestVectors
vectors = JWTTestVectors.get_test_vectors()
print(f'✓ {len(vectors)} JWT test vectors loaded')
for v in vectors[:3]:
    print(f'  - {v.id}: {v.description}')
"
```

### Test OpenAPI Parsing

```bash
python -c "
from mcp_orchestrator.ingest import IngestOrchestrator
import json

with open('examples/sample-api.json') as f:
    api = json.load(f)

result = IngestOrchestrator.ingest(api, 'openapi', 'https://api.example.com')
print(f'✓ Found {len(result.endpoints)} endpoints')
print(f'✓ Found {len(result.auth_flows)} auth flows')
"
```

---

## 📚 Available Tools

Once connected to an MCP client, you'll have access to these 7 tools:

| Tool | Purpose | Example Use |
|------|---------|-------------|
| **ingest_api** | Parse API specs (OpenAPI, GraphQL, HAR, cURL) | Parse Swagger files |
| **discover_positions** | Extract testable input positions | Find all vulnerable parameters |
| **generate_test_plan** | Create prioritized test plan | Generate 100 security tests |
| **execute_tests** | Run security tests | Execute tests in safe mode |
| **generate_report** | Create security reports | Generate JSON/HTML reports |
| **configure_scanner** | Update scanner config | Set rate limits, scope |
| **update_payloads** | Fetch new payloads | Update from SecLists |

---

## 🎯 Example Workflow

### 1. Parse API

```
Use ingest_api to parse my OpenAPI spec at examples/sample-api.json
```

### 2. Generate Test Plan

```
Use generate_test_plan with max_tests=100, focusing on:
- jwt-vuln (JWT vulnerabilities)
- idor (Insecure Direct Object References)
- sqli (SQL Injection)
- authz-bypass (Authorization bypass)
```

### 3. Configure Scanner

```
Use configure_scanner to:
- Set allowlist to ["api.example.com"]
- Set rate_limit to 5 requests/second
- Enable destructive_tests=false (safe mode)
```

### 4. Execute Tests

```
Use execute_tests with mode=safe and max_concurrency=3
```

### 5. Generate Report

```
Use generate_report with formats: ["json", "html", "markdown"]
and output_dir: "reports"
```

---

## ⚙️ Configuration

Edit `config.yaml` to customize:

### Basic Settings

```yaml
mode: safe  # safe, aggressive, or destructive
rate_limit: 10  # requests per second
max_concurrency: 5  # parallel tests
time_budget_ms: 300000  # 5 minutes
```

### Scope Control

```yaml
scope:
  allowlist:
    - "api.example.com"
    - "*.yourcompany.com"
  denylist:
    - "*.production.com"
```

### Behavior Analysis

```yaml
behavior:
  timing_threshold: 2.0  # seconds
  error_patterns:
    - "SQL syntax"
    - "stack trace"
    - "exception"
```

### OOB Listener (for SSRF/XXE testing)

```yaml
oob_listener:
  enabled: true
  dns_domain: "your-burp-collaborator.com"
  http_endpoint: "https://your-oob-server.com"
```

---

## 🔐 Security Reminders

⚠️ **CRITICAL**:

1. **Authorization Required**: Only test systems you own or have written permission to test
2. **Safe Mode**: Default mode is `safe` - no destructive operations
3. **Scope Control**: Always configure allowlist before testing
4. **Rate Limiting**: Respect rate limits to avoid DoS
5. **Secret Redaction**: Secrets are automatically redacted in reports

---

## 📖 Documentation

- **README.md**: Complete overview and features
- **USAGE.md**: Detailed tool reference (600+ lines)
- **ARCHITECTURE.md**: System design and module details
- **QUICKSTART.md**: Installation and first test
- **SYSTEM_STATUS.md**: Complete deployment verification
- **examples/usage_examples.py**: Code examples

---

## 🐛 Troubleshooting

### MCP Client Can't Connect

1. Check Python path in config:
   ```bash
   which python3.11
   # Should output: /usr/local/Homebrew/bin/python3.11
   ```

2. Test server manually:
   ```bash
   source .venv/bin/activate
   python -m mcp_orchestrator.server
   ```

3. Check logs in MCP client (usually in Settings > Logs)

### Import Errors

```bash
# Reinstall in virtual environment
source .venv/bin/activate
pip install -e .
```

### Configuration Not Loading

```bash
# Verify config file exists and is valid YAML
cat config.yaml
python -c "import yaml; yaml.safe_load(open('config.yaml'))"
```

---

## 🎉 You're Ready!

Your MCP-Orchestrator is fully installed and configured. 

**Next action**: Configure your MCP client (Claude Desktop or Cline) using the instructions above, then start testing!

---

**Need help?** Check the documentation files or run:

```bash
source .venv/bin/activate
python -c "from mcp_orchestrator import __version__; print(f'MCP-Orchestrator v{__version__}')"
```
