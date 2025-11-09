# 🚀 Quick Start Guide - MCP-Orchestrator

## Prerequisites

- **Python 3.10 or higher**
- **pip** (Python package manager)
- **MCP-compatible client** (Claude Desktop, Cline, or similar)

## Installation (2 minutes)

### Option 1: Automated Setup (Recommended)

```bash
cd /Users/narendra/Documents/APISec
./setup.sh
```

The script will:
- ✅ Check Python version
- ✅ Create virtual environment (optional)
- ✅ Install all dependencies
- ✅ Create necessary directories
- ✅ Generate config file
- ✅ Display MCP client configuration

### Option 2: Manual Setup

```bash
cd /Users/narendra/Documents/APISec

# Install package
pip install -e .

# Or with dev dependencies
pip install -e ".[dev]"

# Create directories
mkdir -p reports payloads sandbox logs

# Copy config
cp config.example.yaml config.yaml
```

## Configure MCP Client

### For Claude Desktop

Edit `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "mcp-orchestrator": {
      "command": "python",
      "args": ["-m", "mcp_orchestrator.server"],
      "env": {
        "MCP_ORCHESTRATOR_CONFIG": "/Users/narendra/Documents/APISec/config.yaml"
      }
    }
  }
}
```

### For Cline (VS Code)

Add to Cline's MCP settings:

```json
{
  "mcp-orchestrator": {
    "command": "python",
    "args": ["-m", "mcp_orchestrator.server"]
  }
}
```

## First Test (5 minutes)

### 1. Restart your MCP client

After adding the configuration, restart Claude Desktop or VS Code.

### 2. Verify connection

Ask your MCP client:
```
What MCP tools are available for mcp-orchestrator?
```

You should see 7 tools listed.

### 3. Test with sample API

```
Use the ingest_api tool to parse the file examples/sample-api.json with base_url https://api.example.com
```

### 4. Generate test plan

```
Use generate_test_plan to create a prioritized test plan with top 10 tests
```

### 5. View results

The MCP server will return:
- Detected endpoints
- Auth flows (JWT, OAuth2)
- Top priority test cases with rationale

## Example Workflow

### Scenario: Test a REST API

**Step 1 - Ingest**
```
I have an OpenAPI spec at https://api.example.com/openapi.json
Use ingest_api to parse it
```

**Step 2 - Generate Plan**
```
Generate a test plan focusing on jwt-vuln, sqli, and xss
Show me the top 10 highest priority tests
```

**Step 3 - Review Tests**
```
Explain the rationale for the top 3 tests
```

**Step 4 - Configure Scope**
```
Configure the scanner with:
- allowlist: https://api.example.com/*
- denylist: */admin/delete*
- mode: safe
```

**Step 5 - Execute (when ready)**
```
Execute the tests in safe mode with max 5 concurrent requests
```

## Common Commands

### Parse OpenAPI
```
Use ingest_api:
  content: <paste OpenAPI JSON/YAML>
  descriptor_type: openapi
  base_url: https://api.example.com
```

### Parse cURL
```
Use ingest_api:
  content: curl -X POST https://api.example.com/users -H "Authorization: Bearer token" -d '{"name":"test"}'
  descriptor_type: curl
  base_url: https://api.example.com
```

### Generate Test Plan
```
Use generate_test_plan:
  max_tests: 100
  focus_vulnerabilities: [sqli, xss, jwt-vuln]
  top_n_preview: 10
```

### Configure Scanner
```
Use configure_scanner:
  mode: safe
  allowlist: [https://api.example.com/*]
  sensitivity_level: high
```

## Troubleshooting

### Issue: "No module named 'pydantic'"

**Solution**: Install dependencies
```bash
pip install -e .
```

### Issue: "No module named 'mcp'"

**Solution**: Install MCP SDK
```bash
pip install mcp
```

### Issue: MCP server not showing in client

**Solutions**:
1. Check config file path is correct
2. Restart MCP client completely
3. Check Python path: `which python`
4. Test server manually: `python -m mcp_orchestrator.server`

### Issue: "Import error" in server

**Solution**: Ensure you're in the right directory
```bash
cd /Users/narendra/Documents/APISec
pip install -e .
```

## Test Without MCP Client

You can test the core functionality without an MCP client:

```bash
cd /Users/narendra/Documents/APISec
python3 test_integration.py
```

This will verify:
- ✅ Data models
- ✅ Ingest parsers
- ✅ JWT test vectors
- ✅ Example API parsing

## What's Next?

### Learn More
- **README.md** - Feature overview
- **USAGE.md** - Detailed tool reference
- **ARCHITECTURE.md** - System design
- **examples/** - Code examples

### Try Advanced Features
1. **JWT Testing**: Use the 23 built-in JWT test vectors
2. **GraphQL**: Parse GraphQL schemas and test
3. **Adaptive Learning**: Enable learning mode in config
4. **OOB Detection**: Set up callback listener for SSRF/XXE
5. **Report Generation**: Export findings to JSON/Markdown/HTML

### Customize
1. Edit `config.yaml` for your environment
2. Add custom payload sources
3. Configure integrations (Slack, Jira, GitHub)
4. Adjust rate limits and concurrency

## Safety Reminders

⚠️ **CRITICAL**: Only test systems you own or have written authorization to test!

- Default mode is "safe" (non-destructive)
- Use allowlist/denylist to control scope
- Respect rate limits
- Review test plans before execution

## Support

### Documentation
- `README.md` - Overview
- `USAGE.md` - Complete tool reference
- `ARCHITECTURE.md` - Technical details
- `IMPLEMENTATION_SUMMARY.md` - What's included

### Examples
- `examples/sample-api.json` - Sample OpenAPI spec
- `examples/usage_examples.py` - Python examples
- `config.example.yaml` - Configuration reference

### Community
- File issues on GitHub
- Contribute improvements
- Share your findings (responsibly!)

---

## Quick Reference Card

| Tool | Purpose | Example |
|------|---------|---------|
| `ingest_api` | Parse API descriptor | OpenAPI, cURL, HAR |
| `discover_positions` | Extract input positions | Path, query, body |
| `generate_test_plan` | Create prioritized tests | Top 10 by risk |
| `execute_tests` | Run security scans | Safe mode |
| `generate_report` | Create reports | JSON, Markdown |
| `configure_scanner` | Set scope/limits | Allowlist, rate |
| `update_payloads` | Fetch signatures | GitHub, RSS |

---

## Success Checklist

- [ ] Python 3.10+ installed
- [ ] Dependencies installed (`pip install -e .`)
- [ ] MCP client configured
- [ ] MCP client restarted
- [ ] Sample API test successful
- [ ] Test plan generated
- [ ] Config file customized

**Ready to secure APIs! 🚀**

---

**Need Help?** Check USAGE.md for detailed examples or ARCHITECTURE.md for technical details.

**Found a Bug?** File an issue with reproduction steps.

**Want to Contribute?** Pull requests welcome!
