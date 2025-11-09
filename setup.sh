#!/bin/bash
# Setup script for MCP-Orchestrator

set -e

echo "=============================================="
echo "  MCP-Orchestrator Setup"
echo "=============================================="
echo ""

# Check Python version
echo "Checking Python version..."
python_version=$(python3 --version 2>&1 | awk '{print $2}')
echo "Found Python $python_version"

# Check if version is >= 3.10
required_version="3.10"
if [ "$(printf '%s\n' "$required_version" "$python_version" | sort -V | head -n1)" != "$required_version" ]; then 
    echo "Error: Python 3.10 or higher is required"
    exit 1
fi

echo "✓ Python version OK"
echo ""

# Create virtual environment (optional)
read -p "Create virtual environment? (recommended) [y/N]: " create_venv
if [[ $create_venv =~ ^[Yy]$ ]]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
    source venv/bin/activate
    echo "✓ Virtual environment created and activated"
    echo ""
fi

# Install package
echo "Installing MCP-Orchestrator..."
pip install -e .
echo "✓ Package installed"
echo ""

# Install dev dependencies (optional)
read -p "Install development dependencies? [y/N]: " install_dev
if [[ $install_dev =~ ^[Yy]$ ]]; then
    echo "Installing dev dependencies..."
    pip install -e ".[dev]"
    echo "✓ Dev dependencies installed"
    echo ""
fi

# Create directories
echo "Creating directories..."
mkdir -p reports
mkdir -p payloads
mkdir -p sandbox
mkdir -p logs
echo "✓ Directories created"
echo ""

# Copy example config
if [ ! -f config.yaml ]; then
    echo "Creating config.yaml from example..."
    cp config.example.yaml config.yaml
    echo "✓ Config file created"
    echo "  Please edit config.yaml with your settings"
else
    echo "config.yaml already exists, skipping..."
fi
echo ""

# Test installation
echo "Testing installation..."
python3 -c "from mcp_orchestrator import models; print('✓ Core modules imported successfully')"
python3 -c "from mcp_orchestrator.ingest import IngestOrchestrator; print('✓ Ingest module OK')"
python3 -c "from mcp_orchestrator.auth.jwt_tests import JWTTestVectors; print('✓ JWT tests OK')"
echo ""

# Display MCP configuration
echo "=============================================="
echo "  MCP Client Configuration"
echo "=============================================="
echo ""
echo "Add this to your MCP client config:"
echo ""
echo '{
  "mcpServers": {
    "mcp-orchestrator": {
      "command": "python",
      "args": ["-m", "mcp_orchestrator.server"],
      "env": {
        "MCP_ORCHESTRATOR_CONFIG": "'$(pwd)'/config.yaml"
      }
    }
  }
}'
echo ""

# Quick start guide
echo "=============================================="
echo "  Quick Start"
echo "=============================================="
echo ""
echo "1. Edit config.yaml with your settings"
echo ""
echo "2. Add MCP server to your client (Claude, Cline, etc.)"
echo ""
echo "3. Test with a sample API:"
echo "   Use the 'ingest_api' tool with examples/sample-api.json"
echo ""
echo "4. Generate test plan:"
echo "   Use the 'generate_test_plan' tool"
echo ""
echo "5. Execute tests:"
echo "   Use the 'execute_tests' tool in safe mode"
echo ""
echo "6. Generate report:"
echo "   Use the 'generate_report' tool"
echo ""

# Show next steps
echo "=============================================="
echo "  Resources"
echo "=============================================="
echo ""
echo "Documentation:"
echo "  • README.md - Overview and features"
echo "  • USAGE.md - Tool reference and workflows"
echo "  • ARCHITECTURE.md - System design"
echo ""
echo "Examples:"
echo "  • examples/sample-api.json - Sample OpenAPI spec"
echo "  • examples/usage_examples.py - Code examples"
echo ""
echo "Configuration:"
echo "  • config.yaml - Your configuration"
echo "  • config.example.yaml - Reference"
echo ""

echo "=============================================="
echo "  Setup Complete!"
echo "=============================================="
echo ""
echo "Next steps:"
echo "  1. Edit config.yaml"
echo "  2. Configure your MCP client"
echo "  3. Start testing!"
echo ""
