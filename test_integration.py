#!/usr/bin/env python3
"""
Integration test for MCP-Orchestrator
Verifies core functionality without requiring dependencies
"""

import sys
import json
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

def test_models():
    """Test data models can be imported and instantiated"""
    print("Testing models...", end=" ")
    try:
        from mcp_orchestrator.models import (
            Position,
            PositionType,
            DataType,
            SensitivityLevel,
            VulnerabilityType,
            TestCase,
            Finding,
            OrchestratorConfig,
        )
        
        # Create a position
        pos = Position(
            id="test-pos-1",
            endpoint="/api/users",
            method="GET",
            position_type=PositionType.QUERY,
            path="q",
            name="search",
            inferred_type=DataType.STRING,
            sensitivity_level=SensitivityLevel.MEDIUM,
            required=False,
        )
        
        assert pos.name == "search"
        assert pos.position_type == PositionType.QUERY
        
        # Create config
        config = OrchestratorConfig()
        assert config.mode == "safe"
        assert config.destructive_tests == False
        
        print("✓")
        return True
    except Exception as e:
        print(f"✗ - {e}")
        return False


def test_ingest():
    """Test ingestion module"""
    print("Testing ingest module...", end=" ")
    try:
        from mcp_orchestrator.ingest import (
            OpenAPIParser,
            CurlParser,
            IngestOrchestrator,
        )
        
        # Test OpenAPI parsing
        openapi_spec = {
            "openapi": "3.0.0",
            "info": {"title": "Test API", "version": "1.0.0"},
            "paths": {
                "/users": {
                    "get": {
                        "summary": "List users",
                        "parameters": [
                            {"name": "limit", "in": "query", "schema": {"type": "integer"}}
                        ],
                        "responses": {"200": {"description": "Success"}},
                    }
                }
            },
        }
        
        result = OpenAPIParser.parse(openapi_spec)
        assert result.success == True
        assert len(result.endpoints) == 1
        assert result.endpoints[0].path == "/users"
        assert result.endpoints[0].method == "GET"
        
        # Test cURL parsing
        curl_cmd = 'curl -X POST https://api.example.com/data -H "Content-Type: application/json" -d \'{"key":"value"}\''
        result = CurlParser.parse(curl_cmd)
        assert result.success == True
        assert result.endpoints[0].method == "POST"
        
        print("✓")
        return True
    except Exception as e:
        print(f"✗ - {e}")
        import traceback
        traceback.print_exc()
        return False


def test_jwt():
    """Test JWT test vectors"""
    print("Testing JWT test vectors...", end=" ")
    try:
        from mcp_orchestrator.auth.jwt_tests import JWTTestVectors
        
        vectors = JWTTestVectors.get_test_vectors()
        
        # Should have 23 test vectors
        assert len(vectors) >= 23, f"Expected 23+ vectors, got {len(vectors)}"
        
        # Check for key vectors
        vector_ids = [v.id for v in vectors]
        assert "jwt-001-alg-none" in vector_ids
        assert "jwt-006-tampered-sub" in vector_ids
        assert "jwt-021-x5u-injection" in vector_ids
        
        # Verify vector structure
        first_vector = vectors[0]
        assert first_vector.vulnerability_type.value == "jwt-vuln"
        assert len(first_vector.expected_signals) > 0
        assert first_vector.severity is not None
        
        print("✓")
        return True
    except Exception as e:
        print(f"✗ - {e}")
        import traceback
        traceback.print_exc()
        return False


def test_example_api():
    """Test parsing the example API"""
    print("Testing example API parsing...", end=" ")
    try:
        from mcp_orchestrator.ingest import OpenAPIParser
        
        # Load example API
        example_path = Path(__file__).parent / "examples" / "sample-api.json"
        with open(example_path) as f:
            spec = json.load(f)
        
        result = OpenAPIParser.parse(spec)
        assert result.success == True
        assert len(result.endpoints) > 0
        
        # Check for expected endpoints
        endpoints = {(e.path, e.method) for e in result.endpoints}
        assert ("/users/{id}", "GET") in endpoints or ("/v1/users/{id}", "GET") in endpoints
        
        # Check auth flows detected
        assert len(result.auth_flows) > 0
        
        print("✓")
        return True
    except Exception as e:
        print(f"✗ - {e}")
        import traceback
        traceback.print_exc()
        return False


def test_server_structure():
    """Test server module structure"""
    print("Testing server structure...", end=" ")
    try:
        from mcp_orchestrator.server import app
        
        # Server should exist
        assert app is not None
        
        print("✓")
        return True
    except Exception as e:
        print(f"✗ - {e}")
        return False


def main():
    """Run all tests"""
    print("=" * 60)
    print("MCP-Orchestrator Integration Tests")
    print("=" * 60)
    print()
    
    tests = [
        ("Core Models", test_models),
        ("Ingest Module", test_ingest),
        ("JWT Test Vectors", test_jwt),
        ("Example API", test_example_api),
        ("Server Structure", test_server_structure),
    ]
    
    results = []
    for name, test_func in tests:
        success = test_func()
        results.append((name, success))
    
    print()
    print("=" * 60)
    print("Test Results")
    print("=" * 60)
    
    passed = sum(1 for _, success in results if success)
    total = len(results)
    
    for name, success in results:
        status = "✓ PASS" if success else "✗ FAIL"
        print(f"{status} - {name}")
    
    print()
    print(f"Total: {passed}/{total} tests passed")
    print()
    
    if passed == total:
        print("🎉 All tests passed!")
        print()
        print("Next steps:")
        print("  1. Install dependencies: pip install -e .")
        print("  2. Configure your MCP client")
        print("  3. Start testing APIs!")
        return 0
    else:
        print("⚠️  Some tests failed. Check dependencies and setup.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
