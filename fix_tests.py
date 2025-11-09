import re

# Files to fix
files = [
    "src/mcp_orchestrator/injection/xpath_tests.py",
    "src/mcp_orchestrator/injection/xslt_tests.py",
    "src/mcp_orchestrator/injection/crlf_tests.py",
    "src/mcp_orchestrator/injection/prototype_pollution_tests.py",
    "src/mcp_orchestrator/injection/el_injection_tests.py",
    "src/mcp_orchestrator/owasp/open_redirect_tests.py",
    "src/mcp_orchestrator/api/websocket_tests.py",
    "src/mcp_orchestrator/api/cache_poisoning_tests.py",
    "src/mcp_orchestrator/api/hpp_tests.py"
]

for filepath in files:
    with open(filepath, 'r') as f:
        content = f.read()
    
    # Fix vulnerability_type -> vuln_type
    content = re.sub(r'vulnerability_type=VulnerabilityType\.', r'vuln_type=VulnerabilityType.', content)
    
    # Fix Evidence structure - remove response_codes, response_patterns, keep only indicators and extract confidence if mentioned
    # This regex finds Evidence blocks and simplifies them
    def simplify_evidence(match):
        full_block = match.group(0)
        # Extract indicators
        indicators_match = re.search(r'indicators=\[(.*?)\]', full_block, re.DOTALL)
        if indicators_match:
            indicators = indicators_match.group(1)
            # Return simplified Evidence
            return f'expected_evidence=Evidence(\n            indicators=[{indicators}],\n            confidence=ConfidenceLevel.HIGH\n        ),'
        return full_block
    
    content = re.sub(r'expected_evidence=Evidence\((.*?)\),', simplify_evidence, content, flags=re.DOTALL)
    
    # Fix sensitivity -> it should be after expected_evidence, format: sensitivity=SensitivityLevel.X,
    # Remove confidence= line if it exists in the wrong place
    content = re.sub(r',\s*confidence=ConfidenceLevel\.\w+', '', content)
    
    with open(filepath, 'w') as f:
        f.write(content)

print("Fixed all test files")
