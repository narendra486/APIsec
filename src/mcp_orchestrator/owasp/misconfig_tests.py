"""
Security Misconfiguration Testing Vectors
Directory listing, default credentials, error disclosure
"""

from ..models import (
    TestVector, VulnerabilityType, TestVectorPosition as Position, PositionType,
    TestVectorPayload as PayloadTemplate, TestVectorEvidence as Evidence, 
    ConfidenceLevel, SensitivityLevel
)

MISCONFIGURATION_VECTORS = [
    TestVector(
        id="misconfig-dir-list-001",
        name="Directory Listing Enabled",
        description="Tests if web server has directory listing enabled",
        vuln_type=VulnerabilityType.DIRECTORY_LISTING,
        position=Position(type=PositionType.PATH, name="path", value_prefix="/", value_suffix="/"),
        payload=PayloadTemplate(
            base="uploads",
            variants=["uploads", "files", "images", "documents", "static"],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["Directory listing page", "Index of /uploads"],
            confidence=ConfidenceLevel.HIGH
        ),
        sensitivity=SensitivityLevel.MEDIUM,
        remediation="Disable directory listing. Use index.html in all directories.",
        references=["https://cwe.mitre.org/data/definitions/548.html"],
        tags=["misconfiguration", "directory-listing", "information-disclosure"]
    ),
    
    TestVector(
        id="misconfig-default-002",
        name="Default Credentials Test",
        description="Tests for default or common credentials on authentication endpoints",
        vuln_type=VulnerabilityType.DEFAULT_CREDENTIALS,
        position=Position(type=PositionType.BODY_JSON, name="credentials", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base='{"username":"admin","password":"admin"}',
            variants=[
                '{"username":"admin","password":"admin"}',
                '{"username":"root","password":"root"}',
                '{"username":"administrator","password":"password"}',
            ],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["Successful authentication", "Default credentials accepted", "Access granted"],
            confidence=ConfidenceLevel.CRITICAL
        ),
        sensitivity=SensitivityLevel.LOW,
        remediation="Force credential changes on first login. Implement strong password policies.",
        references=["https://cwe.mitre.org/data/definitions/798.html"],
        tags=["misconfiguration", "default-credentials", "authentication"]
    ),
    
    TestVector(
        id="misconfig-debug-001",
        name="Debug Mode Enabled Detection",
        description="Tests if debug/development mode is exposed in production",
        vuln_type=VulnerabilityType.ERROR_MESSAGE_DISCLOSURE,
        position=Position(type=PositionType.QUERY, name="debug", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="true",
            variants=["true", "1", "on"],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["Debug information exposed", "Stack trace visible", "Internal paths revealed"],
            confidence=ConfidenceLevel.HIGH
        ),
        sensitivity=SensitivityLevel.MEDIUM,
        remediation="Disable debug mode in production. Remove debug parameters.",
        references=["https://cwe.mitre.org/data/definitions/489.html"],
        tags=["misconfiguration", "debug-mode", "information-disclosure"]
    ),
    
    TestVector(
        id="misconfig-stack-001",
        name="Stack Trace Disclosure",
        description="Tests if detailed stack traces are exposed on errors",
        vuln_type=VulnerabilityType.ERROR_MESSAGE_DISCLOSURE,
        position=Position(type=PositionType.QUERY, name="param", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="invalid_value'\"<>",
            variants=["'", "\"", "<script>", "{{7*7}}"],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["Stack trace in response", "Framework version exposed", "File paths leaked"],
            confidence=ConfidenceLevel.HIGH
        ),
        sensitivity=SensitivityLevel.LOW,
        remediation="Use generic error messages. Log detailed errors server-side only.",
        references=["https://cwe.mitre.org/data/definitions/209.html"],
        tags=["misconfiguration", "stack-trace", "error-handling"]
    ),
    
    TestVector(
        id="misconfig-backup-001",
        name="Backup File Exposure",
        description="Tests for accessible backup files (.bak, .old, .~, .swp)",
        vuln_type=VulnerabilityType.SECURITY_MISCONFIGURATION,
        position=Position(type=PositionType.PATH, name="backup_file", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="config.php.bak",
            variants=["config.php.bak", "config.php.old", "config.php~", ".config.php.swp", "config.php.txt"],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["Backup file accessible", "Source code exposed", "Credentials in backup"],
            confidence=ConfidenceLevel.HIGH
        ),
        sensitivity=SensitivityLevel.LOW,
        remediation="Remove backup files from web root. Configure web server to block access.",
        references=["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information"],
        tags=["misconfiguration", "backup-files", "information-disclosure"]
    ),
    
    TestVector(
        id="misconfig-source-001",
        name="Source Code Disclosure",
        description="Tests if source code can be accessed directly",
        vuln_type=VulnerabilityType.SECURITY_MISCONFIGURATION,
        position=Position(type=PositionType.PATH, name="source_file", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="index.php.txt",
            variants=["index.php.txt", "app.py", "server.js", "web.config", "composer.json"],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["Source code visible", "Application logic exposed", "API keys in source"],
            confidence=ConfidenceLevel.CRITICAL
        ),
        sensitivity=SensitivityLevel.MEDIUM,
        remediation="Configure server to prevent source code access. Use proper file permissions.",
        references=["https://cwe.mitre.org/data/definitions/540.html"],
        tags=["misconfiguration", "source-disclosure", "code-exposure"]
    ),
    
    TestVector(
        id="misconfig-admin-001",
        name="Admin Panel Exposure",
        description="Tests for exposed administrative interfaces",
        vuln_type=VulnerabilityType.SECURITY_MISCONFIGURATION,
        position=Position(type=PositionType.PATH, name="admin_path", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="/admin",
            variants=["/admin", "/administrator", "/admin.php", "/admin/login", "/wp-admin", "/phpmyadmin"],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["Admin panel accessible", "No IP restriction", "Weak authentication"],
            confidence=ConfidenceLevel.MEDIUM
        ),
        sensitivity=SensitivityLevel.LOW,
        remediation="Restrict admin access by IP. Use strong authentication. Implement rate limiting.",
        references=["https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration"],
        tags=["misconfiguration", "admin-panel", "access-control"]
    ),
    
    TestVector(
        id="misconfig-apidocs-001",
        name="API Documentation Leak",
        description="Tests for exposed API documentation endpoints",
        vuln_type=VulnerabilityType.SECURITY_MISCONFIGURATION,
        position=Position(type=PositionType.PATH, name="docs_path", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="/api-docs",
            variants=["/api-docs", "/swagger", "/swagger-ui", "/docs", "/api/docs", "/openapi.json", "/api/v1/docs"],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["API documentation accessible", "Endpoints disclosed", "Parameters exposed"],
            confidence=ConfidenceLevel.MEDIUM
        ),
        sensitivity=SensitivityLevel.LOW,
        remediation="Restrict documentation access. Require authentication. Remove from production.",
        references=["https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/"],
        tags=["misconfiguration", "api-docs", "information-disclosure"]
    ),
    
    TestVector(
        id="misconfig-env-001",
        name="Environment File Exposure",
        description="Tests for accessible .env and environment configuration files",
        vuln_type=VulnerabilityType.SECURITY_MISCONFIGURATION,
        position=Position(type=PositionType.PATH, name="env_file", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="/.env",
            variants=["/.env", "/.env.local", "/.env.production", "/.env.backup", "/env"],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["Environment file accessible", "API keys exposed", "Database credentials leaked"],
            confidence=ConfidenceLevel.CRITICAL
        ),
        sensitivity=SensitivityLevel.LOW,
        remediation="Block access to .env files. Move outside web root. Use proper permissions.",
        references=["https://cwe.mitre.org/data/definitions/552.html"],
        tags=["misconfiguration", "env-file", "credentials-exposure"]
    ),
    
    TestVector(
        id="misconfig-git-001",
        name="Git Directory Exposure",
        description="Tests for exposed .git directory allowing source code download",
        vuln_type=VulnerabilityType.SECURITY_MISCONFIGURATION,
        position=Position(type=PositionType.PATH, name="git_path", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="/.git/config",
            variants=["/.git/config", "/.git/HEAD", "/.git/index", "/.gitignore"],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=[".git directory accessible", "Repository can be cloned", "Source code leaked"],
            confidence=ConfidenceLevel.CRITICAL
        ),
        sensitivity=SensitivityLevel.LOW,
        remediation="Remove .git from production. Block access via web server config.",
        references=["https://cwe.mitre.org/data/definitions/540.html"],
        tags=["misconfiguration", "git-exposure", "source-disclosure"]
    ),
    
    TestVector(
        id="misconfig-db-001",
        name="Database Dump Discovery",
        description="Tests for exposed database dump files",
        vuln_type=VulnerabilityType.SECURITY_MISCONFIGURATION,
        position=Position(type=PositionType.PATH, name="db_file", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="/backup.sql",
            variants=["/backup.sql", "/database.sql", "/dump.sql", "/db.sql", "/mysql.sql", "/backup.sql.gz"],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["Database dump accessible", "User data exposed", "Complete database leaked"],
            confidence=ConfidenceLevel.CRITICAL
        ),
        sensitivity=SensitivityLevel.LOW,
        remediation="Remove database dumps from web root. Store backups securely offline.",
        references=["https://cwe.mitre.org/data/definitions/530.html"],
        tags=["misconfiguration", "database-dump", "data-leak"]
    ),
    
    TestVector(
        id="misconfig-sensitive-001",
        name="Sensitive Endpoint Exposure",
        description="Tests for unprotected sensitive endpoints",
        vuln_type=VulnerabilityType.SECURITY_MISCONFIGURATION,
        position=Position(type=PositionType.PATH, name="sensitive_path", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="/actuator/health",
            variants=["/actuator/health", "/actuator/env", "/metrics", "/health", "/status", "/info", "/debug"],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["Sensitive endpoint accessible", "System information exposed", "No authentication required"],
            confidence=ConfidenceLevel.MEDIUM
        ),
        sensitivity=SensitivityLevel.LOW,
        remediation="Require authentication for sensitive endpoints. Implement IP whitelisting.",
        references=["https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration"],
        tags=["misconfiguration", "sensitive-endpoints", "information-disclosure"]
    ),
    
    TestVector(
        id="misconfig-cors-001",
        name="Overly Permissive CORS Configuration",
        description="Tests for misconfigured CORS allowing any origin",
        vuln_type=VulnerabilityType.SECURITY_MISCONFIGURATION,
        position=Position(type=PositionType.HEADER, name="Origin", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="http://evil.com",
            variants=["http://evil.com", "null", "http://localhost"],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["Access-Control-Allow-Origin: *", "Credentials allowed", "CORS bypass"],
            confidence=ConfidenceLevel.HIGH
        ),
        sensitivity=SensitivityLevel.LOW,
        remediation="Use specific origin allowlist. Don't allow credentials with wildcard.",
        references=["https://portswigger.net/web-security/cors"],
        tags=["misconfiguration", "cors", "cross-origin"]
    ),
    
    TestVector(
        id="misconfig-cache-001",
        name="Sensitive Data in Cache Headers",
        description="Tests if sensitive responses are cacheable",
        vuln_type=VulnerabilityType.SECURITY_MISCONFIGURATION,
        position=Position(type=PositionType.HEADER, name="Cache-Control", value_prefix="", value_suffix=""),
        payload=PayloadTemplate(
            base="",
            variants=["public", "max-age=3600"],
            encoding="none"
        ),
        expected_evidence=Evidence(
            indicators=["Sensitive data cacheable", "No Cache-Control: no-store", "PII in cache"],
            confidence=ConfidenceLevel.MEDIUM
        ),
        sensitivity=SensitivityLevel.LOW,
        remediation="Set Cache-Control: no-store for sensitive endpoints. Use Pragma: no-cache.",
        references=["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/06-Testing_for_Browser_Cache_Weaknesses"],
        tags=["misconfiguration", "cache", "information-disclosure"]
    ),
]

# Total vectors: 14
