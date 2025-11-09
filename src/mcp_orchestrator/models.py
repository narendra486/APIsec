"""
Core data models for MCP-Orchestrator
Comprehensive security testing framework types using Pydantic
"""

from datetime import datetime
from enum import Enum
from typing import Any, Literal, Optional
from pydantic import BaseModel, Field, HttpUrl


# ============================================================================
# ENUMS
# ============================================================================

class PositionType(str, Enum):
    PATH = "path"
    QUERY = "query"
    HEADER = "header"
    COOKIE = "cookie"
    BODY_JSON = "body-json"
    BODY_XML = "body-xml"
    BODY_FORM = "body-form"
    BODY_MULTIPART = "body-multipart"
    GRAPHQL_OPERATION = "graphql-operation"
    GRAPHQL_VARIABLE = "graphql-variable"
    GRAPHQL_FRAGMENT = "graphql-fragment"
    GRAPHQL_DIRECTIVE = "graphql-directive"


class DataType(str, Enum):
    STRING = "string"
    NUMBER = "number"
    INTEGER = "integer"
    BOOLEAN = "boolean"
    EMAIL = "email"
    UUID = "uuid"
    URL = "url"
    DATE = "date"
    DATETIME = "datetime"
    BINARY = "binary"
    ENUM = "enum"
    ARRAY = "array"
    OBJECT = "object"
    REGEX = "regex"


class SensitivityLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AuthType(str, Enum):
    OAUTH2 = "oauth2"
    JWT = "jwt"
    SAML = "saml"
    BASIC = "basic"
    APIKEY = "apikey"
    COOKIE = "cookie"
    CUSTOM = "custom"


class OAuth2FlowType(str, Enum):
    AUTHORIZATION_CODE = "authorization_code"
    IMPLICIT = "implicit"
    CLIENT_CREDENTIALS = "client_credentials"
    PASSWORD = "password"
    REFRESH_TOKEN = "refresh_token"


class VulnerabilityType(str, Enum):
    SQLI = "sqli"
    XSS = "xss"
    XXE = "xxe"
    SSRF = "ssrf"
    IDOR = "idor"
    AUTHZ_BYPASS = "authz-bypass"
    AUTHN_BYPASS = "authn-bypass"
    JWT_VULN = "jwt-vuln"
    OAUTH_VULN = "oauth-vuln"
    SESSION_VULN = "session-vuln"
    COMMAND_INJECTION = "command-injection"
    PATH_TRAVERSAL = "path-traversal"
    DESERIALIZATION = "deserialization"
    GRAPHQL_INJECTION = "graphql-injection"
    GRAPHQL_DOS = "graphql-dos"
    GRAPHQL_INTROSPECTION = "graphql-introspection"
    PRIVILEGE_ESCALATION = "privilege-escalation"
    CSRF = "csrf"
    CORS_MISCONFIGURATION = "cors-misconfiguration"
    SECURITY_MISCONFIGURATION = "security-misconfiguration"
    # New vulnerability types from competitive analysis
    OAUTH_REDIRECT_URI_BYPASS = "oauth-redirect-uri-bypass"
    OAUTH_STATE_CSRF = "oauth-state-csrf"
    OAUTH_CODE_REUSE = "oauth-code-reuse"
    OAUTH_PKCE_BYPASS = "oauth-pkce-bypass"
    OAUTH_SCOPE_ESCALATION = "oauth-scope-escalation"
    SAML_SIGNATURE_WRAPPING = "saml-signature-wrapping"
    SAML_ASSERTION_MANIPULATION = "saml-assertion-manipulation"
    SAML_REPLAY_ATTACK = "saml-replay-attack"
    SAML_XXE = "saml-xxe"
    MFA_BYPASS = "mfa-bypass"
    MFA_TOKEN_REUSE = "mfa-token-reuse"
    MFA_RATE_LIMIT_BYPASS = "mfa-rate-limit-bypass"
    SESSION_FIXATION = "session-fixation"
    SESSION_FLAG_MISSING = "session-flag-missing"
    AUTHORIZATION_FORCED_BROWSING = "authorization-forced-browsing"
    AUTHORIZATION_HTTP_METHOD_BYPASS = "authorization-http-method-bypass"
    AUTHORIZATION_PARAMETER_POLLUTION = "authorization-parameter-pollution"
    AUTHORIZATION_HEADER_MANIPULATION = "authorization-header-manipulation"
    MASS_ASSIGNMENT = "mass-assignment"
    SSTI = "ssti"
    SSTI_JINJA2 = "ssti-jinja2"
    SSTI_TWIG = "ssti-twig"
    SSTI_FREEMARKER = "ssti-freemarker"
    NOSQL_INJECTION = "nosql-injection"
    NOSQL_MONGODB = "nosql-mongodb"
    NOSQL_REDIS = "nosql-redis"
    NOSQL_COUCHDB = "nosql-couchdb"
    NOSQL_CASSANDRA = "nosql-cassandra"
    LDAP_INJECTION = "ldap-injection"
    LDAP_BLIND = "ldap-blind"
    COMMAND_INJECTION_BLIND = "command-injection-blind"
    COMMAND_INJECTION_OOB = "command-injection-oob"
    XXE_BLIND = "xxe-blind"
    XXE_OOB = "xxe-oob"
    XXE_FILE_UPLOAD = "xxe-file-upload"
    GRAPHQL_BATCH_ATTACK = "graphql-batch-attack"
    GRAPHQL_DEPTH_LIMIT = "graphql-depth-limit"
    GRAPHQL_MUTATION_INJECTION = "graphql-mutation-injection"
    API_SCHEMA_EXPOSURE = "api-schema-exposure"
    API_RATE_LIMIT_BYPASS = "api-rate-limit-bypass"
    REST_VERB_TAMPERING = "rest-verb-tampering"
    REST_CONTENT_TYPE_CONFUSION = "rest-content-type-confusion"
    BUSINESS_LOGIC_STEP_SKIP = "business-logic-step-skip"
    BUSINESS_LOGIC_RACE_CONDITION = "business-logic-race-condition"
    BUSINESS_LOGIC_PRICE_MANIPULATION = "business-logic-price-manipulation"
    FILE_UPLOAD_EXTENSION_BYPASS = "file-upload-extension-bypass"
    FILE_UPLOAD_MIME_BYPASS = "file-upload-mime-bypass"
    FILE_UPLOAD_ZIP_SLIP = "file-upload-zip-slip"
    SECURITY_HEADER_MISSING = "security-header-missing"
    DEFAULT_CREDENTIALS = "default-credentials"
    DIRECTORY_LISTING = "directory-listing"
    ERROR_MESSAGE_DISCLOSURE = "error-message-disclosure"
    # Additional vulnerability types
    API_MISCONFIGURATION = "api-misconfiguration"
    API_ENDPOINT_EXPOSURE = "api-endpoint-exposure"
    API_PARAMETER_POLLUTION = "api-parameter-pollution"
    API_EXCESSIVE_DATA_EXPOSURE = "api-excessive-data-exposure"
    API_VERSIONING_ISSUE = "api-versioning-issue"
    API_CORS_MISCONFIGURATION = "api-cors-misconfiguration"
    REST_INFO_DISCLOSURE = "rest-info-disclosure"
    REST_XST = "rest-xst"
    REST_HEADER_INJECTION = "rest-header-injection"
    REST_CHARSET_CONFUSION = "rest-charset-confusion"
    REST_AUTHORIZATION_BYPASS = "rest-authorization-bypass"
    REST_MASS_ASSIGNMENT = "rest-mass-assignment"
    REST_PROTOCOL_DOWNGRADE = "rest-protocol-downgrade"
    BUSINESS_LOGIC_WORKFLOW_BYPASS = "business-logic-workflow-bypass"
    BUSINESS_LOGIC_STATE_MANIPULATION = "business-logic-state-manipulation"
    BUSINESS_LOGIC_IDEMPOTENCY = "business-logic-idempotency"
    BUSINESS_LOGIC_PAYMENT_BYPASS = "business-logic-payment-bypass"
    BUSINESS_LOGIC_APPROVAL_BYPASS = "business-logic-approval-bypass"
    BUSINESS_LOGIC_SESSION_FIXATION = "business-logic-session-fixation"
    BUSINESS_LOGIC_ASYNC_RACE = "business-logic-async-race"
    BUSINESS_LOGIC_TRANSACTION_INTEGRITY = "business-logic-transaction-integrity"
    BUSINESS_LOGIC_DISCOUNT_ABUSE = "business-logic-discount-abuse"
    BUSINESS_LOGIC_POINTS_MANIPULATION = "business-logic-points-manipulation"
    BUSINESS_LOGIC_QUANTITY_MANIPULATION = "business-logic-quantity-manipulation"
    BUSINESS_LOGIC_INTEGER_OVERFLOW = "business-logic-integer-overflow"
    BUSINESS_LOGIC_INTEGER_UNDERFLOW = "business-logic-integer-underflow"
    BUSINESS_LOGIC_CURRENCY_MANIPULATION = "business-logic-currency-manipulation"
    BUSINESS_LOGIC_REFUND_ABUSE = "business-logic-refund-abuse"
    BUSINESS_LOGIC_BALANCE_MANIPULATION = "business-logic-balance-manipulation"
    BUSINESS_LOGIC_PRECISION_ERROR = "business-logic-precision-error"
    BUSINESS_LOGIC_ROUNDING_ERROR = "business-logic-rounding-error"
    FILE_UPLOAD_MAGIC_BYTES = "file-upload-magic-bytes"
    FILE_UPLOAD_NULL_BYTE = "file-upload-null-byte"
    FILE_UPLOAD_POLYGLOT = "file-upload-polyglot"
    FILE_UPLOAD_PATH_TRAVERSAL = "file-upload-path-traversal"
    FILE_UPLOAD_XSS = "file-upload-xss"
    FILE_UPLOAD_XXE = "file-upload-xxe"
    FILE_UPLOAD_SIZE_BYPASS = "file-upload-size-bypass"
    FILE_UPLOAD_CONTENT_SNIFFING = "file-upload-content-sniffing"
    FILE_UPLOAD_MALICIOUS_CONTENT = "file-upload-malicious-content"
    FILE_UPLOAD_BOMB = "file-upload-bomb"
    FILE_UPLOAD_SYMLINK = "file-upload-symlink"
    FILE_UPLOAD_EXECUTION = "file-upload-execution"
    # Additional injection and web vulnerabilities
    XPATH_INJECTION = "xpath-injection"
    XSLT_INJECTION = "xslt-injection"
    CRLF_INJECTION = "crlf-injection"
    OPEN_REDIRECT = "open-redirect"
    WEBSOCKET_VULN = "websocket-vuln"
    PROTOTYPE_POLLUTION = "prototype-pollution"
    EL_INJECTION = "el-injection"
    CACHE_POISONING = "cache-poisoning"
    HPP = "hpp"
    SOFTWARE_SUPPLY_CHAIN_FAILURES = "software-supply-chain-failures"
    MISHANDLING_OF_EXCEPTIONAL_CONDITIONS = "mishandling-of-exceptional-conditions"


class EncodingType(str, Enum):
    NONE = "none"
    URL = "url"
    DOUBLE_URL = "double-url"
    HTML = "html"
    BASE64 = "base64"
    HEX = "hex"
    UNICODE = "unicode"
    JSON_ESCAPE = "json-escape"


class MutationStrategyType(str, Enum):
    PREFIX = "prefix"
    SUFFIX = "suffix"
    INFIX = "infix"
    REPLACE = "replace"
    WRAP = "wrap"


class SeverityLevel(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ConfidenceLevel(str, Enum):
    MINIMAL = "minimal"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    CONFIRMED = "confirmed"


class DescriptorType(str, Enum):
    OPENAPI = "openapi"
    SWAGGER = "swagger"
    WSDL = "wsdl"
    GRAPHQL = "graphql"
    HAR = "har"
    RAW = "raw"


# ============================================================================
# BASE MODELS
# ============================================================================

class ValidationConstraint(BaseModel):
    pattern: Optional[str] = None
    min_length: Optional[int] = None
    max_length: Optional[int] = None
    minimum: Optional[float] = None
    maximum: Optional[float] = None
    enum: Optional[list[str]] = None
    format: Optional[str] = None


class Position(BaseModel):
    """Represents an input position in an API request"""
    id: str
    endpoint: str
    method: str
    position_type: PositionType
    path: str  # JSONPath, XPath, or literal path
    name: str
    inferred_type: DataType
    validation_constraints: Optional[ValidationConstraint] = None
    sensitivity_level: SensitivityLevel
    benign_filler: Optional[Any] = None
    parent_context: Optional[str] = None
    required: bool = True


# ============================================================================
# AUTH MODELS
# ============================================================================

class AuthEndpoints(BaseModel):
    authorize: Optional[str] = None
    token: Optional[str] = None
    refresh: Optional[str] = None
    revoke: Optional[str] = None
    introspect: Optional[str] = None
    metadata: Optional[str] = None


class AuthFlow(BaseModel):
    type: AuthType
    endpoints: AuthEndpoints
    parameters: dict[str, Any] = Field(default_factory=dict)
    scopes: Optional[list[str]] = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class JWTHeader(BaseModel):
    alg: str
    typ: Optional[str] = "JWT"
    kid: Optional[str] = None
    extra: dict[str, Any] = Field(default_factory=dict)


class JWTClaims(BaseModel):
    iss: Optional[str] = None
    sub: Optional[str] = None
    aud: Optional[str | list[str]] = None
    exp: Optional[int] = None
    iat: Optional[int] = None
    nbf: Optional[int] = None
    jti: Optional[str] = None
    extra: dict[str, Any] = Field(default_factory=dict)


# ============================================================================
# VULNERABILITY TEST MODELS
# ============================================================================

class PayloadTemplate(BaseModel):
    id: str
    vulnerability_type: VulnerabilityType
    payload: str
    encodings: list[EncodingType]
    mutation_strategies: list[MutationStrategyType]
    applicable_positions: list[PositionType]
    expected_signals: list[str]
    db_specific: Optional[list[str]] = None  # ['mysql', 'postgresql', 'mssql', 'oracle']
    tags: list[str] = Field(default_factory=list)
    severity: SeverityLevel
    description: str


# ============================================================================
# TEST VECTOR MODELS (NEW - For v2.0.0)
# ============================================================================

class TestVectorPosition(BaseModel):
    """Position in request where payload should be injected"""
    type: PositionType
    name: str
    value_prefix: Optional[str] = None
    value_suffix: Optional[str] = None


class TestVectorPayload(BaseModel):
    """Payload template with variants"""
    base: str
    variants: list[str] = Field(default_factory=list)
    encoding: Optional[str] = None


class TestVectorEvidence(BaseModel):
    """Expected evidence for vulnerability detection"""
    indicators: list[str] = Field(default_factory=list)
    false_positive_indicators: Optional[list[str]] = None
    confidence: ConfidenceLevel = ConfidenceLevel.MEDIUM


class TestVector(BaseModel):
    """Complete test vector specification"""
    id: str
    name: str
    description: str
    vuln_type: VulnerabilityType
    position: TestVectorPosition
    payload: TestVectorPayload
    expected_evidence: TestVectorEvidence
    sensitivity: SensitivityLevel
    remediation: str
    references: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)


class TestCase(BaseModel):
    id: str
    endpoint: str
    method: str
    position: Position
    vulnerability_type: VulnerabilityType
    payload: str
    encoding: EncodingType
    mutation_strategy: MutationStrategyType
    expected_signal: str
    rationale: str
    priority: int
    destructive: bool = False
    template: Optional[PayloadTemplate] = None


# ============================================================================
# BEHAVIOR ANALYSIS MODELS
# ============================================================================

class OOBInteraction(BaseModel):
    type: Literal["dns", "http", "https", "smtp", "ftp"]
    timestamp: float
    source: str
    target: str
    payload: Optional[str] = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class BehaviorSignal(BaseModel):
    request_time: float
    response_time: float
    timing_delta: float
    status_code: int
    headers: dict[str, str]
    body_length: int
    error_strings: list[str] = Field(default_factory=list)
    stack_traces: list[str] = Field(default_factory=list)
    new_cookies: list[str] = Field(default_factory=list)
    set_cookie_differences: list[str] = Field(default_factory=list)
    redirect_chain: list[str] = Field(default_factory=list)
    created_resource_ids: list[str] = Field(default_factory=list)
    oob_interactions: list[OOBInteraction] = Field(default_factory=list)
    anomaly_indicators: list[str] = Field(default_factory=list)


class HTTPRequest(BaseModel):
    method: str
    url: str
    headers: dict[str, str]
    body: Optional[str] = None
    timestamp: float
    curl: Optional[str] = None


class HTTPResponse(BaseModel):
    status_code: int
    status_text: str
    headers: dict[str, str]
    body: str
    timestamp: float
    duration_ms: float


class Evidence(BaseModel):
    request: HTTPRequest
    response: HTTPResponse
    behavior: BehaviorSignal
    confidence_level: ConfidenceLevel
    anomaly_score: float
    reproducible: bool
    poc_steps: list[str]
    side_effects: Optional[list[str]] = None


# ============================================================================
# FINDING & REMEDIATION MODELS
# ============================================================================

class CodeExample(BaseModel):
    language: str
    description: str
    vulnerable: Optional[str] = None
    secure: str


class ConfigExample(BaseModel):
    platform: str
    description: str
    vulnerable: Optional[str] = None
    secure: str


class RemediationGuidance(BaseModel):
    summary: str
    steps: list[str]
    code_examples: list[CodeExample] = Field(default_factory=list)
    config_examples: list[ConfigExample] = Field(default_factory=list)
    best_practices: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)


class Finding(BaseModel):
    id: str
    vulnerability_type: VulnerabilityType
    severity: SeverityLevel
    confidence: ConfidenceLevel
    title: str
    description: str
    endpoint: str
    method: str
    position: Position
    evidence: Evidence
    remediation: RemediationGuidance
    cvss_score: Optional[float] = None
    cwe: list[str] = Field(default_factory=list)
    owasp: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    timestamp: float = Field(default_factory=lambda: datetime.now().timestamp())


# ============================================================================
# TEST PLAN MODELS
# ============================================================================

class EndpointInfo(BaseModel):
    path: str
    method: str
    summary: Optional[str] = None
    operation_id: Optional[str] = None
    tags: list[str] = Field(default_factory=list)
    parameters: list[Any] = Field(default_factory=list)
    request_body: Optional[Any] = None
    responses: dict[str, Any] = Field(default_factory=dict)
    security: list[Any] = Field(default_factory=list)


class APIDescriptor(BaseModel):
    type: DescriptorType
    version: Optional[str] = None
    content: Any
    endpoints: list[EndpointInfo]


class ScopeConfig(BaseModel):
    allowlist: list[str] = Field(default_factory=list)
    denylist: list[str] = Field(default_factory=list)
    max_depth: Optional[int] = None
    follow_redirects: bool = True
    respect_robots_txt: bool = False


class AuthConfig(BaseModel):
    flows: list[AuthFlow] = Field(default_factory=list)
    credentials: dict[str, Any] = Field(default_factory=dict)
    tokens: dict[str, str] = Field(default_factory=dict)
    pre_auth_request: Optional[HTTPRequest] = None


class TargetSpec(BaseModel):
    base_url: str
    descriptor: Optional[APIDescriptor] = None
    auth_config: Optional[AuthConfig] = None
    scope: ScopeConfig


class TestPlan(BaseModel):
    id: str
    target: TargetSpec
    positions: list[Position]
    test_cases: list[TestCase]
    estimated_duration: int
    total_tests: int
    priority_distribution: dict[str, int] = Field(default_factory=dict)
    created: float = Field(default_factory=lambda: datetime.now().timestamp())


# ============================================================================
# ADAPTIVE ENGINE MODELS
# ============================================================================

class LearningEntry(BaseModel):
    position: str
    payload: str
    encoding: EncodingType
    success_rate: float
    last_used: float
    times_used: int
    false_positive_rate: float
    schema_breaker: bool
    metadata: dict[str, Any] = Field(default_factory=dict)


class MutationRecord(BaseModel):
    original: str
    mutated: str
    strategy: str
    success: bool
    timestamp: float


class Budget(BaseModel):
    max_attempts: int
    max_time_ms: int
    consumed: int = 0


class AdaptiveContext(BaseModel):
    target_fingerprint: str
    learning_table: dict[str, LearningEntry] = Field(default_factory=dict)
    successful_payloads: list[PayloadTemplate] = Field(default_factory=list)
    mutation_history: list[MutationRecord] = Field(default_factory=list)
    confidence_threshold: float = 0.7
    budget: Budget


# ============================================================================
# PAYLOAD UPDATE MODELS
# ============================================================================

class PayloadSource(BaseModel):
    type: Literal["github", "rss", "atom", "curated"]
    url: str
    path: Optional[str] = None
    last_fetch: Optional[float] = None
    etag: Optional[str] = None
    enabled: bool = True


class PayloadUpdate(BaseModel):
    source: PayloadSource
    timestamp: float
    new_payloads: list[PayloadTemplate] = Field(default_factory=list)
    modified_payloads: list[PayloadTemplate] = Field(default_factory=list)
    removed_payloads: list[str] = Field(default_factory=list)
    changelog: str


class CVEInfo(BaseModel):
    id: str
    description: str
    severity: SeverityLevel
    cvss_score: float
    published: str
    modified: str
    references: list[str] = Field(default_factory=list)
    affected_products: list[str] = Field(default_factory=list)
    cwe: list[str] = Field(default_factory=list)


class TestRecipe(BaseModel):
    id: str
    cve_id: Optional[str] = None
    name: str
    description: str
    applicable_positions: list[PositionType]
    payloads: list[PayloadTemplate]
    encodings: list[EncodingType]
    smoke_tests: list[TestCase] = Field(default_factory=list)
    full_tests: list[TestCase] = Field(default_factory=list)
    severity: SeverityLevel
    tags: list[str] = Field(default_factory=list)
    created: float = Field(default_factory=lambda: datetime.now().timestamp())


# ============================================================================
# CONFIGURATION MODELS
# ============================================================================

class OOBListener(BaseModel):
    dns_server: Optional[str] = None
    http_server: Optional[str] = None
    callback: str


class RateLimit(BaseModel):
    requests_per_second: int = 10
    burst_size: int = 20


class AdaptiveConfig(BaseModel):
    enabled: bool = True
    confidence_threshold: float = 0.7
    mutation_budget: int = 50
    learn_across_targets: bool = False


class ReportingConfig(BaseModel):
    formats: list[Literal["json", "markdown", "html", "burp"]] = ["json", "markdown"]
    output_dir: str = "./reports"
    redact_secrets: bool = True


class SlackIntegration(BaseModel):
    webhook_url: str


class JiraIntegration(BaseModel):
    url: str
    api_token: str
    project: str


class GitHubIntegration(BaseModel):
    repo: str
    token: str


class SIEMIntegration(BaseModel):
    endpoint: str
    api_key: str


class Integrations(BaseModel):
    slack: Optional[SlackIntegration] = None
    jira: Optional[JiraIntegration] = None
    github: Optional[GitHubIntegration] = None
    siem: Optional[SIEMIntegration] = None


class OrchestratorConfig(BaseModel):
    # Core settings
    mode: Literal["safe", "aggressive", "custom"] = "safe"
    destructive_tests: bool = False
    max_concurrency: int = 5
    time_budget_ms: int = 300000
    
    # OOB listener
    oob_listener: Optional[OOBListener] = None
    
    # Rate limiting
    rate_limit: RateLimit = Field(default_factory=RateLimit)
    
    # Scope control
    scope: ScopeConfig = Field(default_factory=ScopeConfig)
    
    # Sensitivity
    sensitivity_level: SensitivityLevel = SensitivityLevel.MEDIUM
    
    # Payload sources
    payload_sources: list[PayloadSource] = Field(default_factory=list)
    
    # Learning
    adaptive: AdaptiveConfig = Field(default_factory=AdaptiveConfig)
    
    # Reporting
    reporting: ReportingConfig = Field(default_factory=ReportingConfig)
    
    # Integrations
    integrations: Optional[Integrations] = None


# ============================================================================
# REPORT MODELS
# ============================================================================

class ReportSummary(BaseModel):
    total_tests: int
    total_findings: int
    severity_counts: dict[SeverityLevel, int] = Field(default_factory=dict)
    confidence_counts: dict[ConfidenceLevel, int] = Field(default_factory=dict)
    vulnerability_type_counts: dict[str, int] = Field(default_factory=dict)
    highest_severity: SeverityLevel
    critical_findings: list[Finding] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)


class ReportMetadata(BaseModel):
    version: str = "1.0.0"
    start_time: float
    end_time: float
    duration_ms: float
    orchestrator_version: str = "1.0.0"
    config: OrchestratorConfig


class SecurityReport(BaseModel):
    id: str
    target: TargetSpec
    test_plan: TestPlan
    findings: list[Finding]
    summary: ReportSummary
    metadata: ReportMetadata
    timestamp: float = Field(default_factory=lambda: datetime.now().timestamp())


# ============================================================================
# INGEST MODELS
# ============================================================================

class IngestResult(BaseModel):
    success: bool
    descriptor_type: str
    endpoints: list[EndpointInfo]
    auth_flows: list[AuthFlow] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class RawHTTPInput(BaseModel):
    method: str
    url: str
    headers: dict[str, str]
    body: Optional[str] = None


class CurlInput(BaseModel):
    raw: str
    parsed: Optional[RawHTTPInput] = None


class HARRequest(BaseModel):
    method: str
    url: str
    headers: list[dict[str, str]]
    post_data: Optional[dict[str, Any]] = None


class HARResponse(BaseModel):
    status: int
    headers: list[dict[str, str]]
    content: dict[str, Any]


class HAREntry(BaseModel):
    request: HARRequest
    response: HARResponse


class HARInput(BaseModel):
    log: dict[str, Any]
    entries: list[HAREntry] = Field(default_factory=list)
