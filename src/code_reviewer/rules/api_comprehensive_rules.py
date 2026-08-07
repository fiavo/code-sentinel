"""
Comprehensive API design patterns for REST, GraphQL, WebSocket, gRPC.
"""
import re
from ..core.models import CodeIssue, Severity, IssueCategory
from ..core.rules import BaseRule


class APIComprehensiveRules(BaseRule):
    @property
    def name(self) -> str:
        return "api_comprehensive"
    @property
    def description(self) -> str:
        return "Comprehensive API design patterns"
    @property
    def category(self) -> IssueCategory:
        return IssueCategory.BEST_PRACTICE
    @property
    def severity(self) -> Severity:
        return Severity.INFO

    def check(self, file_path: str, content: str) -> list[CodeIssue]:
        issues = []
        lines = content.splitlines()
        patterns = [
            # REST API patterns
            (r"(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE)\s*\(", "HTTP method", "Good: using HTTP methods", Severity.INFO),
            (r"(?:@GetMapping|@PostMapping|@PutMapping|@DeleteMapping|@PatchMapping|@RequestMapping)", "Spring mapping", "Good: using Spring mappings", Severity.INFO),
            (r"(?:@GET|@POST|@PUT|@DELETE|@PATCH|@HEAD|@OPTIONS)", "JAX-RS annotation", "Good: using JAX-RS", Severity.INFO),
            (r"(?:@app\.(?:get|post|put|delete|patch|options|head|route))", "Flask/FastAPI route", "Good: using routes", Severity.INFO),
            (r"(?:router\.(?:get|post|put|delete|patch|options|head|route))", "Express route", "Good: using routes", Severity.INFO),
            (r"(?:app\.(?:get|post|put|delete|patch|options|head|route))", "Express route", "Good: using routes", Severity.INFO),
            (r"(?:@Controller|@RestController)", "Controller", "Good: using controllers", Severity.INFO),
            (r"(?:@Service|@Repository)", "Service/Repository", "Good: using services", Severity.INFO),
            (r"(?:@RequestBody|@ResponseBody)", "Request/Response body", "Good: using body annotations", Severity.INFO),
            (r"(?:@PathVariable|@RequestParam|@RequestHeader|@CookieValue)", "Parameter binding", "Good: binding parameters", Severity.INFO),
            (r"(?:@Valid|@Validated|@NotNull|@NotBlank|@NotEmpty)", "Validation", "Good: validating input", Severity.INFO),
            (r"(?:ResponseEntity|HttpStatus|HttpStatusCode)", "Response entity", "Good: using ResponseEntity", Severity.INFO),
            (r"(?:Response\.ok|Response\.status|Response\.entity)", "Response builder", "Good: building responses", Severity.INFO),
            (r"(?:res\.status|res\.json|res\.send|res\.redirect|res\.render)", "Express response", "Good: using Express response", Severity.INFO),
            (r"(?:c\.JSON|c\.IndentedJSON|c\.YAML|c\.XML|c\.String|c\.Data|c\.File|c\.FileAttachment|c\.Stream|c\.SSEEvent|c\.Redirect|c\.HTML|c\.IndentedJSON|c\.ProtoBuf|c\.AsciiJSON|c\.PureJSON|c\.JSONP)", "Gin response", "Good: using Gin response", Severity.INFO),
            (r"(?:render\.JSON|render\.HTML|render\.XML|render\.YAML|render\.ProtoBuf)", "Renderer", "Good: using renderers", Severity.INFO),
            # Status codes
            (r"(?:200|201|204|301|302|304|400|401|403|404|405|408|409|410|412|413|415|422|429|500|501|502|503)", "HTTP status code", "Good: using status codes", Severity.INFO),
            (r"(?:HttpStatus\.\w+|StatusCodes?\.\w+|StatusCode\.\w+)", "Status code enum", "Good: using status code enums", Severity.INFO),
            (r"(?:c\.Status\(\d+\))", "Gin status code", "Good: setting status code", Severity.INFO),
            # Content types
            (r"(?:application/json|text/html|text/plain|text/xml|application/xml|multipart/form-data|application/x-www-form-urlencoded)", "Content type", "Good: specifying content type", Severity.INFO),
            (r"(?:Content-Type|Accept|Authorization|Bearer|Basic)", "HTTP header", "Good: using headers", Severity.INFO),
            # API versioning
            (r"(?:/api/v\d+/|/v\d+/|api_version|API_VERSION|APIVersion)", "API versioning", "Good: versioning API", Severity.INFO),
            (r"(?:api_key|API_KEY|apiKey|ApiKey)", "API key", "Good: using API keys", Severity.INFO),
            (r"(?:token|TOKEN|jwt|JWT|JWT_TOKEN)", "Token", "Good: using tokens", Severity.INFO),
            # Rate limiting
            (r"(?:rate.?limit|throttle|quota|limit|RateLimit|rateLimit)", "Rate limiting", "Good: implementing rate limiting", Severity.INFO),
            # Pagination
            (r"(?:page|limit|offset|cursor|pageSize|pageNum|currentPage|hasMore|nextPage|previousPage|totalPages|totalCount)", "Pagination", "Good: implementing pagination", Severity.INFO),
            # Sorting
            (r"(?:sort|order|sortBy|sortOrder|orderBy|order_by|descending|ascending)", "Sorting", "Good: implementing sorting", Severity.INFO),
            # Filtering
            (r"(?:filter|search|query|param|where|conditions)", "Filtering", "Good: implementing filtering", Severity.INFO),
            # CORS
            (r"(?:cors|CORS|Access-Control|Origin|Cross-Origin)", "CORS", "Good: handling CORS", Severity.INFO),
            # Caching
            (r"(?:Cache-Control|ETag|If-None-Match|Last-Modified|If-Modified-Since|max-age|no-cache|no-store|must-revalidate)", "Caching", "Good: implementing caching", Severity.INFO),
            # Compression
            (r"(?:Content-Encoding|Accept-Encoding|gzip|deflate|br|zstd)", "Compression", "Good: using compression", Severity.INFO),
            # Timeout
            (r"(?:timeout|Timeout|TIMEOUT|deadline|Deadline|DEADLINE)", "Timeout", "Good: setting timeouts", Severity.INFO),
            # Resilience
            (r"(?:retry|Retry|RETRY|backoff|Backoff|circuit.?breaker|CircuitBreaker|fallback|Fallback|bulkhead|Bulkhead)", "Resilience", "Good: implementing resilience", Severity.INFO),
            # Health checks
            (r"(?:health|Health|HEALTH|readiness|Readiness|liveness|Liveness|startup|Startup)", "Health check", "Good: health checks", Severity.INFO),
            # Monitoring
            (r"(?:metrics|Metrics|METRICS|prometheus|Prometheus|grafana|Grafana|datadog|Datadog|opentelemetry|OpenTelemetry)", "Monitoring", "Good: monitoring API", Severity.INFO),
            # Logging
            (r"(?:logging|Logging|trace|Trace|TRACE|span|Span|SPAN|correlation.?id|CorrelationId|request.?id|RequestId)", "Logging/Observability", "Good: implementing observability", Severity.INFO),
            # Documentation
            (r"(?:swagger|Swagger|openapi|OpenAPI|postman|Postman|insomnia|Insomnia)", "API docs", "Good: documenting API", Severity.INFO),
            # Authentication
            (r"(?:auth|Auth|AUTH|authentication|Authentication|authorization|Authorization|login|Login|logout|Logout|signup|SignUp)", "Authentication", "Good: implementing auth", Severity.INFO),
            (r"(?:JWT|jwt|JsonWebToken|JSON_WEB_TOKEN)", "JWT", "Good: using JWT", Severity.INFO),
            (r"(?:OAuth|oauth|OAuth2|oauth2|OpenID|OpenIDConnect|OIDC)", "OAuth", "Good: using OAuth", Severity.INFO),
            # Input validation
            (r"(?:validate|Validate|sanitize|Sanitize|escape|Escape|encode|Encode|whitelist|blacklist|allowlist|blocklist)", "Validation", "Good: validating input", Severity.INFO),
            # Error responses
            (r"(?:error|Error|ERROR|exception|Exception|EXCEPTION|fault|Fault|FAULT|problem|Problem|PROBLEM|error.?response|ErrorResponse)", "Error handling", "Good: error responses", Severity.INFO),
            # Resource naming
            (r"(?:resource|Resource|RESOURCE|endpoint|Endpoint|ENDPOINT|route|Route|ROUTE|path|Path|PATH|uri|URI|url|URL)", "API resources", "Good: naming resources", Severity.INFO),
            # Idempotency
            (r"(?:idempotent|Idempotent|IDEMPOTENT|idempotency.?key|IdempotencyKey)", "Idempotency", "Good: idempotent operations", Severity.INFO),
            # HATEOAS
            (r"(?:_links|_embedded|HAL|hal|hypertext|Hypermedia|HATEOAS|json.?links|JSON-LD)", "HATEOAS", "Good: hypermedia controls", Severity.INFO),
            # Webhooks
            (r"(?:webhook|Webhook|WEBHOOK|callback|Callback|CALLBACK|event|Event|EVENT|notification|Notification)", "Webhooks", "Good: using webhooks", Severity.INFO),
            # File upload
            (r"(?:upload|Upload|UPLOAD|multipart|Multipart|MULTIPART|formdata|FormData|FORMDATA|file.?upload|FileUpload)", "File upload", "Good: handling file uploads", Severity.INFO),
            # File download
            (r"(?:download|Download|DOWNLOAD|stream|Stream|STREAM|attachment|Attachment|file.?download|FileDownload)", "File download", "Good: handling file downloads", Severity.INFO),
            # WebSocket
            (r"(?:WebSocket|websocket|WEBSOCKET|ws://|wss://|socket\.io|Socket\.IO|signalr|SignalR|centrifuge|Centrifuge)", "WebSocket", "Good: using WebSocket", Severity.INFO),
            # GraphQL
            (r"(?:GraphQL|graphql|GRAPHQL|query|mutation|subscription|resolver|schema|type|enum|input|interface|union|scalar)", "GraphQL", "Good: using GraphQL", Severity.INFO),
            # gRPC
            (r"(?:grpc|gRPC|GRPC|protobuf|Protocol.?Buffers|\.proto|service\s+\w+\s*\{)", "gRPC", "Good: using gRPC", Severity.INFO),
            # SSE
            (r"(?:SSE|Server.?Sent.?Events|EventSource|text/event-stream)", "SSE", "Good: using SSE", Severity.INFO),
            # CORS preflight
            (r"(?:OPTIONS|preflight|Preflight|PREFLIGHT)", "CORS preflight", "Good: handling CORS preflight", Severity.INFO),
            # API gateway
            (r"(?:gateway|Gateway|GATEWAY|api.?gateway|APIGateway|proxy|Proxy|PROXY)", "API Gateway", "Good: using API gateway", Severity.INFO),
            # Load balancing
            (r"(?:load.?balanc|LoadBalanc|LOAD_BALANC|round.?robin|RoundRobin|weighted|Weighted|least.?connections|LeastConnections)", "Load balancing", "Good: load balancing", Severity.INFO),
            # Circuit breaker
            (r"(?:circuit.?breaker|CircuitBreaker|CIRCUIT_BREAKER|breaker|Breaker|tripped|reset|half.?open|halfOpen|open|closed)", "Circuit breaker", "Good: circuit breaker pattern", Severity.INFO),
            # Retry
            (r"(?:retry|Retry|RETRY|backoff|Backoff|BACKOFF|exponential|Exponential|jitter|Jitter)", "Retry", "Good: retry pattern", Severity.INFO),
            # Bulkhead
            (r"(?:bulkhead|Bulkhead|BULKHEAD|pool|Pool|POOL|queue|Queue|QUEUE|semaphore|Semaphore)", "Bulkhead", "Good: bulkhead pattern", Severity.INFO),
            # Timeout
            (r"(?:timeout|Timeout|TIMEOUT|deadline|Deadline|DEADLINE|max.?time|maxTime)", "Timeout pattern", "Good: timeout pattern", Severity.INFO),
            # Rate limiting
            (r"(?:rate.?limit|RateLimit|RATE_LIMIT|throttle|Throttle|THROTTLE|quota|Quota|sliding.?window|SlidingWindow|token.?bucket|TokenBucket)", "Rate limiting pattern", "Good: rate limiting pattern", Severity.INFO),
            # Pagination
            (r"(?:page|Page|PAGE|limit|Limit|LIMIT|offset|Offset|OFFSET|cursor|Cursor|CURSOR|next|Next|NEXT|previous|Previous|PREVIOUS|hasMore|has_more|HasMore)", "Pagination pattern", "Good: pagination pattern", Severity.INFO),
            # Sorting
            (r"(?:sort|Sort|SORT|order|Order|ORDER|sortBy|sort_by|SortBy|sortOrder|sort_order|SortOrder|ascending|Ascending|ASCENDING|descending|Descending|DESCENDING)", "Sorting pattern", "Good: sorting pattern", Severity.INFO),
            # Filtering
            (r"(?:filter|Filter|FILTER|search|Search|SEARCH|query|Query|QUERY|where|Where|WHERE|conditions|Conditions|CONDITIONS)", "Filtering pattern", "Good: filtering pattern", Severity.INFO),
            # Field selection
            (r"(?:fields|Fields|FIELDS|select|Select|SELECT|include|Include|INCLUDE|exclude|Exclude|EXCLUDE|sparse|Sparse|SPARSE)", "Field selection", "Good: field selection", Severity.INFO),
            # Embedding
            (r"(?:embed|Embed|EMBED|expand|Expand|EXPAND|include|Include|INCLUDE|nested|Nested|NESTED|related|Related|RELATED)", "Embedding", "Good: resource embedding", Severity.INFO),
            # Versioning
            (r"(?:version|Version|VERSION|v\d+|api.?version|apiVersion|APIVersion|API_VERSION)", "Versioning pattern", "Good: versioning pattern", Severity.INFO),
            # Content negotiation
            (r"(?:content.?type|ContentType|CONTENT_TYPE|accept|Accept|ACCEPT|negotiate|Negotiate|NEGOTIATE)", "Content negotiation", "Good: content negotiation", Severity.INFO),
            # Conditional requests
            (r"(?:etag|ETag|ETAG|if.?none.?match|IfNoneMatch|last.?modified|LastModified|if.?modified.?since|IfModifiedSince|304|Not Modified)", "Conditional requests", "Good: conditional requests", Severity.INFO),
            # Partial responses
            (r"(?:partial|Partial|PARTIAL|range|Range|RANGE|multipart|MultiPart|MULTIPART|chunked|Chunked|CHUNKED)", "Partial responses", "Good: partial responses", Severity.INFO),
            # Caching
            (r"(?:cache.?control|CacheControl|CACHE_CONTROL|max.?age|maxAge|no.?cache|noCache|no.?store|noStore|must.?revalidate|mustRevalidate|private|Private|PUBLIC|public|s-maxage|sMaxage)", "Cache control", "Good: cache control", Severity.INFO),
            # Compression
            (r"(?:content.?encoding|ContentEncoding|accept.?encoding|AcceptEncoding|gzip|GZIP|deflate|DEFLATE|br|BROTLI|zstd|ZSTD)", "Compression", "Good: compression", Severity.INFO),
            # Security headers
            (r"(?:strict.?transport|StrictTransport|HSTS|content.?security|ContentSecurity|CSP|x.?frame|XFrame|XFO|x.?content|XContent|x.?xss|XXSS|referrer.?policy|ReferrerPolicy|permissions.?policy|PermissionsPolicy)", "Security headers", "Good: security headers", Severity.INFO),
            # TLS
            (r"(?:tls|TLS|https|HTTPS|ssl|SSL|certificate|Certificate|CERTIFICATE|encrypt|Encrypt|ENCRYPT)", "TLS/SSL", "Good: TLS/SSL", Severity.INFO),
            # Authentication
            (r"(?:auth|Auth|AUTH|authenticate|Authenticate|AUTHENTICATE|authorize|Authorize|AUTHORIZE|login|Login|LOGIN|logout|Logout|LOGOUT|signup|SignUp|SIGNUP|register|Register|REGISTER)", "Authentication pattern", "Good: authentication pattern", Severity.INFO),
            # Authorization
            (r"(?:role|Role|ROLE|permission|Permission|PERMISSION|access|Access|ACCESS|policy|Policy|POLICY|acl|ACL|rbac|RBAC|abac|ABAC)", "Authorization pattern", "Good: authorization pattern", Severity.INFO),
            # Token management
            (r"(?:token|Token|TOKEN|jwt|JWT|refresh|Refresh|REFRESH|access.?token|accessToken|ACCESS_TOKEN|refresh.?token|refreshToken|REFRESH_TOKEN)", "Token management", "Good: token management", Severity.INFO),
            # Session management
            (r"(?:session|Session|SESSION|cookie|Cookie|COOKIE|csrf|CSRF|xsrf|XSRF|cors|CORS)", "Session management", "Good: session management", Severity.INFO),
            # Input validation
            (r"(?:valid|Valid|VALID|sanitize|Sanitize|SANITIZE|escape|Escape|ESCAPE|encode|Encode|ENCODE|decode|Decode|DECODE|whitelist|Whitelist|WHITELIST|blacklist|Blacklist|BLACKLIST|allowlist|Allowlist|ALLOWLIST|blocklist|Blocklist|BLOCKLIST)", "Input validation", "Good: input validation", Severity.INFO),
            # Output encoding
            (r"(?:encode|Encode|ENCODE|decode|Decode|DECODE|escape|Escape|ESCAPE|unescape|Unescape|UNESCAPE|html.?encode|htmlEncode|url.?encode|urlEncode|json.?encode|jsonEncode|xml.?encode|xmlEncode)", "Output encoding", "Good: output encoding", Severity.INFO),
            # Error handling
            (r"(?:error|Error|ERROR|exception|Exception|EXCEPTION|fault|Fault|FAULT|problem|Problem|PROBLEM|rfc7807|RFC7807|rfc9457|RFC9457|problem.?json|ProblemJson|error.?response|ErrorResponse)", "Error handling pattern", "Good: error handling pattern", Severity.INFO),
            # Logging
            (r"(?:log|Log|LOG|logging|Logging|LOGGING|trace|Trace|TRACE|span|Span|SPAN|correlation.?id|correlationId|request.?id|requestId|trace.?id|traceId|span.?id|spanId)", "Logging pattern", "Good: logging pattern", Severity.INFO),
            # Monitoring
            (r"(?:metric|Metric|METRIC|prometheus|Prometheus|grafana|Grafana|datadog|Datadog|new.?relic|NewRelic|dynatrace|Dynatrace|opentelemetry|OpenTelemetry|openmetrics|OpenMetrics)", "Monitoring pattern", "Good: monitoring pattern", Severity.INFO),
            # Alerting
            (r"(?:alert|Alert|ALERT|notification|Notification|NOTIFICATION|pager|Pager|PAGER|incident|Incident|INCIDENT|escalation|Escalation|ESCALATION)", "Alerting pattern", "Good: alerting pattern", Severity.INFO),
            # Documentation
            (r"(?:swagger|Swagger|SWAGGER|openapi|OpenAPI|openapi.?3|OpenAPI3|postman|Postman|insomnia|Insomnia|api.?doc|ApiDoc|API_DOC)", "Documentation pattern", "Good: documentation pattern", Severity.INFO),
            # Testing
            (r"(?:test|Test|TEST|spec|Spec|SPEC|mock|Mock|MOCK|stub|Stub|STUB|fixture|Fixture|FIXTURE|factory|Factory|FACTORY)", "Testing pattern", "Good: testing pattern", Severity.INFO),
            # CI/CD
            (r"(?:ci|CI|cd|CD|pipeline|Pipeline|PIPELINE|continuous|Continuous|CONTINUOUS|integration|Integration|INTEGRATION|delivery|Delivery|DELIVERY|deployment|Deployment|DEPLOYMENT)", "CI/CD pattern", "Good: CI/CD pattern", Severity.INFO),
            # Containerization
            (r"(?:docker|Docker|DOCKER|kubernetes|Kubernetes|KUBERNETES|k8s|K8S|container|Container|CONTAINER|pod|Pod|POD|service|Service|SERVICE|deployment|Deployment|DEPLOYMENT|ingress|Ingress|INGRESS)", "Containerization pattern", "Good: containerization pattern", Severity.INFO),
            # Infrastructure
            (r"(?:terraform|Terraform|TERRAFORM|ansible|Ansible|ANSIBLE|cloudformation|CloudFormation|pulumi|Pulumi|CDK|cdk)", "Infrastructure pattern", "Good: infrastructure pattern", Severity.INFO),
            # Monitoring
            (r"(?:prometheus|Prometheus|grafana|Grafana|datadog|Datadog|new.?relic|NewRelic|dynatrace|Dynatrace|opentelemetry|OpenTelemetry)", "Monitoring tools", "Good: monitoring tools", Severity.INFO),
            # Logging
            (r"(?:elasticsearch|Elasticsearch|logstash|Logstash|kibana|Kibana|fluentd|Fluentd|fluentbit|FluentBit|loki|Loki|tempo|Tempo|mimir|Mimir)", "Logging tools", "Good: logging tools", Severity.INFO),
            # Caching
            (r"(?:redis|Redis|REDIS|memcached|Memcached|MEMCACHED|varnish|Varnish|VARNISH|cdn|CDN)", "Caching tools", "Good: caching tools", Severity.INFO),
            # Message queues
            (r"(?:rabbitmq|RabbitMQ|kafka|Kafka|nats|NATS|pulsar|Pulsar|zeromq|ZeroMQ|activemq|ActiveMQ|sqs|SQS|sns|SNS|pubsub|PubSub)", "Message queue tools", "Good: message queue tools", Severity.INFO),
            # Databases
            (r"(?:postgresql|PostgreSQL|mysql|MySQL|sqlite|SQLite|mongodb|MongoDB|redis|Redis|cassandra|Cassandra|dynamodb|DynamoDB|elasticsearch|Elasticsearch|neo4j|Neo4j|influxdb|InfluxDB|timescaledb|TimescaleDB|couchdb|CouchDB)", "Database tools", "Good: database tools", Severity.INFO),
        ]
        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith('#') or stripped.startswith('//'):
                continue
            for pattern, message, severity in patterns:
                if re.search(pattern, line):
                    issues.append(self._create_issue(
                        file_path=file_path, line=line_num, message=message,
                        suggestion=message, severity=severity, code_snippet=stripped,
                    ))
        return issues
