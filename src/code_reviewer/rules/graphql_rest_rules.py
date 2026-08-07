"""
GraphQL and REST API patterns.
"""
import re
from ..core.models import CodeIssue, Severity, IssueCategory
from ..core.rules import BaseRule


class GraphQLRestRules(BaseRule):
    @property
    def name(self) -> str:
        return "graphql_rest"
    @property
    def description(self) -> str:
        return "GraphQL and REST API patterns"
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
            # REST API
            (r"GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE|CONNECT", "HTTP method", "Good: HTTP method", Severity.INFO),
            (r"/api/|/v1/|/v2/|/v3/|/api/v1/|/api/v2/|/api/v3/", "API versioning", "Good: API versioning", Severity.INFO),
            (r"Content-Type|Accept|Authorization|User-Agent|Cache-Control|Set-Cookie|Cookie|X-Requested-With|X-Forwarded-For|X-Real-IP|X-API-Key|Bearer|X-Request-ID|X-Correlation-ID", "HTTP header", "Good: HTTP headers", Severity.INFO),
            (r"200|201|204|301|302|304|400|401|403|404|405|409|410|422|429|500|502|503|504", "HTTP status", "Good: HTTP status codes", Severity.INFO),
            (r"application/json|text/html|text/plain|multipart/form-data|application/x-www-form-urlencoded|application/xml|text/xml|application/octet-stream", "MIME type", "Good: MIME types", Severity.INFO),
            # REST best practices
            (r"rate.?limit|rateLimit|rate_limit|throttle|Throttle|THROTTLE|brute.?force|BruteForce|brute_force", "Rate limiting", "Good: rate limiting", Severity.INFO),
            (r"CORS|cors|Cross-Origin|cross-origin|Access-Control-Allow-Origin|Access-Control-Allow-Methods|Access-Control-Allow-Headers|Access-Control-Allow-Credentials|Access-Control-Max-Age|Access-Control-Expose-Headers|Access-Control-Request-Headers|Access-Control-Request-Method|Origin|Referer", "CORS", "Good: CORS", Severity.INFO),
            (r"pagination|Pagination|PAGE|page|PAGE|limit|LIMIT|offset|OFFSET|cursor|CURSOR|hasMore|has_more|nextPage|next_page|prevPage|prev_page|totalCount|total_count|totalPages|total_pages|pageSize|page_size", "Pagination", "Good: pagination", Severity.INFO),
            (r"Etag|etag|ETag|If-None-Match|If-Modified-Since|Last-Modified|If-Match|If-Unmodified-Since|Cache-Control|max-age|no-cache|no-store|must-revalidate|public|private|s-maxage|stale-while-revalidate|immutable", "Caching", "Good: caching headers", Severity.INFO),
            (r"HATEOAS|hypermedia|_links|_embedded|self|next|prev|first|last|related|Hal|HAL|JSON:API|jsonapi|json-api", "Hypermedia", "Good: HATEOAS/hypermedia", Severity.INFO),
            # GraphQL
            (r"query\s+\w+|mutation\s+\w+|subscription\s+\w+|fragment\s+\w+|type\s+\w+\s*\{|input\s+\w+\s*\{|enum\s+\w+\s*\{|interface\s+\w+\s*\{|union\s+\w+\s*\{|scalar\s+\w+|schema\s*\{", "GraphQL type", "Good: GraphQL types", Severity.INFO),
            (r"@deprecated|@skip|@include|@specifiedBy|@defer|@stream|@defer|@stream|@deprecated|@skip|@include", "GraphQL directive", "Good: GraphQL directives", Severity.INFO),
            (r"graphQL|GraphQL|graphql|apollo|Apollo|APOLLO|urql|URQL|relay|Relay|RELAY|hasura|Hasura|HASURA|prisma|Prisma|PRISMA|strawberry|Strawberry|strawberry-graphql|ariadne|Ariadne|ariadne-graphql|sgqlc|sgqlc|gql|gql-graphql|sgqlc|gql|gql-graphql|strawberry|Strawberry|ariadne|Ariadne|graphene|Graphene|graphene-python|graphene-django|graphene-sqlalchemy", "GraphQL library", "Good: GraphQL libraries", Severity.INFO),
            # WebSocket
            (r"WebSocket|websocket|ws://|wss://|onopen|onmessage|onerror|onclose|send\(|close\(|CONNECTING|OPEN|CLOSING|CLOSED", "WebSocket", "Good: WebSocket", Severity.INFO),
            # gRPC
            (r"grpc|gRPC|proto|protobuf|\.proto|service\s+\w+\s*\{|rpc\s+\w+\s*\(|message\s+\w+\s*\{|enum\s+\w+\s*\{|import\s+", "gRPC/protobuf", "Good: gRPC/protobuf", Severity.INFO),
            # API documentation
            (r"swagger|Swagger|SWAGGER|openapi|OpenAPI|OPENAPI|postman|Postman|POSTMAN|insomnia|Insomnia|INSOMNIA|hoppscotch|Hoppscotch|HOPPSCOTCH|httpie|HTTPie|HTTPIE|thunder.?client|ThunderClient|REST.?Client|rest.?client|REST_CLIENT|bruno|Bruno|BRUNO|stoplight|Stoplight|STOPLIGHT|redoc|Redoc|REDOC|swagger-ui|SwaggerUI|swagger-ui-dist|swagger-ui-express|swagger-ui-react|swagger-ui-vue|swagger-ui-angular", "API docs", "Good: API documentation", Severity.INFO),
            # API versioning
            (r"/v1/|/v2/|/v3/|api.?version|ApiVersion|API_VERSION|versioning|Versioning|VERSIONING|header|Header|accept|Accept|content.?type|ContentType|media.?type|MediaType|negotiation|Negotiation|content.?negotiation|ContentNegotiation", "API versioning", "Good: API versioning", Severity.INFO),
            # API authentication
            (r"OAuth|OAuth2|OIDC|OpenID|SAML|SAML2|JWT|JWT|bearer|Bearer|token|Token|session|Session|cookie|Cookie|API.?key|APIKey|api_key|access.?token|refresh.?token|id.?token|authorization.?code|grant.?type|client.?credentials|authorization.?code|implicit|PKCE|pkce", "API auth", "Good: API authentication", Severity.INFO),
            # API testing
            (r"supertest|SuperTest|rest.?assured|RestAssured|frisby|Frisby|pact|Pact|PACT|pactum|Pactum|insomnia|Insomnia|postman|Postman|httpie|HTTPie|curl|Curl|cURL|wget|Wget|http|HTTP|axios|Axios|fetch|Fetch|request|Request|got|Got|node-fetch|node.?fetch|ky|ky|ofetch|Ofetch|undici|Undici|reqwest|reqwest|ureq|ureq|httpx|httpx|aiohttp|aiohttp|requests|Requests", "API testing", "Good: API testing", Severity.INFO),
            # API patterns
            (r"REST|rest|RESTful|restful|RESTful|graphql|GraphQL|graphQL|gRPC|grpc|WebSocket|websocket|WebSocket|MQTT|mqtt|AMQP|amqp|STOMP|stomp|SSE|SSE|server.?sent.?events|ServerSentEvents|long.?polling|LongPolling|short.?polling|ShortPolling|webhook|Webhook|callback|Callback", "API pattern", "Good: API patterns", Severity.INFO),
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
