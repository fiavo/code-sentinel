"""
API design patterns for REST, GraphQL, and WebSocket.
"""

import re
from typing import Optional

from ..core.models import CodeIssue, Severity, IssueCategory
from ..core.rules import BaseRule


class APIDesignRules(BaseRule):
    """API design pattern detection."""

    @property
    def name(self) -> str:
        return "api_design"

    @property
    def description(self) -> str:
        return "API design pattern detection"

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
            (r"(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)", "HTTP method", "Good: using HTTP methods", Severity.INFO),
            (r"(?:/api/|/v1/|/v2/|/graphql|/ws)", "API endpoint", "Good: defining API endpoints", Severity.INFO),
            (r"(?:Content-Type|Accept|Authorization|Bearer|Basic)", "HTTP header", "Good: using HTTP headers", Severity.INFO),
            (r"(?:application/json|text/html|multipart/form-data)", "Content type", "Good: specifying content type", Severity.INFO),
            (r"(?:200|201|204|301|302|400|401|403|404|405|409|422|429|500|502|503)", "HTTP status code", "Good: using status codes", Severity.INFO),
            (r"(?:rate.?limit|throttle|quota|limit)", "Rate limiting", "Good: implementing rate limiting", Severity.INFO),
            (r"(?:pagination|page|limit|offset|cursor)", "Pagination", "Good: implementing pagination", Severity.INFO),
            (r"(?:sort|order|order.?by|sort.?by)", "Sorting", "Good: implementing sorting", Severity.INFO),
            (r"(?:filter|search|query|param)", "Filtering", "Good: implementing filtering", Severity.INFO),
            (r"(?:version|api.?version|v[0-9]+)", "API versioning", "Good: versioning API", Severity.INFO),
            (r"(?:cors|origin|access.?control)", "CORS", "Good: handling CORS", Severity.INFO),
            (r"(?:cache.?control|etag|last.?modified)", "Caching", "Good: implementing caching", Severity.INFO),
            (r"(?:content.?encoding|gzip|deflate|br)", "Compression", "Good: using compression", Severity.INFO),
            (r"(?:timeout|deadline|cancel)", "Timeout", "Good: setting timeouts", Severity.INFO),
            (r"(?:retry|backoff|circuit.?breaker)", "Resilience", "Good: implementing resilience", Severity.INFO),
            (r"(?:health|readiness|liveness|startup)", "Health check", "Good: implementing health checks", Severity.INFO),
            (r"(?:metrics|prometheus|grafana|datadog)", "Monitoring", "Good: monitoring API", Severity.INFO),
            (r"(?:logging|trace|span|correlation.?id)", "Observability", "Good: implementing observability", Severity.INFO),
            (r"(?:swagger|openapi|postman|insomnia)", "API documentation", "Good: documenting API", Severity.INFO),
            (r"(?:authentication|authorization|token|jwt|oauth)", "Auth", "Good: implementing auth", Severity.INFO),
            (r"(?:validation|sanitize|escape|encode)", "Input validation", "Good: validating input", Severity.INFO),
            (r"(?:error|exception|fault|failure)", "Error handling", "Good: handling errors", Severity.INFO),
            (r"(?:request|response|body|header|cookie)", "HTTP components", "Good: using HTTP components", Severity.INFO),
            (r"(?:method|path|query|fragment)", "URL components", "Good: using URL components", Severity.INFO),
            (r"(?:id|uuid|slug|identifier)", "Resource identifier", "Good: identifying resources", Severity.INFO),
            (r"(?:created|updated|deleted|modified)", "Resource state", "Good: tracking resource state", Severity.INFO),
            (r"(?:created.?at|updated.?at|deleted.?at)", "Timestamps", "Good: using timestamps", Severity.INFO),
            (r"(?:user|admin|role|permission)", "User management", "Good: managing users", Severity.INFO),
            (r"(?:tenant|organization|workspace)", "Multi-tenancy", "Good: supporting multi-tenancy", Severity.INFO),
            (r"(?:webhook|callback|event|notification)", "Event handling", "Good: handling events", Severity.INFO),
            (r"(?:queue|job|task|worker)", "Background processing", "Good: processing background", Severity.INFO),
            (r"(?:cache|redis|memcached)", "Caching", "Good: using caching", Severity.INFO),
            (r"(?:queue|rabbitmq|kafka|nats)", "Message queue", "Good: using message queue", Severity.INFO),
            (r"(?:database|sql|nosql|orm)", "Database", "Good: using database", Severity.INFO),
            (r"(?:storage|s3|blob|file)", "File storage", "Good: using file storage", Severity.INFO),
            (r"(?:cdn|cloudfront|fastly|cloudflare)", "CDN", "Good: using CDN", Severity.INFO),
            (r"(?:load.?balancer|nginx|haproxy)", "Load balancer", "Good: using load balancer", Severity.INFO),
            (r"(?:ssl|tls|https|certificate)", "TLS", "Good: using TLS", Severity.INFO),
            (r"(?:firewall|waf|ddos|rate.?limit)", "Security", "Good: implementing security", Severity.INFO),
            (r"(?:backup|restore|disaster.?recovery)", "Backup", "Good: implementing backup", Severity.INFO),
            (r"(?:deploy|release|rollback|canary|blue.?green)", "Deployment", "Good: managing deployments", Severity.INFO),
            (r"(?:ci|cd|pipeline|build|test)", "CI/CD", "Good: using CI/CD", Severity.INFO),
            (r"(?:monitor|alert|dashboard|report)", "Monitoring", "Good: monitoring system", Severity.INFO),
            (r"(?:log|audit|trace|metric)", "Logging", "Good: logging appropriately", Severity.INFO),
            (r"(?:config|env|secret|vault)", "Configuration", "Good: managing configuration", Severity.INFO),
            (r"(?:feature.?flag|toggle|experiment)", "Feature flags", "Good: using feature flags", Severity.INFO),
            (r"(?:a/b|experiment|variant|bucket)", "A/B testing", "Good: running experiments", Severity.INFO),
            (r"(?:analytics|telemetry|tracking)", "Analytics", "Good: tracking analytics", Severity.INFO),
            (r"(?:i18n|l10n|locale|language)", "Internationalization", "Good: supporting i18n", Severity.INFO),
            (r"(?:accessibility|a11y|aria|wcag)", "Accessibility", "Good: ensuring accessibility", Severity.INFO),
            (r"(?:performance|optimization|cache|compress)", "Performance", "Good: optimizing performance", Severity.INFO),
            (r"(?:security|auth|encrypt|hash)", "Security", "Good: implementing security", Severity.INFO),
            (r"(?:test|spec|mock|stub|fixture)", "Testing", "Good: writing tests", Severity.INFO),
            (r"(?:doc|readme|changelog|license)", "Documentation", "Good: documenting project", Severity.INFO),
            (r"(?:package|dependency|module|library)", "Package management", "Good: managing packages", Severity.INFO),
            (r"(?:build|compile|bundle|minify|uglify)", "Build process", "Good: building project", Severity.INFO),
            (r"(?:lint|format|check|validate)", "Code quality", "Good: maintaining code quality", Severity.INFO),
            (r"(?:refactor|cleanup|optimize|improve)", "Code maintenance", "Good: maintaining code", Severity.INFO),
            (r"(?:debug|trace|profile|benchmark)", "Debugging", "Good: debugging code", Severity.INFO),
        ]

        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith('#') or stripped.startswith('//'):
                continue

            for pattern, message, suggestion, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    issues.append(self._create_issue(
                        file_path=file_path,
                        line=line_num,
                        message=message,
                        suggestion=suggestion,
                        severity=severity,
                        code_snippet=stripped,
                    ))

        return issues
