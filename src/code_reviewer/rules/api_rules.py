"""
Comprehensive API design rules for code analysis.
Covers REST, GraphQL, WebSocket, and general API best practices.
"""

import re
from typing import Optional

from ..core.models import CodeIssue, Severity, IssueCategory
from ..core.rules import BaseRule


class RESTAPIRules(BaseRule):
    """REST API design and security rules."""

    @property
    def name(self) -> str:
        return "rest_api"

    @property
    def description(self) -> str:
        return "REST API design and security detection"

    @property
    def category(self) -> IssueCategory:
        return IssueCategory.BEST_PRACTICE

    @property
    def severity(self) -> Severity:
        return Severity.WARNING

    def check(self, file_path: str, content: str) -> list[CodeIssue]:
        issues = []
        lines = content.splitlines()

        patterns = [
            # Missing authentication
            (r'@app\.route\s*\(\s*["\']/api/', "API route without auth middleware",
             "Add authentication middleware", Severity.WARNING),
            (r'router\.(?:get|post|put|delete|patch)\s*\(\s*["\']/api/', "API route without auth middleware",
             "Add authentication middleware", Severity.WARNING),
            (r'(?:get|post|put|delete|patch)\s*\(\s*["\']/api/', "API endpoint without auth",
             "Add authentication middleware", Severity.WARNING),

            # Missing rate limiting
            (r'@app\.route\s*\([^)]*\)', "Route without rate limiting",
             "Add rate limiting middleware", Severity.INFO),
            (r'router\.(?:get|post|put|delete)\s*\([^)]*\)', "Route without rate limiting",
             "Add rate limiting middleware", Severity.INFO),

            # Missing input validation
            (r'@app\.route\s*\([^)]*methods\s*=\s*\[.*(?:POST|PUT|PATCH)', "Write route without input validation",
             "Add input validation (marshmallow, pydantic, etc.)", Severity.WARNING),
            (r'router\.(?:post|put|patch)\s*\([^)]*\)', "Write endpoint without validation",
             "Add request body validation", Severity.WARNING),
            (r'(?:req|request)\.(?:body|json)\b', "Request body without validation",
             "Validate request body before use", Severity.WARNING),

            # Missing CORS
            (r'(?:CORS|cors)\s*\(', "CORS configuration",
             "Ensure CORS is properly configured", Severity.INFO),
            (r'(?:Access-Control-Allow-Origin)', "CORS header",
             "Ensure CORS is not too permissive", Severity.INFO),
            (r'allow_origins\s*=\s*\[.*\*.*\]', "CORS allows all origins",
             "Restrict CORS to specific origins in production", Severity.WARNING),

            # Missing Content-Type
            (r'res\.json\s*\(\s*\)', "Response without Content-Type",
             "Ensure proper Content-Type header", Severity.INFO),
            (r'res\.send\s*\(', "Response without Content-Type",
             "Set appropriate Content-Type header", Severity.INFO),

            # Status code issues
            (r'return\s+200', "Always returning 200",
             "Use appropriate HTTP status codes (201, 204, 400, 404, etc.)", Severity.INFO),
            (r'return\s+200\s*,\s*\{', "Always returning 200 with data",
             "Use 201 for creation, 204 for deletion", Severity.INFO),
            (r'status_code\s*=\s*200', "Always returning 200",
             "Use appropriate HTTP status codes", Severity.INFO),

            # Missing pagination
            (r'(?:get|post)\s*\(\s*["\']/api/.*(?:list|all|index)', "List endpoint without pagination",
             "Add pagination parameters (page, limit)", Severity.INFO),
            (r'\.all\s*\(\s*\)', "Returning all records",
             "Add pagination for large datasets", Severity.WARNING),

            # Versioning
            (r'(?:get|post|put|delete)\s*\(\s*["\']/(?!v\d|api/v)[^"\']+["\']', "API without versioning",
             "Consider API versioning (e.g., /api/v1/)", Severity.INFO),

            # Missing error responses
            (r'(?:get|post|put|delete)\s*\([^)]*\)\s*(?:async\s+)?(?:def|function)', "Endpoint without error handling",
             "Add proper error responses (400, 404, 500)", Severity.INFO),

            # N+1 in API
            (r'(?:serializer|response)\s*=\s*\w+.*many\s*=\s*True', "Serializer with many=True",
             "Use select_related/prefetch_related to avoid N+1", Severity.INFO),

            # Missing HATEOAS
            (r'(?:serializer|response)\s*=\s*\w+', "API response without HATEOAS links",
             "Consider adding hypermedia links", Severity.INFO),
        ]

        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith('#') or stripped.startswith('//'):
                continue

            for pattern, message, suggestion, severity in patterns:
                if re.search(pattern, line):
                    issues.append(self._create_issue(
                        file_path=file_path,
                        line=line_num,
                        message=message,
                        suggestion=suggestion,
                        severity=severity,
                        code_snippet=stripped,
                    ))

        return issues


class GraphQLRules(BaseRule):
    """GraphQL API design rules."""

    @property
    def name(self) -> str:
        return "graphql"

    @property
    def description(self) -> str:
        return "GraphQL API design detection"

    @property
    def category(self) -> IssueCategory:
        return IssueCategory.BEST_PRACTICE

    @property
    def severity(self) -> Severity:
        return Severity.WARNING

    def check(self, file_path: str, content: str) -> list[CodeIssue]:
        issues = []
        lines = content.splitlines()

        patterns = [
            # Missing authentication
            (r'(?:Query|Mutation|Subscription)\s*:\s*\{', "GraphQL resolver without auth",
             "Add authentication to resolvers", Severity.WARNING),
            (r'resolve\s*\(\s*parent\s*,\s*info', "Resolver without authentication",
             "Add authentication check in resolver", Severity.WARNING),

            # Missing rate limiting
            (r'(?:Query|Mutation)\s*\{', "GraphQL endpoint without rate limiting",
             "Add query complexity analysis and rate limiting", Severity.WARNING),

            # Missing depth limiting
            (r'(?:Query|Mutation)\s*\{', "GraphQL without depth limiting",
             "Add query depth limiting to prevent abuse", Severity.WARNING),

            # N+1 in GraphQL
            (r'(?:resolve|loader)\s*\([^)]*\)', "GraphQL resolver without DataLoader",
             "Use DataLoader for batch loading", Severity.INFO),

            # Missing validation
            (r'(?:args|input)\s*:\s*\w+', "GraphQL input without validation",
             "Add input validation for GraphQL mutations", Severity.WARNING),

            # Exposing sensitive fields
            (r'(?:password|secret|token|key)\s*:\s*\w+', "Sensitive field in GraphQL schema",
             "Remove sensitive fields from GraphQL schema", Severity.CRITICAL),

            # Missing error handling
            (r'(?:Query|Mutation)\s*\{', "GraphQL without error handling",
             "Add proper error handling in resolvers", Severity.INFO),

            # Missing pagination
            (r'(?:Query|Mutation)\s*\{.*(?:list|all|items)', "GraphQL list without pagination",
             "Add cursor-based pagination for lists", Severity.INFO),

            # Subscription issues
            (r'Subscription\s*\{', "GraphQL subscription",
             "Ensure proper authentication for subscriptions", Severity.INFO),
        ]

        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith('#') or stripped.startswith('//'):
                continue

            for pattern, message, suggestion, severity in patterns:
                if re.search(pattern, line):
                    issues.append(self._create_issue(
                        file_path=file_path,
                        line=line_num,
                        message=message,
                        suggestion=suggestion,
                        severity=severity,
                        code_snippet=stripped,
                    ))

        return issues


class WebSocketRules(BaseRule):
    """WebSocket API design rules."""

    @property
    def name(self) -> str:
        return "websocket"

    @property
    def description(self) -> str:
        return "WebSocket API design detection"

    @property
    def category(self) -> IssueCategory:
        return IssueCategory.BEST_PRACTICE

    @property
    def severity(self) -> Severity:
        return Severity.WARNING

    def check(self, file_path: str, content: str) -> list[CodeIssue]:
        issues = []
        lines = content.splitlines()

        patterns = [
            # Missing authentication
            (r'(?:WebSocket|ws|socket)\s*\(', "WebSocket without authentication",
             "Add authentication for WebSocket connections", Severity.WARNING),
            (r'on\s*\(\s*["\']connection["\']', "WebSocket connection handler without auth",
             "Add authentication check in connection handler", Severity.WARNING),

            # Missing input validation
            (r'(?:on|addEventListener)\s*\(\s*["\']message["\']', "WebSocket message without validation",
             "Validate incoming WebSocket messages", Severity.WARNING),
            (r'socket\.on\s*\(\s*["\']message["\']', "WebSocket message handler without validation",
             "Validate incoming messages", Severity.WARNING),

            # Missing rate limiting
            (r'ws\.(?:send|emit)\s*\(', "WebSocket send without rate limiting",
             "Add rate limiting for WebSocket messages", Severity.INFO),

            # Missing heartbeat
            (r'(?:WebSocket|ws)\s*\(', "WebSocket without heartbeat",
             "Add heartbeat/ping-pong for connection health", Severity.INFO),
            (r'socket\.on\s*\(\s*["\']close["\']', "WebSocket close handler",
             "Ensure proper cleanup on disconnect", Severity.INFO),

            # Missing error handling
            (r'socket\.on\s*\(\s*["\']error["\']', "WebSocket error handler",
             "Good: handling WebSocket errors", Severity.INFO),
            (r'(?:WebSocket|ws)\s*\(.*\)(?![\s\S]*\.on\s*\(\s*["\']error)', "WebSocket without error handler",
             "Add error event handler", Severity.WARNING),

            # Missing reconnection
            (r'ws\.on\s*\(\s*["\']close["\']', "WebSocket close without reconnect",
             "Implement automatic reconnection", Severity.INFO),

            # Memory leaks
            (r'socket\.on\s*\([^)]*\)(?!.*(?:off|removeEventListener|removeListener))', "Event listener without cleanup",
             "Remove event listeners on disconnect", Severity.INFO),
        ]

        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith('#') or stripped.startswith('//'):
                continue

            for pattern, message, suggestion, severity in patterns:
                if re.search(pattern, line):
                    issues.append(self._create_issue(
                        file_path=file_path,
                        line=line_num,
                        message=message,
                        suggestion=suggestion,
                        severity=severity,
                        code_snippet=stripped,
                    ))

        return issues
