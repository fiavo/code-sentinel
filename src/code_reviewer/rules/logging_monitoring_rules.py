"""
Logging, monitoring, and observability patterns.
"""
import re
from ..core.models import CodeIssue, Severity, IssueCategory
from ..core.rules import BaseRule


class LoggingMonitoringRules(BaseRule):
    @property
    def name(self) -> str:
        return "logging_monitoring"
    @property
    def description(self) -> str:
        return "Logging, monitoring, and observability patterns"
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
            # Logging levels
            (r"logging\.debug|logger\.debug|LOG\.debug|log\.debug|Logger\.debug|System\.out\.println|fmt\.Println|println!|print!|console\.log|console\.debug|console\.trace", "Debug logging", "Good: debug logging", Severity.INFO),
            (r"logging\.info|logger\.info|LOG\.info|log\.info|Logger\.info|System\.out\.println|fmt\.Println|println!|console\.log|console\.info", "Info logging", "Good: info logging", Severity.INFO),
            (r"logging\.warning|logger\.warning|LOG\.warning|log\.warning|Logger\.warning|System\.err\.println|fmt\.Println|println!|console\.warn", "Warning logging", "Good: warning logging", Severity.INFO),
            (r"logging\.error|logger\.error|LOG\.error|log\.error|Logger\.error|System\.err\.println|fmt\.Println|eprintln!|console\.error", "Error logging", "Good: error logging", Severity.INFO),
            (r"logging\.critical|logger\.critical|LOG\.critical|log\.critical|Logger\.critical|System\.err\.println|fmt\.Println|eprintln!|console\.error", "Critical logging", "Good: critical logging", Severity.INFO),
            (r"logging\.fatal|logger\.fatal|LOG\.fatal|log\.fatal|Logger\.fatal|System\.err\.println|fmt\.Println|eprintln!|console\.error", "Fatal logging", "Good: fatal logging", Severity.INFO),
            # Logging frameworks
            (r"import logging|from logging|logging\.getLogger|logging\.basicConfig|logging\.FileHandler|logging\.StreamHandler|logging\.RotatingFileHandler|logging\.TimedRotatingFileHandler|logging\.SocketHandler|logging\.SMTPHandler|logging\.SysLogHandler|logging\.NTEventLogHandler|logging\.HTTPHandler|logging\.MemoryHandler|logging\.QueueHandler|logging\.NullHandler|logging\.Formatter|logging\.Filter", "Python logging", "Good: Python logging", Severity.INFO),
            (r"winston|pino|bunyan|log4j|logback|slf4j|commons-logging|tinylog|f4j|jul|java\.util\.logging|System\.out|System\.err", "Java/JS logging", "Good: logging frameworks", Severity.INFO),
            (r"log\.\w+\(|log\.Debug|log\.Info|log\.Warn|log\.Error|log\.Fatal|log\.Panic|log\.Print|log\.Printf|log\.Println|log\.Fatalf|log\.Fatalln|log\.Panicf|log\.Panicln", "Go logging", "Good: Go logging", Severity.INFO),
            (r"tracing::|tracing_subscriber|env_logger|log4rs|slog|fern|simplelog|log4rust", "Rust logging", "Good: Rust logging", Severity.INFO),
            # Structured logging
            (r"structured|json.?log|JSON.?log|key.?value|key.?pair|structured.?logging|JSON.?format|JSON.?logging|JSON.?output", "Structured logging", "Good: structured logging", Severity.INFO),
            (r"logger\.\w+\(.*\{.*\}|log\.\w+\(.*\{.*\}|print\(\{.*\}", "Structured log entry", "Good: structured log entry", Severity.INFO),
            # Monitoring
            (r"prometheus|Prometheus|metrics|Metrics|counter|Counter|gauge|Gauge|histogram|Histogram|summary|Summary|metric|Metric", "Prometheus metrics", "Good: Prometheus metrics", Severity.INFO),
            (r"opentelemetry|OpenTelemetry|otel|OTEL|trace|Trace|span|Span|span\.SetAttribute|span\.AddEvent|span\.SetStatus|span\.SetName|tracer|Tracer|propagat|context\.Context", "OpenTelemetry", "Good: OpenTelemetry", Severity.INFO),
            (r"jaeger|Jaeger|zipkin|Zipkin|datadog|Datadog|dynatrace|Dynatrace|newrelic|NewRelic|new.?relic|AppDynamics|appdynamics|Elastic.?APM|elastic.?apm", "APM tools", "Good: APM tools", Severity.INFO),
            (r"grafana|Grafana|kibana|Kibana|ELK|elastic|Elastic|Elasticsearch|elasticsearch|OpenSearch|opensearch|Loki|loki|Tempo|tempo|Mimir|mimir|Prometheus|prometheus", "Observability stack", "Good: observability stack", Severity.INFO),
            # Health checks
            (r"health.?check|healthcheck|HealthCheck|HEALTHCHECK|readiness|Readiness|liveness|Liveness|startup.?probe|StartupProbe|/health|/ready|/live|/healthz|/readyz|/livez", "Health check", "Good: health checks", Severity.INFO),
            # Alerting
            (r"alert|Alert|alerting|Alerting|notification|Notification|pagerduty|PagerDuty|opsgenie|OpsGenie|slack|Slack|email|Email|webhook|Webhook|incident|Incident", "Alerting", "Good: alerting", Severity.INFO),
            # Dashboards
            (r"dashboard|Dashboard|visualization|Visualization|chart|Chart|panel|Panel|widget|Widget|graph|Graph|plot|Plot", "Dashboard", "Good: dashboards", Severity.INFO),
            # Logging best practices
            (r"correlation.?id|CorrelationId|correlation_id|request.?id|request_id|trace.?id|trace_id|span.?id|span_id|transaction.?id|transaction_id|operation.?id|operation_id", "Correlation ID", "Good: correlation IDs", Severity.INFO),
            (r"request.?id|request_id|RequestID|requestID|x-request-id|X-Request-ID|x-correlation-id|X-Correlation-ID", "Request ID", "Good: request IDs", Severity.INFO),
            (r"trace.?id|trace_id|TraceID|traceID|X-Trace-ID|x-trace-id", "Trace ID", "Good: trace IDs", Severity.INFO),
            (r"span.?id|span_id|SpanID|spanID|X-Span-ID|x-span-id", "Span ID", "Good: span IDs", Severity.INFO),
            # Log levels
            (r"TRACE|DEBUG|INFO|WARN|WARNING|ERROR|FATAL|CRITICAL", "Log level", "Good: log levels", Severity.INFO),
            # Log destinations
            (r"stdout|STDERR|STDERR|syslog|Syslog|file|File|FILE|database|Database|DATABASE|elasticsearch|Elasticsearch|kafka|Kafka|kinesis|Kinesis|firehose|Firehose|cloudwatch|CloudWatch|splunk|Splunk|datadog|Datadog|grafana|Grafana|loki|Loki|papertrail|Papertrail|logentries|Logentries|loggly|Loggly|sumologic|Sumo.?Logic", "Log destination", "Good: log destinations", Severity.INFO),
            # Context propagation
            (r"context.?propagation|ContextPropagation|context_propagation|baggage|Baggage|BAGGAGE|context\.Context|context\.Background|context\.WithCancel|context\.WithTimeout|context\.WithValue", "Context propagation", "Good: context propagation", Severity.INFO),
        ]
        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith('#') or stripped.startswith('//') or stripped.startswith('/*'):
                continue
            for pattern, message, severity in patterns:
                if re.search(pattern, line):
                    issues.append(self._create_issue(
                        file_path=file_path, line=line_num, message=message,
                        suggestion=message, severity=severity, code_snippet=stripped,
                    ))
        return issues
