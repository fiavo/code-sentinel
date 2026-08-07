"""
DevOps patterns for CI/CD, deployment, and infrastructure.
"""

import re
from typing import Optional

from ..core.models import CodeIssue, Severity, IssueCategory
from ..core.rules import BaseRule


class DevOpsPatternsRules(BaseRule):
    """DevOps pattern detection."""

    @property
    def name(self) -> str:
        return "devops_patterns"

    @property
    def description(self) -> str:
        return "DevOps pattern detection"

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
            # CI/CD patterns
            (r"(?:ci|cd|pipeline|continuous|integration|delivery|deployment)", "CI/CD", "Good: using CI/CD", Severity.INFO),
            (r"(?:build|compile|bundle|minify|uglify|transpile|transcode)", "Build process", "Good: building project", Severity.INFO),
            (r"(?:test|spec|lint|format|check|validate)", "Testing/quality", "Good: testing code", Severity.INFO),
            (r"(?:deploy|release|rollback|canary|blue.?green|rolling|shadow)", "Deployment", "Good: managing deployments", Severity.INFO),
            (r"(?:monitor|alert|dashboard|report|log|trace|metric)", "Monitoring", "Good: monitoring system", Severity.INFO),
            (r"(?:backup|restore|recovery|disaster)", "Disaster recovery", "Good: implementing disaster recovery", Severity.INFO),
            (r"(?:security|vulnerability|patch|update|upgrade)", "Security", "Good: managing security", Severity.INFO),
            (r"(?:performance|optimize|cache|compress|cdn)", "Performance", "Good: optimizing performance", Severity.INFO),
            (r"(?:scalab|elastic|auto.?scale|load.?balanc)", "Scalability", "Good: designing for scalability", Severity.INFO),
            (r"(?:config|env|secret|vault|feature.?flag)", "Configuration", "Good: managing configuration", Severity.INFO),
            (r"(?:log|audit|trace|metric|analytics)", "Logging", "Good: logging appropriately", Severity.INFO),
            (r"(?:container|docker|kubernetes|k8s|podman)", "Containerization", "Good: using containers", Severity.INFO),
            (r"(?:terraform|ansible|chef|puppet|salt)", "Infrastructure as Code", "Good: using IaC", Severity.INFO),
            (r"(?:cloud|aws|azure|gcp|vercel|netlify)", "Cloud platform", "Good: using cloud platform", Severity.INFO),
            (r"(?:git|github|gitlab|bitbucket|svn)", "Version control", "Good: using version control", Severity.INFO),
            (r"(?:npm|yarn|pnpm|pip|cargo|go|mod|composer|gem|bundler|pub|mix|hex|nuget|maven|gradle|sbt|cocoapods|carthage|spm|homebrew|apt|yum|dnf|pacman|chocolatey|winget|scoop)", "Package manager", "Good: using package manager", Severity.INFO),
            (r"(?:node|deno|bun|python|ruby|php|java|go|rust|c\+\+|c#|swift|kotlin|scala|clojure|elixir|erlang|haskell|ocaml|f#|julia|r|matlab|sas|spss|stata|lua|perl|tcl|ada|fortran|cobol|assembly)", "Runtime environment", "Good: using runtime environment", Severity.INFO),
            (r"(?:postgresql|mysql|mariadb|sqlite|oracle|sql.?server|mongodb|cassandra|dynamodb|couchdb|redis|memcached|elasticsearch|neo4j|rethinkdb|arangodb|ravendb|firebase|firestore|supabase|planetscale|tidb|cockroachdb|yugabytedb|vitess|proxysql|maxscale|clickhouse|druid|influxdb|timescaledb|questdb|duckdb|parquet|iceberg|delta.?lake|hudi)", "Database system", "Good: using databases", Severity.INFO),
            (r"(?:rabbitmq|kafka|nats|redis|pulsar|zeromq|activemq|ibm.?mq|amazon.?sqs|amazon.?sns|google.?pub|azure.?service.?bus|azure.?queue)", "Message queue", "Good: using message queue", Severity.INFO),
            (r"(?:redis|memcached|hazelcast|ehcache|caffeine|guava|aerospike|dragonfly|keydb|valkey)", "Caching system", "Good: using caching", Severity.INFO),
            (r"(?:elasticsearch|opensearch|solr|meilisearch|typesense|algolia|splunk|grafana.?loki)", "Search engine", "Good: using search engine", Severity.INFO),
            (r"(?:google.?analytics|mixpanel|amplitude|segment|heap|hotjar|fullstory|logrocket|posthog|plausible|umami|matomo)", "Analytics", "Good: using analytics", Severity.INFO),
            (r"(?:stripe|paypal|braintree|square|adyen|authorize|checkout|paymentintent|paymentmethod|customer|subscription|invoice|webhook|charge|refund|dispute|payout|connect|identity|radar|tax|terminal|sigma|climate|issuing|treasury|financial.?connections|payment.?links|payment.?request|setupintent)", "Payment processing", "Good: using payment processing", Severity.INFO),
            (r"(?:sendgrid|mailgun|postmark|ses|sparkpost|mailchimp|brevo|mailtrap|emailoctopus|moosend|mailerlite|convertkit)", "Email service", "Good: using email service", Severity.INFO),
            (r"(?:contentful|sanity|strapi|directus|payload|keystone|ghost|wordpress|drupal|joomla|netlify.?cms|decap|storyblok|contentstack|kontent|prismic|butter)", "CMS", "Good: using CMS", Severity.INFO),
            (r"(?:s3|cloud.?storage|azure.?blob|minio|r2|digitalocean.?spaces|wasabi|b2|backblaze|google.?drive|dropbox|onedrive)", "Cloud storage", "Good: using cloud storage", Severity.INFO),
            (r"(?:auth0|firebase.?auth|supabase.?auth|cognito|keycloak|okta|ping.?identity|onelogin|jumpcloud|azure.?ad|aws.?sso|duo|yubikey|totp|oauth|oidc|saml|jwt|session|cookie|token)", "Authentication", "Good: using authentication", Severity.INFO),
            (r"(?:launchdarkly|split|flagsmith|unleash|flipt|configcat|eppo|growthbook|statsig|harness|feature.?flag|toggle|experiment|a/b)", "Feature flags", "Good: using feature flags", Severity.INFO),
            (r"(?:sentry|bugsnag|rollbar|airbrake|logrocket|honeybadger|errorception|trackjs|errorstackr|sentry)", "Error tracking", "Good: using error tracking", Severity.INFO),
            (r"(?:new.?relic|datadog|dynatrace|appdynamics|elastic.?apm|jaeger|zipkin|opentelemetry|prometheus|grafana|grafana.?tempo)", "APM", "Good: using APM", Severity.INFO),
            (r"(?:swagger|openapi|postman|insomnia|hoppscotch|httpie|thunder.?client|rest.?client|bruno|kong|tyk|stoplight)", "API documentation", "Good: documenting APIs", Severity.INFO),
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
