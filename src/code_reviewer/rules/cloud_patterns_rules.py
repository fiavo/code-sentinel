"""
Cloud patterns for AWS, GCP, and Azure.
"""

import re
from typing import Optional

from ..core.models import CodeIssue, Severity, IssueCategory
from ..core.rules import BaseRule


class CloudPatternsRules(BaseRule):
    """Cloud pattern detection."""

    @property
    def name(self) -> str:
        return "cloud_patterns"

    @property
    def description(self) -> str:
        return "Cloud pattern detection"

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
            # AWS patterns
            (r"(?:aws|boto3|botocore|s3|ec2|lambda|dynamodb|sqs|sns|ses|route53|cloudfront|cloudwatch|iam|kms|secrets.?manager|ssm|ecs|eks|fargate|amplify|appsync|cognito|step.?functions|eventbridge|kinesis|firehose|glue|athena|redshift|rds|aurora|neptune|timestream|qldb|managed.?blockchain|elasticache|elasticsearch.?service|opensearch|msk|mq|docdb|memorydb)", "AWS service", "Good: using AWS", Severity.INFO),

            # GCP patterns
            (r"(?:gcp|gcloud|firebase|firestore|cloud.?functions|cloud.?run|cloud.?build|cloud.?storage|cloud.?sql|cloud.?pubsub|cloud.?bigquery|cloud.?dataflow|cloud.?dataproc|cloud.?composer|cloud.?spanner|cloud.?firestore|cloud.?memorystore|cloud.?dns|cloud.?cdn|cloud.?armor|cloud.?load|cloud.?armor|cloud.?monitoring|cloud.?logging|cloud.?trace|cloud.?profiler|cloud.?debugger|cloud.?scheduler|cloud.?tasks|cloud.?vision|cloud.?speech|cloud.?translate|cloud.?natural|cloud.?ml|ai.?platform|vertex.?ai|bigquery|datastore|datastore.?admin)", "GCP service", "Good: using GCP", Severity.INFO),

            # Azure patterns
            (r"(?:azure|azure.?functions|azure.?storage|azure.?sql|azure.?cosmos|azure.?redis|azure.?service|azure.?event|azure.?signalr|azure.?search|azure.?cognitive|azure.?form|azure.?document|azure.?video|azure.?speech|azure.?translation|azure.?bot|azure.?devops|azure.?pipelines|azure.?repos|azure.?artifacts|azure.?boards|azure.?test|azure.?monitor|azure.?log|azure.?application|azure.?keyvault|azure.?identity|azure.?credentials|azure.?management|azure.?resource|azure.?deploy|azure.?arm|azure.?bicep|azure.?terraform|azure.?ansible)", "Azure service", "Good: using Azure", Severity.INFO),

            # Serverless patterns
            (r"(?:serverless|sls|lambda|function\.handler|function\.context|function\.event|function\.callback|serverless\.yml|serverless\.ts|serverless\.js)", "Serverless", "Good: using serverless", Severity.INFO),
            (r"(?:netlify\.functions|netlify\.edge|netlify\.background|netlify\.blobs|netlify\.identity)", "Netlify", "Good: using Netlify", Severity.INFO),
            (r"(?:vercel\.functions|vercel\.edge|vercel\.blob|vercel\.kv|vercel\.postgres|vercel\.postgres\.edge|vercel\.redis|vercel\.cron|vercel\.analytics|vercel\.speed|vercel\.sentry)", "Vercel", "Good: using Vercel", Severity.INFO),
            (r"(?:cloudflare\.workers|cloudflare\.kv|cloudflare\.d1|cloudflare\.r2|cloudflare\.durable|cloudflare\.pages|cloudflare\.images|cloudflare\.stream|cloudflare\.analytics|cloudflare\.zaraz|cloudflare\.turnstile|cloudflare\.waf|cloudflare\.cdn|cloudflare\.dns|cloudflare\.email|cloudflare\.spectrum|cloudflare\.load|cloudflare\.ssl|cloudflare\.zero|cloudflare\.tunnel|cloudflare\.warp)", "Cloudflare", "Good: using Cloudflare", Severity.INFO),

            # Container orchestration
            (r"(?:kubernetes|kubectl|helm|kustomize|skaffold|tilt|devspace|docker|docker-compose|podman|containerd|cri-o|runc|buildah|buildkit)", "Container orchestration", "Good: using container tools", Severity.INFO),

            # CI/CD
            (r"(?:Jenkins|GitLab|GitHub|CircleCI|Travis|Azure|Pipelines|ArgoCD|Flux|Tekton|Drone|Woodpecker|Buildkite|TeamCity|Bamboo|Buddy|Codeship|Bitbucket|Harness|Spinnaker|Octopus|Deploy)", "CI/CD", "Good: using CI/CD", Severity.INFO),

            # Monitoring
            (r"(?:Prometheus|Grafana|Datadog|New Relic|Dynatrace|Splunk|ELK|Jaeger|Zipkin|OpenTelemetry|OpenMetrics|StatsD|Graphite|CollectD|Telegraf|Fluentd|FluentBit|Logstash|Filebeat|Metricbeat|Heartbeat|Packetbeat|APM)", "Monitoring/Observability", "Good: using monitoring tools", Severity.INFO),

            # Security
            (r"(?:Vault|HashiCorp|Consul|Nomad|Waypoint|Boundary|Sentinel|Atlantis|Packer|Vagrant|Terraform|Terragrunt|Terratest|Checkov|tfsec|tflint|Snyk|SonarQube|OWASP|ZAP|Burp|Nmap|Metasploit|Cobalt|Nessus|Qualys|Rapid7)", "Security tool", "Good: using security tools", Severity.INFO),

            # Infrastructure
            (r"(?:Terraform|Terragrunt|Pulumi|Ansible|Chef|Puppet|SaltStack|CloudFormation|ARM|Bicep|CDK|SST|Crossplane)", "Infrastructure as Code", "Good: using IaC", Severity.INFO),

            # Service mesh
            (r"(?:Istio|Envoy|Linkerd|Consul|Cilium|Kong|Tyk|Traefik|NGINX|HAProxy|HAProxy|Varnish|Envoy|Istio|Linkerd|Consul|Kuma|Open Service|Mesh|Gloo|Ambassador|Emissary|Kong|Tyk|APISIX|Grafana|Tempo|Mimir|Loki|Pyroscope)", "Service mesh/API Gateway", "Good: using service mesh", Severity.INFO),

            # Message queues
            (r"(?:RabbitMQ|Kafka|NATS|Redis|Pulsar|ZeroMQ|ActiveMQ|IBM MQ|Amazon SQS|Amazon SNS|Google Pub/Sub|Azure Service Bus|Azure Queue)", "Message queue", "Good: using message queues", Severity.INFO),

            # Caching
            (r"(?:Redis|Memcached|Hazelcast|Ehcache|Caffeine|Guava|Aerospike|Dragonfly|KeyDB|Valkey)", "Caching system", "Good: using caching", Severity.INFO),

            # Search
            (r"(?:Elasticsearch|OpenSearch|Solr|Meilisearch|Typesense|Algolia|Splunk|Grafana Loki)", "Search engine", "Good: using search engine", Severity.INFO),

            # Analytics
            (r"(?:Google Analytics|Mixpanel|Amplitude|Segment|Heap|Hotjar|FullStory|LogRocket|PostHog|Plausible|Umami|Matomo)", "Analytics", "Good: using analytics", Severity.INFO),

            # Payment
            (r"(?:Stripe|PayPal|Braintree|Square|Adyen|Authorize\.net|Checkout|PaymentIntent|PaymentMethod|Customer|Subscription|Invoice|Webhook|Charge|Refund|Dispute|Payout|Connect|Identity|Radar|Tax|Terminal|Sigma|Climate|Issuing|Treasury|Financial Connections|Payment Links|Payment Request|SetupIntent)", "Payment processing", "Good: using payment processing", Severity.INFO),

            # Email
            (r"(?:SendGrid|Mailgun|Postmark|SES|SparkPost|Mailchimp|Brevo|Mailtrap|EmailOctopus|Moosend|MailerLite|ConvertKit)", "Email service", "Good: using email service", Severity.INFO),

            # CMS
            (r"(?:Contentful|Sanity|Strapi|Directus|Payload|Keystone|Ghost|WordPress|Drupal|Joomla|Netlify CMS|Decap|Storyblok|Contentstack|Kontent|Prismic|Butter)", "CMS", "Good: using CMS", Severity.INFO),

            # Storage
            (r"(?:S3|Cloud Storage|Azure Blob|MinIO|R2|DigitalOcean Spaces|Wasabi|B2|Backblaze|Google Drive|Dropbox|OneDrive)", "Cloud storage", "Good: using cloud storage", Severity.INFO),

            # Authentication
            (r"(?:Auth0|Firebase Auth|Supabase Auth|Cognito|Keycloak|Okta|Ping Identity|OneLogin|JumpCloud|Azure AD|AWS SSO|Duo|YubiKey|TOTP|OAuth|OIDC|SAML|JWT|session|cookie|token)", "Authentication", "Good: using authentication", Severity.INFO),

            # Feature flags
            (r"(?:LaunchDarkly|Split|Flagsmith|Unleash|Flipt|ConfigCat|Eppo|GrowthBook|Statsig|Harness|FeatureFlag|feature.*flag|toggle|experiment|A/B)", "Feature flags", "Good: using feature flags", Severity.INFO),

            # Error tracking
            (r"(?:Sentry|Bugsnag|Rollbar|Airbrake|LogRocket|Honeybadger|Errorception|TrackJS|ErrorStackr|Sentry)", "Error tracking", "Good: using error tracking", Severity.INFO),

            # Performance monitoring
            (r"(?:New Relic|Datadog|Dynatrace|AppDynamics|Elastic APM|Jaeger|Zipkin|OpenTelemetry|Prometheus|Grafana|Grafana Tempo)", "APM", "Good: using APM", Severity.INFO),

            # Documentation
            (r"(?:Swagger|OpenAPI|Postman|Insomnia|Hoppscotch|HTTPie|Thunder Client|REST Client|Bruno|Kong|Tyk|Stoplight)", "API documentation", "Good: documenting APIs", Severity.INFO),

            # Version control
            (r"(?:git|GitHub|GitLab|Bitbucket|Azure DevOps|Perforce|SVN|Mercurial|Subversion)", "Version control", "Good: using version control", Severity.INFO),

            # Package managers
            (r"(?:npm|yarn|pnpm|bun|pip|poetry|conda|cargo|go|mod|composer|gem|bundler|pub|mix|hex|nuget|maven|gradle|sbt|cocoapods|carthage|spm|homebrew|apt|yum|dnf|pacman|chocolatey|winget|scoop)", "Package manager", "Good: using package manager", Severity.INFO),

            # Runtime environments
            (r"(?:Node\.js|Deno|Bun|Python|Ruby|PHP|Java|Go|Rust|C\+\+|C#|Swift|Kotlin|Scala|Clojure|Elixir|Erlang|Haskell|OCaml|F#|Julia|R|MATLAB|SAS|SPSS|Stata|Lua|Perl|Tcl|Ada|Fortran|COBOL|Assembly)", "Runtime environment", "Good: using runtime environment", Severity.INFO),

            # Databases
            (r"(?:PostgreSQL|MySQL|MariaDB|SQLite|Oracle|SQL Server|DB2|MongoDB|Cassandra|DynamoDB|CouchDB|Redis|Memcached|Elasticsearch|Neo4j|RethinkDB|ArangoDB|RavenDB|Firebase|Firestore|Supabase|PlanetScale|TiDB|CockroachDB|YugabyteDB|Vitess|ProxySQL|MaxScale|ClickHouse|Druid|InfluxDB|TimescaleDB|QuestDB|DuckDB|Parquet|Iceberg|Delta Lake|Hudi)", "Database system", "Good: using databases", Severity.INFO),
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
