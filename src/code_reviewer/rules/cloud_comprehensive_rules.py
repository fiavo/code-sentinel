"""
Comprehensive cloud patterns for AWS, GCP, Azure, and serverless.
"""
import re
from ..core.models import CodeIssue, Severity, IssueCategory
from ..core.rules import BaseRule


class CloudComprehensiveRules(BaseRule):
    @property
    def name(self) -> str:
        return "cloud_comprehensive"
    @property
    def description(self) -> str:
        return "Comprehensive cloud patterns"
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
            # AWS
            (r"aws|boto3|botocore|s3|ec2|lambda|dynamodb|sqs|sns|ses|route53|cloudfront|cloudwatch|iam|kms|secrets.?manager|ssm|ecs|eks|fargate|amplify|appsync|cognito|step.?functions|eventbridge|kinesis|firehose|glue|athena|redshift|rds|aurora|neptune|timestream|qldb|managed.?blockchain|elasticache|elasticsearch.?service|opensearch|msk|mq|docdb|memorydb", "AWS service", "Good: using AWS", Severity.INFO),
            # GCP
            (r"gcp|gcloud|firebase|firestore|cloud.?functions|cloud.?run|cloud.?build|cloud.?storage|cloud.?sql|cloud.?pubsub|cloud.?bigquery|cloud.?dataflow|cloud.?dataproc|cloud.?composer|cloud.?spanner|cloud.?firestore|cloud.?memorystore|cloud.?dns|cloud.?cdn|cloud.?armor|cloud.?load|cloud.?monitoring|cloud.?logging|cloud.?trace|cloud.?profiler|cloud.?debugger|cloud.?scheduler|cloud.?tasks|cloud.?vision|cloud.?speech|cloud.?translate|cloud.?natural|cloud.?ml|ai.?platform|vertex.?ai|bigquery|datastore", "GCP service", "Good: using GCP", Severity.INFO),
            # Azure
            (r"azure|azure.?functions|azure.?storage|azure.?sql|azure.?cosmos|azure.?redis|azure.?service|azure.?event|azure.?signalr|azure.?search|azure.?cognitive|azure.?form|azure.?document|azure.?video|azure.?speech|azure.?translation|azure.?bot|azure.?devops|azure.?pipelines|azure.?repos|azure.?artifacts|azure.?boards|azure.?test|azure.?monitor|azure.?log|azure.?application|azure.?keyvault|azure.?identity|azure.?credentials|azure.?management|azure.?resource|azure.?deploy|azure.?arm|azure.?bicep|azure.?terraform|azure.?ansible", "Azure service", "Good: using Azure", Severity.INFO),
            # Serverless
            (r"serverless|sls|lambda|function\.handler|function\.context|function\.event|function\.callback|serverless\.yml|serverless\.ts|serverless\.js", "Serverless", "Good: using serverless", Severity.INFO),
            (r"netlify\.functions|netlify\.edge|netlify\.background|netlify\.blobs|netlify\.identity", "Netlify", "Good: using Netlify", Severity.INFO),
            (r"vercel\.functions|vercel\.edge|vercel\.blob|vercel\.kv|vercel\.postgres|vercel\.postgres\.edge|vercel\.redis|vercel\.cron|vercel\.analytics|vercel\.speed|vercel\.sentry", "Vercel", "Good: using Vercel", Severity.INFO),
            (r"cloudflare\.workers|cloudflare\.kv|cloudflare\.d1|cloudflare\.r2|cloudflare\.durable|cloudflare\.pages|cloudflare\.images|cloudflare\.stream|cloudflare\.analytics|cloudflare\.zaraz|cloudflare\.turnstile|cloudflare\.waf|cloudflare\.cdn|cloudflare\.dns|cloudflare\.email|cloudflare\.spectrum|cloudflare\.load|cloudflare\.ssl|cloudflare\.zero|cloudflare\.tunnel|cloudflare\.warp", "Cloudflare", "Good: using Cloudflare", Severity.INFO),
            # Container orchestration
            (r"kubernetes|kubectl|helm|kustomize|skaffold|tilt|devspace|docker|docker-compose|podman|containerd|cri-o|runc|buildah|buildkit", "Container orchestration", "Good: using container tools", Severity.INFO),
            # CI/CD
            (r"Jenkins|GitLab|GitHub|CircleCI|Travis|Azure|Pipelines|ArgoCD|Flux|Tekton|Drone|Woodpecker|Buildkite|TeamCity|Bamboo|Buddy|Codeship|Bitbucket|Harness|Spinnaker|Octopus|Deploy", "CI/CD", "Good: using CI/CD", Severity.INFO),
            # Monitoring
            (r"Prometheus|Grafana|Datadog|New Relic|Dynatrace|Splunk|ELK|Jaeger|Zipkin|OpenTelemetry|OpenMetrics|StatsD|Graphite|CollectD|Telegraf|Fluentd|FluentBit|Logstash|Filebeat|Metricbeat|Heartbeat|Packetbeat|APM", "Monitoring/Observability", "Good: using monitoring tools", Severity.INFO),
            # Security
            (r"Vault|HashiCorp|Consul|Nomad|Waypoint|Boundary|Sentinel|Atlantis|Packer|Vagrant|Terraform|Terragrunt|Terratest|Checkov|tfsec|tflint|Snyk|SonarQube|OWASP|ZAP|Burp|Nmap|Metasploit|Cobalt|Nessus|Qualys|Rapid7", "Security tool", "Good: using security tools", Severity.INFO),
            # Infrastructure
            (r"Terraform|Terragrunt|Pulumi|Ansible|Chef|Puppet|SaltStack|CloudFormation|ARM|Bicep|CDK|SST|Crossplane", "Infrastructure as Code", "Good: using IaC", Severity.INFO),
            # Service mesh
            (r"Istio|Envoy|Linkerd|Consul|Cilium|Kong|Tyk|Traefik|NGINX|HAProxy|Varnish|Gloo|Ambassador|Emissary|APISIX|Grafana|Tempo|Mimir|Loki|Pyroscope", "Service mesh/API Gateway", "Good: using service mesh", Severity.INFO),
            # Message queues
            (r"RabbitMQ|Kafka|NATS|Redis|Pulsar|ZeroMQ|ActiveMQ|IBM MQ|Amazon SQS|Amazon SNS|Google Pub/Sub|Azure Service Bus|Azure Queue", "Message queue", "Good: using message queues", Severity.INFO),
            # Caching
            (r"Redis|Memcached|Hazelcast|Ehcache|Caffeine|Guava|Aerospike|Dragonfly|KeyDB|Valkey", "Caching system", "Good: using caching", Severity.INFO),
            # Search
            (r"Elasticsearch|OpenSearch|Solr|Meilisearch|Typesense|Algolia|Splunk|Grafana Loki", "Search engine", "Good: using search engine", Severity.INFO),
            # Analytics
            (r"Google Analytics|Mixpanel|Amplitude|Segment|Heap|Hotjar|FullStory|LogRocket|PostHog|Plausible|Umami|Matomo", "Analytics", "Good: using analytics", Severity.INFO),
            # Payment
            (r"Stripe|PayPal|Braintree|Square|Adyen|Authorize\.net|Checkout|PaymentIntent|PaymentMethod|Customer|Subscription|Invoice|Webhook|Charge|Refund|Dispute|Payout|Connect|Identity|Radar|Tax|Terminal|Sigma|Climate|Issuing|Treasury|Financial Connections|Payment Links|Payment Request|SetupIntent", "Payment processing", "Good: using payment processing", Severity.INFO),
            # Email
            (r"SendGrid|Mailgun|Postmark|SES|SparkPost|Mailchimp|Brevo|Mailtrap|EmailOctopus|Moosend|MailerLite|ConvertKit", "Email service", "Good: using email service", Severity.INFO),
            # CMS
            (r"Contentful|Sanity|Strapi|Directus|Payload|Keystone|Ghost|WordPress|Drupal|Joomla|Netlify CMS|Decap|Storyblok|Contentstack|Kontent|Prismic|Butter", "CMS", "Good: using CMS", Severity.INFO),
            # Storage
            (r"S3|Cloud Storage|Azure Blob|MinIO|R2|DigitalOcean Spaces|Wasabi|B2|Backblaze|Google Drive|Dropbox|OneDrive", "Cloud storage", "Good: using cloud storage", Severity.INFO),
            # Authentication
            (r"Auth0|Firebase Auth|Supabase Auth|Cognito|Keycloak|Okta|Ping Identity|OneLogin|JumpCloud|Azure AD|AWS SSO|Duo|YubiKey|TOTP|OAuth|OIDC|SAML|JWT|session|cookie|token", "Authentication", "Good: using authentication", Severity.INFO),
            # Feature flags
            (r"LaunchDarkly|Split|Flagsmith|Unleash|Flipt|ConfigCat|Eppo|GrowthBook|Statsig|Harness|FeatureFlag|feature.?flag|toggle|experiment|A/B", "Feature flags", "Good: using feature flags", Severity.INFO),
            # Error tracking
            (r"Sentry|Bugsnag|Rollbar|Airbrake|LogRocket|Honeybadger|Errorception|TrackJS|ErrorStackr|Sentry", "Error tracking", "Good: using error tracking", Severity.INFO),
            # APM
            (r"New Relic|Datadog|Dynatrace|AppDynamics|Elastic APM|Jaeger|Zipkin|OpenTelemetry|Prometheus|Grafana|Grafana Tempo", "APM", "Good: using APM", Severity.INFO),
            # Documentation
            (r"Swagger|OpenAPI|Postman|Insomnia|Hoppscotch|HTTPie|Thunder Client|REST Client|Bruno|Kong|Tyk|Stoplight", "API documentation", "Good: documenting APIs", Severity.INFO),
            # Version control
            (r"git|GitHub|GitLab|Bitbucket|Azure DevOps|Perforce|SVN|Mercurial|Subversion", "Version control", "Good: using version control", Severity.INFO),
            # Package managers
            (r"npm|yarn|pnpm|bun|pip|poetry|conda|cargo|go|mod|composer|gem|bundler|pub|mix|hex|nuget|maven|gradle|sbt|cocoapods|carthage|spm|homebrew|apt|yum|dnf|pacman|chocolatey|winget|scoop", "Package manager", "Good: using package manager", Severity.INFO),
            # Runtime environments
            (r"Node\.js|Deno|Bun|Python|Ruby|PHP|Java|Go|Rust|C\+\+|C#|Swift|Kotlin|Scala|Clojure|Elixir|Erlang|Haskell|OCaml|F#|Julia|R|MATLAB|SAS|SPSS|Stata|Lua|Perl|Tcl|Ada|Fortran|COBOL|Assembly", "Runtime environment", "Good: using runtime environment", Severity.INFO),
            # Databases
            (r"PostgreSQL|MySQL|MariaDB|SQLite|Oracle|SQL Server|DB2|MongoDB|Cassandra|DynamoDB|CouchDB|Redis|Memcached|Elasticsearch|Neo4j|RethinkDB|ArangoDB|RavenDB|Firebase|Firestore|Supabase|PlanetScale|TiDB|CockroachDB|YugabyteDB|Vitess|ProxySQL|MaxScale|ClickHouse|Druid|InfluxDB|TimescaleDB|QuestDB|DuckDB|Parquet|Iceberg|Delta Lake|Hudi", "Database system", "Good: using databases", Severity.INFO),
            # Kubernetes resources
            (r"Deployment|Service|Pod|Ingress|ConfigMap|Secret|StatefulSet|DaemonSet|CronJob|Job|Namespace|RBAC|Role|ClusterRole|Binding|ServiceAccount|PersistentVolume|PersistentVolumeClaim|StorageClass|NetworkPolicy|PodSecurityPolicy", "Kubernetes resource", "Good: Kubernetes resources", Severity.INFO),
            # Docker
            (r"Dockerfile|docker-compose|\.dockerignore|container|image|volume|network|build|run|push|pull|tag|inspect|logs|exec|cp|kill|stop|start|restart|rm|rmi|system|builder|manifest|swarm|service|node|config|secret", "Docker", "Good: Docker", Severity.INFO),
            # Terraform resources
            (r"resource|data|variable|output|module|backend|locals|provisioner|lifecycle|depends_on|count|for_each", "Terraform resource", "Good: Terraform resources", Severity.INFO),
            (r"aws_|azurerm_|google_|azuread_|helm_|kubernetes_|random_|local_|null_|template_|tls_|acme_|cloudflare_|digitalocean_|linode_|vultr_|hetzner_", "Terraform provider", "Good: Terraform providers", Severity.INFO),
            # Ansible
            (r"tasks|handlers|vars|defaults|files|templates|meta|roles|playbooks", "Ansible structure", "Good: Ansible structure", Severity.INFO),
            (r"name|hosts|become|gather_facts|vars|tasks|handlers|roles|tags|serial|strategy|any_errors_fatal|max_fail_percentage", "Ansible play", "Good: Ansible play", Severity.INFO),
            (r"copy|file|template|lineinfile|blockinfile|service|package|yum|apt|pip|npm|git|command|shell|user|group|cron|sysctl|wait_for|uri|debug|assert|set_fact|register|when|with_items|loop|until|retries|delay|ignore_errors", "Ansible module", "Good: Ansible modules", Severity.INFO),
            # GitHub Actions
            (r"on|jobs|steps|uses|run|with|env|name|needs|if|strategy|matrix|container|services|permissions|concurrency|defaults", "GitHub Actions", "Good: GitHub Actions", Severity.INFO),
            (r"actions/checkout|actions/setup-node|actions/setup-python|actions/cache|actions/upload-artifact|actions/download-artifact|actions/labeler|actions/stale|actions/github-script|peaceiris/actions-gh-pages|codecov", "GitHub Action", "Good: GitHub Actions", Severity.INFO),
            # GitLab CI
            (r"stages|jobs|script|before_script|after_script|services|cache|artifacts|only|except|when|rules|environment|coverage|interruptible|retry|timeout|tags|image|allow_failure|needs|dependencies|trigger|include|extends", "GitLab CI", "Good: GitLab CI", Severity.INFO),
            # Jenkins
            (r"pipeline|agent|stages|stage|steps|post|always|success|failure|cleanup|environment|parameters|options|triggers|tools|input|parallel|script|sh|bat|echo|dir|withEnv|withCredentials|node|docker", "Jenkins", "Good: Jenkins pipeline", Severity.INFO),
            # CircleCI
            (r"version|jobs|steps|checkout|run|store_test_results|store_artifacts|deploy|filters|requires|context|orbs|commands|executors|workflows|matrix|parallelism|resource_class|docker|machine|macos|windows", "CircleCI", "Good: CircleCI config", Severity.INFO),
            # ArgoCD
            (r"apiVersion|kind|metadata|spec|source|destination|path|repoURL|targetRevision|server|chart|helm|kustomize|directory|syncPolicy|automated|prune|selfHeal|syncOptions", "ArgoCD", "Good: ArgoCD config", Severity.INFO),
            # Helm
            (r"apiVersion|kind|metadata|spec|chart|version|values|set|setString|setFile|setRaw|namespace|createNamespace|atomic|cleanupOnFail|dryRun|wait|timeout|force|depUp", "Helm", "Good: Helm chart", Severity.INFO),
            # Serverless
            (r"service|provider|functions|plugins|package|custom|resources|stepFunctions", "Serverless Framework", "Good: Serverless config", Severity.INFO),
            (r"runtime|handler|memorySize|timeout|environment|events|http|schedule|s3|sns|sqs|stream|alexaSkill|iot|cloudwatchEvent|cloudWatchLog|cognitoUserPool", "Lambda function", "Good: Lambda config", Severity.INFO),
            # Monitoring tools
            (r"prometheus|Prometheus|grafana|Grafana|datadog|Datadog|new.?relic|NewRelic|dynatrace|Dynatrace|elk|ELK|Jaeger|jaeger|Zipkin|zipkin|OpenTelemetry|opentelemetry", "Monitoring tool", "Good: monitoring tools", Severity.INFO),
            # Logging tools
            (r"elasticsearch|Elasticsearch|logstash|Logstash|kibana|Kibana|fluentd|Fluentd|fluentbit|FluentBit|loki|Loki|tempo|Tempo|mimir|Mimir", "Logging tool", "Good: logging tools", Severity.INFO),
            # Caching tools
            (r"redis|Redis|memcached|Memcached|varnish|Varnish|cdn|CDN|Fastly|fastly|CloudFront|cloudfront|Cloudflare|cloudflare|Akamai|akamai", "Caching tool", "Good: caching tools", Severity.INFO),
            # Message queue tools
            (r"rabbitmq|RabbitMQ|kafka|Kafka|nats|NATS|pulsar|Pulsar|zeromq|ZeroMQ|activemq|ActiveMQ|SQS|sqs|SNS|sns|PubSub|pubsub|ServiceBus|servicebus", "Message queue tool", "Good: message queue tools", Severity.INFO),
            # Database tools
            (r"PostgreSQL|postgresql|MySQL|MySQL|MariaDB|mariadb|SQLite|sqlite|Oracle|oracle|SQL.?Server|mongodb|MongoDB|Cassandra|cassandra|DynamoDB|dynamodb|CouchDB|couchdb|Redis|redis|Memcached|memcached|Elasticsearch|elasticsearch|Neo4j|neo4j|RethinkDB|rethinkdb|ArangoDB|arangodb|RavenDB|ravendb|Firebase|firebase|Firestore|firestore|Supabase|supabase|PlanetScale|planetscale|TiDB|tidb|CockroachDB|cockroachdb|YugabyteDB|yugabytedb|Vitess|vitess|ProxySQL|proxysql|MaxScale|maxscale|ClickHouse|clickhouse|Druid|druid|InfluxDB|influxdb|TimescaleDB|timescaledb|QuestDB|questdb|DuckDB|duckdb", "Database tool", "Good: database tools", Severity.INFO),
            # CDN
            (r"CloudFront|cloudfront|Cloudflare|cloudflare|Fastly|fastly|Akamai|akamai|KeyCDN|keycdn|StackPath|stackpath|BunnyCDN|bunnycdn|Cloudinary|cloudinary", "CDN", "Good: using CDN", Severity.INFO),
            # Load balancer
            (r"ALB|alb|ELB|elb|NLB|nlb|CLB|clb|Application.?Load.?Balancer|Classic.?Load.?Balancer|Network.?Load.?Balancer|API.?Gateway|api.?gateway", "Load balancer", "Good: using load balancer", Severity.INFO),
            # WAF
            (r"WAF|waf|AWS.?WAF|ModSecurity|modsecurity|Cloudflare.?WAF|Imperva|imperva|F5.?BIG.?IP", "WAF", "Good: using WAF", Severity.INFO),
            # DDoS protection
            (r"DDoS|ddos|Cloudflare|cloudflare|Akamai|akamai|AWS.?Shield|shield", "DDoS protection", "Good: DDoS protection", Severity.INFO),
            # SSL/TLS
            (r"Let's.?Encrypt|letsencrypt|certbot|certbot|SSL|ssl|TLS|tls|certificate|Certificate|HTTPS|https", "SSL/TLS", "Good: SSL/TLS", Severity.INFO),
            # DNS
            (r"Route53|route53|Cloudflare|cloudflare|DNS|dns|domain|Domain|subdomain|Subdomain|A.?Record|AAAA|CNAME|MX|TXT|SRV", "DNS", "Good: DNS management", Severity.INFO),
            # Email
            (r"SES|ses|SendGrid|sendgrid|Mailgun|mailgun|Postmark|postmark|SparkPost|sparkpost|Mailchimp|mailchimp|Brevo|brevo|Mailtrap|mailtrap|EmailOctopus|emailoctopus|Moosend|moosend|MailerLite|mailerlite|ConvertKit|convertkit", "Email service", "Good: email service", Severity.INFO),
            # Authentication
            (r"Auth0|auth0|Firebase.?Auth|Cognito|cognito|Keycloak|keycloak|Okta|okta|Ping.?Identity|OneLogin|JumpCloud|Azure.?AD|AWS.?SSO|Duo|duo|YubiKey|yubikey|TOTP|totp|OAuth|oauth|OIDC|oidc|SAML|saml|JWT|jwt|session|Session|cookie|Cookie|token|Token)", "Authentication tool", "Good: authentication tools", Severity.INFO),
            # Monitoring
            (r"Prometheus|prometheus|Grafana|grafana|Datadog|datadog|New.?Relic|newrelic|Dynatrace|dynatrace|AppDynamics|appdynamics|Elastic.?APM|Jaeger|jaeger|Zipkin|zipkin|OpenTelemetry|opentelemetry|OpenMetrics|openmetrics|StatsD|statsd|Graphite|graphite|CollectD|collectd|Telegraf|telegraf|Fluentd|fluentd|FluentBit|fluentbit|Logstash|logstash|Filebeat|filebeat|Metricbeat|metricbeat|Heartbeat|heartbeat|Packetbeat|packetbeat|APM|apm)", "Monitoring tool", "Good: monitoring tools", Severity.INFO),
            # Security
            (r"Vault|vault|HashiCorp|hashicorp|Consul|consul|Nomad|nomad|Waypoint|waypoint|Boundary|boundary|Sentinel|sentinel|Atlantis|atlantis|Packer|packer|Vagrant|vagrant|Terraform|terraform|Terragrunt|terragrunt|Terratest|terratest|Checkov|checkov|tfsec|tfsec|tflint|tflint|Snyk|snyk|SonarQube|sonarqube|OWASP|owasp|ZAP|zap|Burp|burp|Nmap|nmap|Metasploit|metasploit|Cobalt|cobalt|Nessus|nessus|Qualys|qualys|Rapid7|rapid7)", "Security tool", "Good: security tools", Severity.INFO),
            # Infrastructure
            (r"Terraform|terraform|Terragrunt|terragrunt|Pulumi|pulumi|Ansible|ansible|Chef|chef|Puppet|puppet|SaltStack|saltstack|CloudFormation|cloudformation|ARM|arm|Bicep|bicep|CDK|cdk|SST|sst|Crossplane|crossplane)", "Infrastructure as Code", "Good: using IaC", Severity.INFO),
            # Service mesh
            (r"Istio|istio|Envoy|envoy|Linkerd|linkerd|Consul|consul|Cilium|cilium|Kong|kong|Tyk|tyk|Traefik|traefik|NGINX|nginx|HAProxy|haproxy|Varnish|varnish|Gloo|gloo|Ambassador|ambassador|Emissary|emissary|APISIX|apisix|Grafana|grafana|Tempo|tempo|Mimir|mimir|Loki|loki|Pyroscope|pyroscope)", "Service mesh/API Gateway", "Good: using service mesh", Severity.INFO),
            # Message queues
            (r"RabbitMQ|rabbitmq|Kafka|kafka|NATS|nats|Redis|redis|Pulsar|pulsar|ZeroMQ|zeromq|ActiveMQ|activemq|IBM.?MQ|SQS|SNS|PubSub|ServiceBus|Queue)", "Message queue", "Good: using message queue", Severity.INFO),
            # Caching
            (r"Redis|redis|Memcached|memcached|Hazelcast|hazelcast|Ehcache|ehcache|Caffeine|caffeine|Guava|guava|Aerospike|aerospike|Dragonfly|dragonfly|KeyDB|keydb|Valkey|valkey)", "Caching system", "Good: using caching", Severity.INFO),
            # Search
            (r"Elasticsearch|elasticsearch|OpenSearch|opensearch|Solr|solr|Meilisearch|meilisearch|Typesense|typesense|Algolia|algolia|Splunk|splunk|Loki|loki)", "Search engine", "Good: using search engine", Severity.INFO),
            # Analytics
            (r"Google.?Analytics|Mixpanel|mixpanel|Amplitude|amplitude|Segment|segment|Heap|heap|Hotjar|hotjar|FullStory|fullstory|LogRocket|logrocket|PostHog|posthog|Plausible|plausible|Umami|umami|Matomo|matomo)", "Analytics tool", "Good: analytics tools", Severity.INFO),
            # Payment
            (r"Stripe|stripe|PayPal|paypal|Braintree|braintree|Square|square|Adyen|adyen|Checkout|PaymentIntent|PaymentMethod|Customer|Subscription|Invoice|Webhook|Charge|Refund|Dispute|Payout|Connect|Identity|Radar|Tax|Terminal|Sigma|Climate|Issuing|Treasury|Financial|Payment|SetupIntent)", "Payment tool", "Good: payment tools", Severity.INFO),
            # Email
            (r"SendGrid|sendgrid|Mailgun|mailgun|Postmark|postmark|SES|ses|SparkPost|sparkpost|Mailchimp|mailchimp|Brevo|brevo|Mailtrap|mailtrap|EmailOctopus|emailoctopus|Moosend|moosend|MailerLite|mailerlite|ConvertKit|convertkit)", "Email tool", "Good: email tools", Severity.INFO),
            # CMS
            (r"Contentful|contentful|Sanity|sanity|Strapi|strapi|Directus|directus|Payload|payload|Keystone|keystone|Ghost|ghost|WordPress|wordpress|Drupal|drupal|Joomla|joomla|Netlify.?CMS|Decap|Storyblok|storyblok|Contentstack|contentstack|Kontent|kontent|Prismic|prismic|Butter|butter)", "CMS tool", "Good: CMS tools", Severity.INFO),
            # Storage
            (r"S3|s3|Cloud.?Storage|Azure.?Blob|MinIO|minio|R2|r2|DigitalOcean.?Spaces|Wasabi|wasabi|B2|b2|Backblaze|backblaze|Google.?Drive|Dropbox|OneDrive)", "Storage tool", "Good: storage tools", Severity.INFO),
        ]
        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith('#') or stripped.startswith('//'):
                continue
            for pattern, message, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    issues.append(self._create_issue(
                        file_path=file_path, line=line_num, message=message,
                        suggestion=message, severity=severity, code_snippet=stripped,
                    ))
        return issues
