"""
Comprehensive DevOps patterns for CI/CD, deployment, and infrastructure.
"""
import re
from ..core.models import CodeIssue, Severity, IssueCategory
from ..core.rules import BaseRule


class DevOpsComprehensiveRules(BaseRule):
    @property
    def name(self) -> str:
        return "devops_comprehensive"
    @property
    def description(self) -> str:
        return "Comprehensive DevOps patterns"
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
            # CI/CD
            (r"(?:ci|cd|pipeline|Pipeline|CI|CD|continuous|Continuous|CONTINUOUS|integration|Integration|INTEGRATION|delivery|Delivery|DELIVERY|deployment|Deployment|DEPLOYMENT)", "CI/CD", "Good: using CI/CD", Severity.INFO),
            (r"(?:build|Build|BUILD|compile|Compile|COMPILE|bundle|Bundle|BUNDLE|minify|Minify|MINIFY|uglify|Uglify|UGLIFY|transpile|Transpile|TRANSPILE)", "Build process", "Good: building project", Severity.INFO),
            (r"(?:test|Test|TEST|spec|Spec|SPEC|lint|Lint|LINT|format|Format|FORMAT|check|Check|CHECK|validate|Validate|VALIDATE)", "Testing/quality", "Good: testing code", Severity.INFO),
            (r"(?:deploy|Deploy|DEPLOY|release|Release|RELEASE|rollback|Rollback|ROLLBACK|canary|Canary|CANARY|blue.?green|BlueGreen|rolling|Rolling|ROLLING|shadow|Shadow|SHADOW)", "Deployment", "Good: managing deployments", Severity.INFO),
            # Monitoring
            (r"(?:monitor|Monitor|MONITOR|alert|Alert|ALERT|dashboard|Dashboard|DASHBOARD|report|Report|REPORT|log|Log|LOG|trace|Trace|TRACE|metric|Metric|METRIC)", "Monitoring", "Good: monitoring system", Severity.INFO),
            # Disaster recovery
            (r"(?:backup|Backup|BACKUP|restore|Restore|RESTORE|recovery|Recovery|RECOVERY|disaster|Disaster|DISASTER)", "Disaster recovery", "Good: implementing disaster recovery", Severity.INFO),
            # Security
            (r"(?:security|Security|SECURITY|vulnerability|Vulnerability|VULNERABILITY|patch|Patch|PATCH|update|Update|UPDATE|upgrade|Upgrade|UPGRADE)", "Security", "Good: managing security", Severity.INFO),
            # Performance
            (r"(?:performance|Performance|PERFORMANCE|optimize|Optimize|OPTIMIZE|cache|Cache|CACHE|compress|Compress|COMPRESS|cdn|CDN)", "Performance", "Good: optimizing performance", Severity.INFO),
            # Scalability
            (r"(?:scalab|Scalab|SCALAB|elastic|Elastic|ELASTIC|auto.?scale|AutoScale|load.?balanc|LoadBalanc)", "Scalability", "Good: designing for scalability", Severity.INFO),
            # Configuration
            (r"(?:config|Config|CONFIG|env|ENV|secret|Secret|SECRET|vault|Vault|VAULT|feature.?flag|FeatureFlag|FEATURE_FLAG)", "Configuration", "Good: managing configuration", Severity.INFO),
            # Logging
            (r"(?:log|Log|LOG|audit|Audit|AUDIT|trace|Trace|TRACE|metric|Metric|METRIC|analytics|Analytics|ANALYTICS)", "Logging", "Good: logging appropriately", Severity.INFO),
            # Containerization
            (r"(?:container|Container|CONTAINER|docker|Docker|DOCKER|kubernetes|Kubernetes|KUBERNETES|k8s|K8S|podman|Podman|PODMAN)", "Containerization", "Good: using containers", Severity.INFO),
            # Infrastructure as Code
            (r"(?:terraform|Terraform|TERRAFORM|ansible|Ansible|ANSIBLE|chef|Chef|CHEF|puppet|Puppet|PUPPET|salt|Salt|SALT)", "Infrastructure as Code", "Good: using IaC", Severity.INFO),
            # Cloud platforms
            (r"(?:cloud|Cloud|CLOUD|aws|AWS|azure|Azure|AZURE|gcp|GCP|vercel|Vercel|VERCEL|netlify|Netlify|NETLIFY)", "Cloud platform", "Good: using cloud platform", Severity.INFO),
            # Version control
            (r"(?:git|Git|GIT|github|GitHub|GITHUB|gitlab|GitLab|GITLAB|bitbucket|Bitbucket|BITBUCKET|svn|SVN)", "Version control", "Good: using version control", Severity.INFO),
            # Package managers
            (r"(?:npm|NPM|yarn|Yarn|YARN|pnpm|Pnpm|PNPM|pip|PIP|cargo|Cargo|CARGO|go|GO|mod|MOD|composer|Composer|COMPOSER|gem|Gem|GEM|bundler|Bundler|BUNDLER|pub|Pub|PUB|mix|Mix|MIX|hex|Hex|HEX|nuget|NuGet|NUGET|maven|Maven|MAVEN|gradle|Gradle|GRADLE|sbt|SBT|cocoapods|CocoaPods|carthage|Carthage|spm|SPM|homebrew|Homebrew|apt|APT|yum|YUM|dnf|DNF|pacman|Pacman|chocolatey|Chocolatey|winget|Winget|scoop|Scoop)", "Package manager", "Good: using package manager", Severity.INFO),
            # Runtime environments
            (r"(?:Node\.js|node|NODE|deno|Deno|DENO|bun|Bun|BUN|python|Python|PYTHON|ruby|Ruby|RUBY|php|PHP|java|Java|JAVA|go|Go|rust|Rust|RUST|c\+\+|C\+\+|c#|C#|swift|Swift|SWIFT|kotlin|Kotlin|KOTLIN|scala|Scala|SCALA|clojure|Clojure|CLOJURE|elixir|Elixir|ELIXIR|erlang|Erlang|ERLANG|haskell|Haskell|HASKELL|ocaml|OCaml|f#|F#|julia|Julia|JULIA|r|R|matlab|MATLAB|sas|SAS|spss|SPSS|stata|Stata|STATA|lua|Lua|LUA|perl|Perl|PERL|tcl|Tcl|TCL|ada|Ada|ADA|fortran|Fortran|FORTRAN|cobol|Cobol|assembly|Assembly|ASSEMBLY)", "Runtime environment", "Good: using runtime environment", Severity.INFO),
            # Databases
            (r"(?:PostgreSQL|postgresql|MYSQL|MySQL|MariaDB|mariadb|SQLite|sqlite|Oracle|oracle|SQL.?Server|mongodb|MongoDB|MONGODB|Cassandra|cassandra|DynamoDB|dynamodb|CouchDB|couchdb|Redis|redis|Memcached|memcached|Elasticsearch|elasticsearch|Neo4j|neo4j|RethinkDB|rethinkdb|ArangoDB|arangodb|RavenDB|ravendb|Firebase|firebase|Firestore|firestore|Supabase|supabase|PlanetScale|planetscale|TiDB|tidb|CockroachDB|cockroachdb|YugabyteDB|yugabytedb|Vitess|vitess|ProxySQL|proxysql|MaxScale|maxscale|ClickHouse|clickhouse|Druid|druid|InfluxDB|influxdb|TimescaleDB|timescaledb|QuestDB|questdb|DuckDB|duckdb)", "Database system", "Good: using databases", Severity.INFO),
            # Message queues
            (r"(?:RabbitMQ|rabbitmq|Kafka|kafka|NATS|nats|Redis|redis|Pulsar|pulsar|ZeroMQ|zeromq|ActiveMQ|activemq|IBM.?MQ|SQS|SNS|PubSub|ServiceBus|Queue)", "Message queue", "Good: using message queue", Severity.INFO),
            # Caching
            (r"(?:Redis|redis|Memcached|memcached|Hazelcast|hazelcast|Ehcache|ehcache|Caffeine|caffeine|Guava|guava|Aerospike|aerospike|Dragonfly|dragonfly|KeyDB|keydb|Valkey|valkey)", "Caching system", "Good: using caching", Severity.INFO),
            # Search engines
            (r"(?:Elasticsearch|elasticsearch|OpenSearch|opensearch|Solr|solr|Meilisearch|meilisearch|Typesense|typesense|Algolia|algolia|Splunk|splunk|Loki|loki)", "Search engine", "Good: using search engine", Severity.INFO),
            # Analytics
            (r"(?:Google.?Analytics|Mixpanel|mixpanel|Amplitude|amplitude|Segment|segment|Heap|heap|Hotjar|hotjar|FullStory|fullstory|LogRocket|logrocket|PostHog|posthog|Plausible|plausible|Umami|umami|Matomo|matomo)", "Analytics", "Good: using analytics", Severity.INFO),
            # Payment
            (r"(?:Stripe|stripe|PayPal|paypal|Braintree|braintree|Square|square|Adyen|adyen|Checkout|PaymentIntent|PaymentMethod|Customer|Subscription|Invoice|Webhook|Charge|Refund|Dispute|Payout|Connect|Identity|Radar|Tax|Terminal|Sigma|Climate|Issuing|Treasury|Financial|Payment|SetupIntent)", "Payment processing", "Good: using payment processing", Severity.INFO),
            # Email
            (r"(?:SendGrid|sendgrid|Mailgun|mailgun|Postmark|postmark|SES|ses|SparkPost|sparkpost|Mailchimp|mailchimp|Brevo|brevo|Mailtrap|mailtrap|EmailOctopus|emailoctopus|Moosend|moosend|MailerLite|mailerlite|ConvertKit|convertkit)", "Email service", "Good: using email service", Severity.INFO),
            # CMS
            (r"(?:Contentful|contentful|Sanity|sanity|Strapi|strapi|Directus|directus|Payload|payload|Keystone|keystone|Ghost|ghost|WordPress|wordpress|Drupal|drupal|Joomla|joomla|Netlify.?CMS|Decap|Storyblok|storyblok|Contentstack|contentstack|Kontent|kontent|Prismic|prismic|Butter|butter)", "CMS", "Good: using CMS", Severity.INFO),
            # Storage
            (r"(?:S3|s3|Cloud.?Storage|Azure.?Blob|MinIO|minio|R2|r2|DigitalOcean.?Spaces|Wasabi|wasabi|B2|b2|Backblaze|backblaze|Google.?Drive|Dropbox|OneDrive)", "Cloud storage", "Good: using cloud storage", Severity.INFO),
            # Authentication
            (r"(?:Auth0|auth0|Firebase.?Auth|Supabase.?Auth|Cognito|cognito|Keycloak|keycloak|Okta|okta|Ping.?Identity|OneLogin|JumpCloud|Azure.?AD|AWS.?SSO|Duo|duo|YubiKey|yubikey|TOTP|totp|OAuth|oauth|OIDC|oidc|SAML|saml|JWT|jwt|session|Session|cookie|Cookie|token|Token)", "Authentication", "Good: using authentication", Severity.INFO),
            # Feature flags
            (r"(?:LaunchDarkly|launchdarkly|Split|split|Flagsmith|flagsmith|Unleash|unleash|Flipt|flipt|ConfigCat|configcat|Eppo|eppo|GrowthBook|growthbook|Statsig|statsig|Harness|harness|FeatureFlag|feature.?flag|toggle|experiment|A/B)", "Feature flags", "Good: using feature flags", Severity.INFO),
            # Error tracking
            (r"(?:Sentry|sentry|Bugsnag|bugsnag|Rollbar|rollbar|Airbrake|airbrake|LogRocket|logrocket|Honeybadger|honeybadger|Errorception|errorception|TrackJS|trackjs|ErrorStackr|errorstackr)", "Error tracking", "Good: using error tracking", Severity.INFO),
            # APM
            (r"(?:New.?Relic|newrelic|Datadog|datadog|Dynatrace|dynatrace|AppDynamics|appdynamics|Elastic.?APM|Jaeger|jaeger|Zipkin|zipkin|OpenTelemetry|opentelemetry|Prometheus|prometheus|Grafana|grafana|Tempo|tempo)", "APM", "Good: using APM", Severity.INFO),
            # API documentation
            (r"(?:Swagger|swagger|OpenAPI|openapi|Postman|postman|Insomnia|insomnia|Hoppscotch|hoppscotch|HTTPie|httpie|Thunder.?Client|REST.?Client|Bruno|bruno|Stoplight|stoplight)", "API documentation", "Good: documenting APIs", Severity.INFO),
            # Docker
            (r"(?:Dockerfile|dockerfile|docker-compose|docker.?compose|\.dockerignore|dockerignore)", "Docker config", "Good: Docker configuration", Severity.INFO),
            (r"(?:FROM|RUN|COPY|ADD|CMD|ENTRYPOINT|ENV|ARG|EXPOSE|VOLUME|WORKDIR|USER|LABEL|STOPSIGNAL|HEALTHCHECK|SHELL)", "Dockerfile instruction", "Good: Dockerfile instructions", Severity.INFO),
            (r"(?:services|build|image|container_name|ports|volumes|environment|depends_on|networks|restart|command|entrypoint)", "Docker Compose", "Good: Docker Compose config", Severity.INFO),
            # Kubernetes
            (r"(?:apiVersion|kind|metadata|spec|selector|template|replicas|containers|ports|env|volumeMounts|volumes|resources|requests|limits|livenessProbe|readinessProbe|startupProbe)", "Kubernetes manifest", "Good: Kubernetes configuration", Severity.INFO),
            (r"(?:Deployment|Service|Pod|Ingress|ConfigMap|Secret|StatefulSet|DaemonSet|CronJob|Job|Namespace|RBAC|Role|ClusterRole|Binding|ServiceAccount|PersistentVolume|PersistentVolumeClaim|StorageClass|NetworkPolicy)", "Kubernetes resource", "Good: Kubernetes resources", Severity.INFO),
            # Terraform
            (r"(?:resource|data|variable|output|module|backend|locals|provisioner|lifecycle|depends_on|count|for_each)", "Terraform resource", "Good: Terraform resources", Severity.INFO),
            (r"(?:aws_|azurerm_|google_|azuread_|helm_|kubernetes_|random_|local_|null_|template_|tls_|acme_|cloudflare_|digitalocean_|linode_|vultr_|hetzner_)", "Terraform provider", "Good: Terraform providers", Severity.INFO),
            # Ansible
            (r"(?:tasks|handlers|vars|defaults|files|templates|meta|roles|playbooks)", "Ansible structure", "Good: Ansible structure", Severity.INFO),
            (r"(?:name|hosts|become|gather_facts|vars|tasks|handlers|roles|tags|serial|strategy|any_errors_fatal|max_fail_percentage)", "Ansible play", "Good: Ansible play", Severity.INFO),
            (r"(?:copy|file|template|lineinfile|blockinfile|service|package|yum|apt|pip|npm|git|command|shell|user|group|cron|sysctl|wait_for|uri|debug|assert|set_fact|register|when|with_items|loop|until|retries|delay|ignore_errors)", "Ansible module", "Good: Ansible modules", Severity.INFO),
            # GitHub Actions
            (r"(?:on|jobs|steps|uses|run|with|env|name|needs|if|strategy|matrix|container|services|permissions|concurrency|defaults)", "GitHub Actions", "Good: GitHub Actions", Severity.INFO),
            (r"(?:actions/checkout|actions/setup-node|actions/setup-python|actions/cache|actions/upload-artifact|actions/download-artifact|actions/labeler|actions/stale|actions/github-script|peaceiris/actions-gh-pages|codecov)", "GitHub Action", "Good: GitHub Actions", Severity.INFO),
            # GitLab CI
            (r"(?:stages|jobs|script|before_script|after_script|services|cache|artifacts|only|except|when|rules|environment|coverage|interruptible|retry|timeout|tags|image|allow_failure|needs|dependencies|trigger|include|extends)", "GitLab CI", "Good: GitLab CI", Severity.INFO),
            # Jenkins
            (r"(?:pipeline|agent|stages|stage|steps|post|always|success|failure|cleanup|environment|parameters|options|triggers|tools|input|parallel|script|sh|bat|echo|dir|withEnv|withCredentials|node|docker)", "Jenkins", "Good: Jenkins pipeline", Severity.INFO),
            # CircleCI
            (r"(?:version|jobs|steps|checkout|run|store_test_results|store_artifacts|deploy|filters|requires|context|orbs|commands|executors|workflows|matrix|parallelism|resource_class|docker|machine|macos|windows)", "CircleCI", "Good: CircleCI config", Severity.INFO),
            # ArgoCD
            (r"(?:apiVersion|kind|metadata|spec|source|destination|path|repoURL|targetRevision|server|chart|helm|kustomize|directory|syncPolicy|automated|prune|selfHeal|syncOptions)", "ArgoCD", "Good: ArgoCD config", Severity.INFO),
            # Helm
            (r"(?:apiVersion|kind|metadata|spec|chart|version|values|set|setString|setFile|setRaw|namespace|createNamespace|atomic|cleanupOnFail|dryRun|wait|timeout|force|depUp)", "Helm", "Good: Helm chart", Severity.INFO),
            # Serverless
            (r"(?:service|provider|functions|plugins|package|custom|resources|stepFunctions)", "Serverless Framework", "Good: Serverless config", Severity.INFO),
            (r"(?:runtime|handler|memorySize|timeout|environment|events|http|schedule|s3|sns|sqs|stream|alexaSkill|iot|cloudwatchEvent|cloudWatchLog|cognitoUserPool)", "Lambda function", "Good: Lambda config", Severity.INFO),
            # Monitoring tools
            (r"(?:prometheus|Prometheus|grafana|Grafana|datadog|Datadog|new.?relic|NewRelic|dynatrace|Dynatrace|elk|ELK|Jaeger|jaeger|Zipkin|zipkin|OpenTelemetry|opentelemetry)", "Monitoring tool", "Good: monitoring tools", Severity.INFO),
            # Logging tools
            (r"(?:elasticsearch|Elasticsearch|logstash|Logstash|kibana|Kibana|fluentd|Fluentd|fluentbit|FluentBit|loki|Loki|tempo|Tempo|mimir|Mimir)", "Logging tool", "Good: logging tools", Severity.INFO),
            # Caching tools
            (r"(?:redis|Redis|memcached|Memcached|varnish|Varnish|cdn|CDN|Fastly|fastly|CloudFront|cloudfront|Cloudflare|cloudflare|Akamai|akamai)", "Caching tool", "Good: caching tools", Severity.INFO),
            # Message queue tools
            (r"(?:rabbitmq|RabbitMQ|kafka|Kafka|nats|NATS|pulsar|Pulsar|zeromq|ZeroMQ|activemq|ActiveMQ|SQS|sqs|SNS|sns|PubSub|pubsub|ServiceBus|servicebus)", "Message queue tool", "Good: message queue tools", Severity.INFO),
            # Database tools
            (r"(?:PostgreSQL|postgresql|MySQL|MySQL|MariaDB|mariadb|SQLite|sqlite|Oracle|oracle|SQL.?Server|mongodb|MongoDB|Cassandra|cassandra|DynamoDB|dynamodb|CouchDB|couchdb|Redis|redis|Memcached|memcached|Elasticsearch|elasticsearch|Neo4j|neo4j|RethinkDB|rethinkdb|ArangoDB|arangodb|RavenDB|ravendb|Firebase|firebase|Firestore|firestore|Supabase|supabase|PlanetScale|planetscale|TiDB|tidb|CockroachDB|cockroachdb|YugabyteDB|yugabytedb|Vitess|vitess|ProxySQL|proxysql|MaxScale|maxscale|ClickHouse|clickhouse|Druid|druid|InfluxDB|influxdb|TimescaleDB|timescaledb|QuestDB|questdb|DuckDB|duckdb)", "Database tool", "Good: database tools", Severity.INFO),
            # CDN
            (r"(?:CloudFront|cloudfront|Cloudflare|cloudflare|Fastly|fastly|Akamai|akamai|KeyCDN|keycdn|StackPath|stackpath|BunnyCDN|bunnycdn|Cloudinary|cloudinary)", "CDN", "Good: using CDN", Severity.INFO),
            # Load balancer
            (r"(?:ALB|alb|ELB|elb|NLB|nlb|CLB|clb|Application.?Load.?Balancer|Classic.?Load.?Balancer|Network.?Load.?Balancer|API.?Gateway|api.?gateway)", "Load balancer", "Good: using load balancer", Severity.INFO),
            # WAF
            (r"(?:WAF|waf|AWS.?WAF|ModSecurity|modsecurity|Cloudflare.?WAF|Imperva|imperva|F5.?BIG.?IP)", "WAF", "Good: using WAF", Severity.INFO),
            # DDoS protection
            (r"(?:DDoS|ddos|Cloudflare|cloudflare|Akamai|akamai|AWS.?Shield|shield)", "DDoS protection", "Good: DDoS protection", Severity.INFO),
            # SSL/TLS
            (r"(?:Let's.?Encrypt|letsencrypt|certbot|certbot|SSL|ssl|TLS|tls|certificate|Certificate|HTTPS|https)", "SSL/TLS", "Good: SSL/TLS", Severity.INFO),
            # DNS
            (r"(?:Route53|route53|Cloudflare|cloudflare|DNS|dns|domain|Domain|subdomain|Subdomain|A.?Record|AAAA|CNAME|MX|TXT|SRV)", "DNS", "Good: DNS management", Severity.INFO),
            # Email
            (r"(?:SES|ses|SendGrid|sendgrid|Mailgun|mailgun|Postmark|postmark|SparkPost|sparkpost|Mailchimp|mailchimp|Brevo|brevo|Mailtrap|mailtrap|EmailOctopus|emailoctopus|Moosend|moosend|MailerLite|mailerlite|ConvertKit|convertkit)", "Email service", "Good: email service", Severity.INFO),
            # Authentication
            (r"(?:Auth0|auth0|Firebase.?Auth|Cognito|cognito|Keycloak|keycloak|Okta|okta|Ping.?Identity|OneLogin|JumpCloud|Azure.?AD|AWS.?SSO|Duo|duo|YubiKey|yubikey|TOTP|totp|OAuth|oauth|OIDC|oidc|SAML|saml|JWT|jwt|session|Session|cookie|Cookie|token|Token)", "Authentication tool", "Good: authentication tools", Severity.INFO),
            # Monitoring
            (r"(?:Prometheus|prometheus|Grafana|grafana|Datadog|datadog|New.?Relic|newrelic|Dynatrace|dynatrace|AppDynamics|appdynamics|Elastic.?APM|Jaeger|jaeger|Zipkin|zipkin|OpenTelemetry|opentelemetry|OpenMetrics|openmetrics|StatsD|statsd|Graphite|graphite|CollectD|collectd|Telegraf|telegraf|Fluentd|fluentd|FluentBit|fluentbit|Logstash|logstash|Filebeat|filebeat|Metricbeat|metricbeat|Heartbeat|heartbeat|Packetbeat|packetbeat|APM|apm)", "Monitoring tool", "Good: monitoring tools", Severity.INFO),
            # Security
            (r"(?:Vault|vault|HashiCorp|hashicorp|Consul|consul|Nomad|nomad|Waypoint|waypoint|Boundary|boundary|Sentinel|sentinel|Atlantis|atlantis|Packer|packer|Vagrant|vagrant|Terraform|terraform|Terragrunt|terragrunt|Terratest|terratest|Checkov|checkov|tfsec|tfsec|tflint|tflint|Snyk|snyk|SonarQube|sonarqube|OWASP|owasp|ZAP|zap|Burp|burp|Nmap|nmap|Metasploit|metasploit|Cobalt|cobalt|Nessus|nessus|Qualys|qualys|Rapid7|rapid7)", "Security tool", "Good: security tools", Severity.INFO),
            # Infrastructure
            (r"(?:Terraform|terraform|Terragrunt|terragrunt|Pulumi|pulumi|Ansible|ansible|Chef|chef|Puppet|puppet|SaltStack|saltstack|CloudFormation|cloudformation|ARM|arm|Bicep|bicep|CDK|cdk|SST|sst|Crossplane|crossplane)", "Infrastructure as Code", "Good: using IaC", Severity.INFO),
            # Service mesh
            (r"(?:Istio|istio|Envoy|envoy|Linkerd|linkerd|Consul|consul|Cilium|cilium|Kong|kong|Tyk|tyk|Traefik|traefik|NGINX|nginx|HAProxy|haproxy|Varnish|varnish|Gloo|gloo|Ambassador|ambassador|Emissary|emissary|APISIX|apisix|Grafana|grafana|Tempo|tempo|Mimir|mimir|Loki|loki|Pyroscope|pyroscope)", "Service mesh/API Gateway", "Good: using service mesh", Severity.INFO),
            # Message queues
            (r"(?:RabbitMQ|rabbitmq|Kafka|kafka|NATS|nats|Redis|redis|Pulsar|pulsar|ZeroMQ|zeromq|ActiveMQ|activemq|IBM.?MQ|SQS|SNS|PubSub|ServiceBus|Queue)", "Message queue", "Good: using message queue", Severity.INFO),
            # Caching
            (r"(?:Redis|redis|Memcached|memcached|Hazelcast|hazelcast|Ehcache|ehcache|Caffeine|caffeine|Guava|guava|Aerospike|aerospike|Dragonfly|dragonfly|KeyDB|keydb|Valkey|valkey)", "Caching system", "Good: using caching", Severity.INFO),
            # Search
            (r"(?:Elasticsearch|elasticsearch|OpenSearch|opensearch|Solr|solr|Meilisearch|meilisearch|Typesense|typesense|Algolia|algolia|Splunk|splunk|Loki|loki)", "Search engine", "Good: using search engine", Severity.INFO),
            # Analytics
            (r"(?:Google.?Analytics|Mixpanel|mixpanel|Amplitude|amplitude|Segment|segment|Heap|heap|Hotjar|hotjar|FullStory|fullstory|LogRocket|logrocket|PostHog|posthog|Plausible|plausible|Umami|umami|Matomo|matomo)", "Analytics tool", "Good: analytics tools", Severity.INFO),
            # Payment
            (r"(?:Stripe|stripe|PayPal|paypal|Braintree|braintree|Square|square|Adyen|adyen|Checkout|PaymentIntent|PaymentMethod|Customer|Subscription|Invoice|Webhook|Charge|Refund|Dispute|Payout|Connect|Identity|Radar|Tax|Terminal|Sigma|Climate|Issuing|Treasury|Financial|Payment|SetupIntent)", "Payment tool", "Good: payment tools", Severity.INFO),
            # Email
            (r"(?:SendGrid|sendgrid|Mailgun|mailgun|Postmark|postmark|SES|ses|SparkPost|sparkpost|Mailchimp|mailchimp|Brevo|brevo|Mailtrap|mailtrap|EmailOctopus|emailoctopus|Moosend|moosend|MailerLite|mailerlite|ConvertKit|convertkit)", "Email tool", "Good: email tools", Severity.INFO),
            # CMS
            (r"(?:Contentful|contentful|Sanity|sanity|Strapi|strapi|Directus|directus|Payload|payload|Keystone|keystone|Ghost|ghost|WordPress|wordpress|Drupal|drupal|Joomla|joomla|Netlify.?CMS|Decap|Storyblok|storyblok|Contentstack|contentstack|Kontent|kontent|Prismic|prismic|Butter|butter)", "CMS tool", "Good: CMS tools", Severity.INFO),
            # Storage
            (r"(?:S3|s3|Cloud.?Storage|Azure.?Blob|MinIO|minio|R2|r2|DigitalOcean.?Spaces|Wasabi|wasabi|B2|b2|Backblaze|backblaze|Google.?Drive|Dropbox|OneDrive)", "Storage tool", "Good: storage tools", Severity.INFO),
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
