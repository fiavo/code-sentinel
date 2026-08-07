"""
Comprehensive dependency management patterns.
"""
import re
from ..core.models import CodeIssue, Severity, IssueCategory
from ..core.rules import BaseRule


class DependencyComprehensiveRules(BaseRule):
    @property
    def name(self) -> str:
        return "dependency_comprehensive"
    @property
    def description(self) -> str:
        return "Comprehensive dependency patterns"
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
            # Package managers
            (r"npm|yarn|pnpm|bun|pip|poetry|conda|cargo|go|mod|composer|gem|bundler|pub|mix|hex|nuget|maven|gradle|sbt|cocoapods|carthage|spm|homebrew|apt|yum|dnf|pacman|chocolatey|winget|scoop", "Package manager", "Good: using package manager", Severity.INFO),
            # Dependencies
            (r"package\.json|requirements\.txt|Cargo\.toml|go\.mod|composer\.json|Gemfile|pubspec\.yaml|build\.gradle|pom\.xml|Package\.csproj|*.csproj|package-lock\.json|yarn\.lock|pnpm-lock\.yaml|bun\.lockb|poetry\.lock|Pipfile\.lock|Cargo\.lock|go\.sum|Gemfile\.lock|pubspec\.lock|build\.gradle\.kts", "Dependency file", "Good: dependency files", Severity.INFO),
            # Version management
            (r"semver|SemVer|semantic.?version|SemanticVersion|version.?range|VersionRange|version.?constraint|VersionConstraint|version.?pin|VersionPin|lock.?file|LockFile", "Version management", "Good: version management", Severity.INFO),
            # Security
            (r"snyk|Snyk|dependabot|Dependabot|renovate|Renovate|npm.?audit|pip.?audit|cargo.?audit|go.?vuln|audit|Audit|vulnerability|Vulnerability|CVE|cve", "Security scanning", "Good: security scanning", Severity.INFO),
            # Updates
            (r"update|Update|upgrade|Upgrade|bump|Bump|patch|Patch|minor|Minor|major|Major|changelog|Changelog|CHANGELOG|release|Release|RELEASE|breaking.?change|BreakingChange|BREAKING_CHANGE", "Version updates", "Good: version updates", Severity.INFO),
            # Installation
            (r"install|Install|INSTALL|uninstall|Uninstall|UNINSTALL|remove|Remove|REMOVE|add|Add|ADD|delete|Delete|DELETE|purge|Purge|PURGE", "Package operations", "Good: package operations", Severity.INFO),
            # Repositories
            (r"registry|Registry|REGISTRY|repository|Repository|REPOSITORY|mirror|Mirror|MIRROR|proxy|Proxy|PROXY|source|Source|SOURCE|feed|Feed|FEED|mirror|Mirror|MIRROR|repository|Repository|REPOSITORY|registry|Registry|REGISTRY", "Repository", "Good: repositories", Severity.INFO),
            # Artifacts
            (r"artifact|Artifact|ARTIFACT|bundle|Bundle|BUNDLE|package|Package|PACKAGE|archive|Archive|ARCHIVE|tarball|Tarball|TARBALL|zip|Zip|ZIP|gz|GZ|bz2|BZ2|xz|XZ|7z|7Z|rar|RAR", "Artifact", "Good: artifacts", Severity.INFO),
            # Caching
            (r"cache|Cache|CACHE|local.?cache|LocalCache|local_cache|global.?cache|GlobalCache|global_cache|shared.?cache|SharedCache|shared_cache|cache.?directory|CacheDirectory|cache_directory|cache.?size|CacheSize|cache_size|cache.?ttl|CacheTTL|cache_ttl|cache.?eviction|CacheEviction|cache_eviction|cache.?invalidation|CacheInvalidation|cache_invalidation", "Dependency cache", "Good: caching dependencies", Severity.INFO),
            # Workspaces
            (r"workspace|Workspace|WORKSPACE|monorepo|Monorepo|MONOREPO|multi.?package|MultiPackage|multi_package|polyrepo|Polyrepo|POLYREPO|lerna|Lerna|LERNA|nx|Nx|NX|turbo|Turbo|TURBO|rush|Rush|RUSH|pnpm.?workspace|pnpm_workspace", "Workspaces", "Good: workspaces/monorepo", Severity.INFO),
            # Scripts
            (r"scripts|Scripts|SCRIPTS|hooks|Hooks|HOOKS|lifecycle|Lifecycle|LIFECYCLE|preinstall|postinstall|prepare|prepublish|prepack|postpack|preuninstall|postuninstall|prerelease|postrelease|preversion|postversion|precommit|prepush|pretest|posttest|prebuild|postbuild|predeploy|postdeploy", "Scripts/hooks", "Good: scripts/hooks", Severity.INFO),
            # Configuration
            (r"config|Config|CONFIG|configuration|Configuration|CONFIGURATION|settings|Settings|SETTINGS|options|Options|OPTIONS|preferences|Preferences|PREFERENCES|env|ENV|environment|Environment|ENVIRONMENT|dotenv|Dotenv|DOTENV|\.env|\.env\.local|\.env\.production|\.env\.development|\.env\.test", "Configuration", "Good: configuration", Severity.INFO),
            # Documentation
            (r"README|readme|CHANGELOG|changelog|CONTRIBUTING|contributing|LICENSE|license|CODE_OF_CONDUCT|code_of_conduct|SECURITY|security|AUTHORS|authors|MAINTAINERS|maintainers|CONTRIBUTORS|contributors|HISTORY|history|RELEASES|releases", "Documentation", "Good: documentation", Severity.INFO),
            # Testing
            (r"test|Test|TEST|tests|Tests|TESTS|spec|Spec|SPEC|specs|Specs|SPECS|coverage|Coverage|COVERAGE|codecov|Codecov|CODECOV|coveralls|Coveralls|COVERALLS|jest|Jest|JEST|vitest|Vitest|VITEST|mocha|Mocha|MOCHA|karma|Karma|KARMA|ava|AVA|tape|Tape|TAPE|uvu|Uvu|UVU", "Testing", "Good: testing", Severity.INFO),
            # CI/CD
            (r"ci|CI|cd|CD|pipeline|Pipeline|PIPELINE|continuous|Continuous|CONTINUOUS|integration|Integration|INTEGRATION|delivery|Delivery|DELIVERY|deployment|Deployment|DEPLOYMENT|github.?actions|GitHubActions|GITHUB_ACTIONS|gitlab|GitLab|GITLAB|jenkins|Jenkins|JENKINS|circleci|CircleCI|CIRCLECI|travis|Travis|TRAVIS|azure.?devops|AzureDevOps|AZURE_DEVOPS|bitbucket|Bitbucket|BITBUCKET", "CI/CD", "Good: CI/CD", Severity.INFO),
            # Containers
            (r"docker|Docker|DOCKER|kubernetes|Kubernetes|KUBERNETES|k8s|K8S|podman|Podman|PODMAN|containerd|containerd|CONTAINERD|cri-o|cri-o|CRI-O|runc|runc|RUNC|buildah|buildah|BUILDAH|buildkit|buildkit|BUILDKIT", "Containers", "Good: containers", Severity.INFO),
            # Infrastructure
            (r"terraform|Terraform|TERRAFORM|ansible|Ansible|ANSIBLE|chef|Chef|CHEF|puppet|Puppet|PUPPET|salt|Salt|SALT|pulumi|Pulumi|PULUMI|cloudformation|CloudFormation|CLOUDFORMATION|arm|ARM|bicep|Bicep|BICEP|cdk|CDK|sst|SST|crossplane|Crossplane|CROSSPLANE", "Infrastructure", "Good: infrastructure", Severity.INFO),
            # Cloud
            (r"aws|AWS|azure|Azure|AZURE|gcp|GCP|vercel|Vercel|VERCEL|netlify|Netlify|NETLIFY|cloudflare|Cloudflare|CLOUDFLARE|firebase|Firebase|FIREBASE|supabase|Supabase|SUPABASE|railway|Railway|RAILWAY|render|Render|RENDER|fly\.io|FlyIO|DigitalOcean|digitalocean|LINODE|linode|VULTR|vultr|HETZNER|hetzner", "Cloud", "Good: cloud platforms", Severity.INFO),
            # Monitoring
            (r"prometheus|Prometheus|PROMETHEUS|grafana|Grafana|GRAFANA|datadog|Datadog|DATADOG|new.?relic|NewRelic|NEW_RELIC|dynatrace|Dynatrace|DYNATRACE|jaeger|Jaeger|JAEGER|zipkin|Zipkin|ZIPKIN|opentelemetry|OpenTelemetry|OPEN_TELEMETRY|elk|ELK|loki|Loki|LOKI|tempo|Tempo|TEMPO|mimir|Mimir|MIMIR|statsd|StatsD|STATSD|graphite|Graphite|GRAPHITE|collectd|CollectD|COLLECTD|telegraf|Telegraf|TELEGRAF|fluentd|Fluentd|FLUENTD|fluentbit|FluentBit|FLUENT_BIT|logstash|Logstash|LOGSTASH|filebeat|Filebeat|FILEBEAT|metricbeat|Metricbeat|METRICBEAT|heartbeat|Heartbeat|HEARTBEAT|packetbeat|Packetbeat|PACKETBEAT|apm|APM", "Monitoring", "Good: monitoring", Severity.INFO),
            # Logging
            (r"log|Log|LOG|logging|Logging|LOGGING|tracing|Tracing|TRACING|metrics|Metrics|METRICS|analytics|Analytics|ANALYTICS|telemetry|Telemetry|TELEMETRY|observability|Observability|OBSERVABILITY", "Logging", "Good: logging", Severity.INFO),
            # Security
            (r"security|Security|SECURITY|auth|Auth|AUTH|authentication|Authentication|AUTHENTICATION|authorization|Authorization|AUTHORIZATION|encryption|Encryption|ENCRYPTION|decryption|Decryption|DECRYPTION|hash|Hash|HASH|hmac|HMAC|HMAC|jwt|JWT|JWT|oauth|OAuth|OAUTH|saml|SAML|SAML|oidc|OIDC|OIDC|tls|TLS|TLS|ssl|SSL|SSL|certificate|Certificate|CERTIFICATE|key|Key|KEY|secret|Secret|SECRET|token|Token|TOKEN|session|Session|SESSION|cookie|Cookie|COOKIE|cors|CORS|CORS|csrf|CSRF|CSRF|xss|XSS|XSS|ssrf|SSRF|SSRF|injection|Injection|INJECTION|sanitization|Sanitization|SANITIZATION|validation|Validation|VALIDATION|escaping|Escaping|ESCAPING|encoding|Encoding|ENCODING|decoding|Decoding|DECODING|signing|Signing|SIGNING|verification|Verification|VERIFICATION", "Security", "Good: security", Severity.INFO),
            # Performance
            (r"performance|Performance|PERFORMANCE|optimization|Optimization|OPTIMIZATION|caching|Caching|CACHING|compression|Compression|COMPRESSION|cdn|CDN|CDN|lazy|Lazy|LAZY|eager|Eager|EAGER|batch|Batch|BATCH|bulk|Bulk|BULK|stream|Stream|STREAM|async|Async|ASYNC|parallel|Parallel|PARALLEL|concurrent|Concurrent|CONCURRENT|worker|Worker|WORKER|pool|Pool|POOL|queue|Queue|QUEUE|buffer|Buffer|BUFFER|cache|Cache|CACHE|memoize|Memoize|MEMOIZE|throttle|Throttle|THROTTLE|debounce|Debounce|DEBOUNCE|rate.?limit|RateLimit|RATE_LIMIT", "Performance", "Good: performance", Severity.INFO),
            # Quality
            (r"lint|Lint|LINT|format|Format|FORMAT|prettier|Prettier|PRETTIER|eslint|ESLint|ESLINT|stylelint|Stylelint|STYLELINT|mypy|Mypy|MYPY|pylint|Pylint|PYLINT|flake8|Flake8|FLAKE8|ruff|Ruff|RUFF|black|Black|BLACK|isort|Isort|ISORT|clippy|Clippy|CLippy|rustfmt|Rustfmt|RUSTFMT|gofmt|Gofmt|GOFMT|golangci|Golangci|GOLANGCI|shellcheck|Shellcheck|SHELLCHECK|hadolint|Hadolint|HADOLINT|commitlint|Commitlint|COMMITLINT|lint-staged|lint-staged|LINT_STAGED|husky|Husky|HUSKY|pre-commit|pre-commit|PRE_COMMIT|lefthook|Lefthook|LEFTHOOK|Yorkie|yorkie|YORKIE", "Code quality", "Good: code quality", Severity.INFO),
            # Documentation
            (r"swagger|Swagger|SWAGGER|openapi|OpenAPI|OPENAPI|postman|Postman|POSTMAN|insomnia|Insomnia|INSOMNIA|hoppscotch|Hoppscotch|HOPPSCOTCH|httpie|HTTPie|HTTPIE|thunder.?client|ThunderClient|REST.?Client|rest.?client|REST_CLIENT|bruno|Bruno|BRUNO|stoplight|Stoplight|STOPLIGHT|readme|README|CHANGELOG|CONTRIBUTING|LICENSE|CODE_OF_CONDUCT|SECURITY|AUTHORS|MAINTAINERS|CONTRIBUTORS|HISTORY|RELEASES", "Documentation", "Good: documentation", Severity.INFO),
            # Versioning
            (r"semver|SemVer|SEMVER|version|Version|VERSION|release|Release|RELEASE|changelog|Changelog|CHANGELOG|breaking|Breaking|BREAKING|deprecation|Deprecation|DEPRECATION|migration|Migration|MIGRATION|upgrade|Upgrade|UPGRADE|backward|Backward|BACKWARD|forward|Forward|FORWARD|compatibility|Compatibility|COMPATIBILITY", "Versioning", "Good: versioning", Severity.INFO),
            # Release
            (r"release|Release|RELEASE|deploy|Deploy|DEPLOY|publish|Publish|PUBLISH|ship|Ship|SHIP|publish|Publish|PUBLISH|upload|Upload|UPLOAD|push|Push|PUSH|tag|Tag|TAG|draft|Draft|DRAFT|prerelease|Prerelease|PRERELEASE|stable|Stable|STABLE|beta|Beta|BETA|alpha|Alpha|ALPHA|rc|RC|nightly|Nightly|NIGHTLY|snapshot|Snapshot|SNAPSHOT|canary|Canary|CANARY|latest|Latest|LATEST", "Release", "Good: release management", Severity.INFO),
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
