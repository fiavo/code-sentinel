"""
CI/CD and pipeline patterns.
"""
import re
from ..core.models import CodeIssue, Severity, IssueCategory
from ..core.rules import BaseRule


class CICDPipelineRules(BaseRule):
    @property
    def name(self) -> str:
        return "cicd_pipeline"
    @property
    def description(self) -> str:
        return "CI/CD and pipeline patterns"
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
            # GitHub Actions
            (r"on:|push:|pull_request:|schedule:|workflow_dispatch:|workflow_call:|repository_dispatch:|release:|create:|delete:|deployment:|deployment_status:|discussion:|fork:|gollum:|issues:|label:|milestone:|page_build:|project:|public:|pull_request_review:|pull_request_target:|registry_package:|status:|watch:|watcher", "GitHub Actions event", "Good: GitHub Actions event", Severity.INFO),
            (r"jobs:|steps:|uses:|run:|with:|env:|name:|needs:|if:|strategy:|matrix:|container:|services:|permissions:|concurrency:|defaults:|timeout-minutes:|runs-on:", "GitHub Actions config", "Good: GitHub Actions config", Severity.INFO),
            (r"actions/checkout@|actions/setup-node@|actions/setup-python@|actions/cache@|actions/upload-artifact@|actions/download-artifact@|actions/labeler@|actions/stale@|actions/github-script@|peaceiris/actions-gh-pages@|codecov/codecov-action@|coverallsapp/github-action@|github/codeql-action/", "GitHub Action", "Good: GitHub Actions", Severity.INFO),
            # GitLab CI
            (r"stages:|jobs:|script:|before_script:|after_script:|services:|cache:|artifacts:|only:|except:|when:|rules:|environment:|coverage:|interruptible:|retry:|timeout:|tags:|image:|allow_failure:|needs:|dependencies:|trigger:|include:|extends:|variables:|default:|workflow:|secrets:", "GitLab CI", "Good: GitLab CI", Severity.INFO),
            (r"\.gitlab-ci\.yml|\.gitlab-ci\.yaml", "GitLab CI file", "Good: GitLab CI file", Severity.INFO),
            # Jenkins
            (r"pipeline|agent|stages|stage|steps|post|always|success|failure|cleanup|environment|parameters|options|triggers|tools|input|parallel|script|sh|bat|echo|dir|withEnv|withCredentials|node|docker", "Jenkins", "Good: Jenkins pipeline", Severity.INFO),
            (r"Jenkinsfile|jenkins", "Jenkins file", "Good: Jenkins file", Severity.INFO),
            # CircleCI
            (r"version:|jobs:|steps:|checkout:|run:|store_test_results:|store_artifacts:|deploy:|filters:|requires:|context:|orbs:|commands:|executors:|workflows:|matrix:|parallelism:|resource_class:|docker:|machine:|macos:|windows:", "CircleCI", "Good: CircleCI config", Severity.INFO),
            (r"\.circleci/config\.yml", "CircleCI file", "Good: CircleCI file", Severity.INFO),
            # Travis CI
            (r"language:|os:|dist:|sudo:|cache:|addons:|install:|script:|after_success:|after_failure:|after_script:|before_install:|before_script:|env:|matrix:|branches:|notifications:|deploy:|stages:|jobs:", "Travis CI", "Good: Travis CI", Severity.INFO),
            (r"\.travis\.yml", "Travis file", "Good: Travis file", Severity.INFO),
            # Azure DevOps
            (r"trigger:|pr:|pool:|vmImage:|stages:|stage:|job:|steps:|task:|script:|bash:|pwsh:|powershell:|cmd:|checkout:|repository:|resources:|variables:|parameters:|templates:|extends:|condition:|displayName:|name:|target:|strategy:|continueOnError:|env:", "Azure DevOps", "Good: Azure DevOps", Severity.INFO),
            (r"azure-pipelines\.yml|azure-pipelines\.yaml", "Azure file", "Good: Azure pipeline file", Severity.INFO),
            # ArgoCD
            (r"apiVersion:|kind:|metadata:|spec:|source:|destination:|path:|repoURL:|targetRevision:|server:|chart:|helm:|kustomize:|directory:|syncPolicy:|automated:|prune:|selfHeal:|syncOptions:", "ArgoCD", "Good: ArgoCD config", Severity.INFO),
            # Flux
            (r"Kustomization:|HelmRelease:|HelmRepository:|GitRepository:|OCIRepository:|Bucket:|ImageRepository:|ImagePolicy:|ImageUpdateAutomation:|Receiver:|Alert:|Provider:|Ealert:|Certificate:|ClusterKustomization:", "Flux", "Good: Flux config", Severity.INFO),
            # Tekton
            (r"Task:|Pipeline:|PipelineRun:|TaskRun:|ClusterTask:|ClusterTriggerBinding:|ClusterInterceptor:|TriggerBinding:|TriggerTemplate:|EventListener:", "Tekton", "Good: Tekton config", Severity.INFO),
            # Build tools
            (r"make|Make|Makefile|makefile|GNUmakefile|just|justfile|Taskfile|taskfile|mage|Magefile|magefile|gradle|gradlew|Maven|mvn|cargo|go build|npm run|yarn build|pnpm build|bun build|tsc|webpack|vite|rollup|esbuild|parcel|snowpack|turbopack|swc|babel", "Build tool", "Good: build tools", Severity.INFO),
            # Testing in CI
            (r"test|jest|vitest|mocha|karma|ava|tape|uvu|pytest|unittest|phpunit|junit|rspec|minitest|gotest|cargo test|go test|dotnet test|gradle test|mvn test|npm test|yarn test|pnpm test|bun test", "CI testing", "Good: CI testing", Severity.INFO),
            # Code quality in CI
            (r"lint|format|prettier|eslint|stylelint|mypy|pylint|flake8|ruff|black|isort|clippy|rustfmt|gofmt|golangci-lint|shellcheck|hadolint|commitlint|sonarqube|sonarcloud|codeclimate|codacy|codefactor|deepsource|lgtm|snyk|trivy|checkov|tfsec|tflint|semgrep|bandit|safety|pip-audit|cargo-audit|cargo-deny|govulncheck|npm-audit|yarn-audit|pnpm-audit", "Code quality tool", "Good: code quality in CI", Severity.INFO),
            # Deployment
            (r"deploy|Deploy|DEPLOY|deployment|Deployment|DEPLOYMENT|release|Release|RELEASE|publish|Publish|PUBLISH|ship|Ship|SHIP", "Deployment", "Good: deployment", Severity.INFO),
            (r"canary|Canary|blue.?green|Blue.?Green|rolling|Rolling|feature.?flag|Feature.?Flag|dark.?launch|Dark.?Launch|shadow|Shadow|a/b|A/B", "Deployment strategy", "Good: deployment strategies", Severity.INFO),
            # Environment management
            (r"staging|Staging|STAGING|development|Development|DEVELOPMENT|production|Production|PRODUCTION|sandbox|Sandbox|SANDBOX|dev|DEV|test|TEST|qa|QA|preprod|PreProd|PREPROD|canary|Canary|CANARY", "Environment", "Good: environment management", Severity.INFO),
            # Secrets management
            (r"secrets|Secrets|SECRETS|vault|Vault|VAULT|secret|Secret|SECRET|credential|Credential|CREDENTIAL|token|Token|TOKEN|key|Key|KEY|password|Password|PASSWORD", "Secrets management", "Good: secrets management", Severity.INFO),
            (r"secrets\.\w+|env:\s*\w+|environment:\s*\w+|env\.secrets\.\w+|vars\.\w+|secrets\.\w+", "Secret reference", "Good: secret reference", Severity.INFO),
            # Artifacts
            (r"artifact|Artifact|ARTIFACT|build|Build|BUILD|output|Output|OUTPUT|package|Package|PACKAGE|dist|Dist|DIST|bin|Bin|BIN", "Build artifact", "Good: build artifacts", Severity.INFO),
            # Cache
            (r"cache|Cache|CACHE|restore|Restore|RESTORE|save|Save|SAVE", "CI cache", "Good: CI caching", Severity.INFO),
            # Notifications
            (r"notify|Notify|NOTIFY|notification|Notification|NOTIFICATION|slack|Slack|email|Email|webhook|Webhook", "CI notification", "Good: CI notifications", Severity.INFO),
        ]
        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith('#') or stripped.startswith('//') or stripped.startswith('##'):
                continue
            for pattern, message, severity in patterns:
                if re.search(pattern, line):
                    issues.append(self._create_issue(
                        file_path=file_path, line=line_num, message=message,
                        suggestion=message, severity=severity, code_snippet=stripped,
                    ))
        return issues
