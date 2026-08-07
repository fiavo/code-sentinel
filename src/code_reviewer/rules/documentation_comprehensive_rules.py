"""
Comprehensive documentation and documentation patterns.
"""
import re
from ..core.models import CodeIssue, Severity, IssueCategory
from ..core.rules import BaseRule


class DocumentationComprehensiveRules(BaseRule):
    @property
    def name(self) -> str:
        return "documentation_comprehensive"
    @property
    def description(self) -> str:
        return "Comprehensive documentation patterns"
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
            # Documentation formats
            (r"README|readme|CHANGELOG|changelog|CONTRIBUTING|contributing|LICENSE|license", "Documentation file", "Good: documentation files", Severity.INFO),
            (r"API.?doc|api.?doc|ApiDoc|APIDOC|doc.?string|docstring|Docstring", "API documentation", "Good: API documentation", Severity.INFO),
            (r"Javadoc|javadoc|JAVADOC|JSDoc|jsdoc|JSDOC|JSDoc|javadoc|Javadoc|PHPDoc|phpdoc|PHPDOC|Python.?doc|pydoc|PYDOC|Javadoc|javadoc|JAVADOC", "Doc comments", "Good: doc comments", Severity.INFO),
            (r"doc|Doc|DOC|documentation|Documentation|DOCUMENTATION", "Documentation", "Good: documentation", Severity.INFO),
            # Documentation tools
            (r"Sphinx|sphinx|SPHINX|MkDocs|mkdocs|MKDOCS|Docusaurus|docusaurus|DOCAUSAURUS|VuePress|vuepress|VUEPRESS|Nextra|nextra|NEXTRA", "Doc tools", "Good: documentation tools", Severity.INFO),
            (r"Swagger|swagger|SWAGGER|OpenAPI|openapi|OPENAPI|Postman|postman|POSTMAN|Insomnia|insomnia|INSOMNIA|Hoppscotch|hoppscotch|HOPPSCOTCH", "API doc tools", "Good: API documentation tools", Severity.INFO),
            # Documentation comments
            (r"///\s+\w+", "Doc comment", "Good: doc comment", Severity.INFO),
            (r"//!\s+\w+", "Module doc", "Good: module doc", Severity.INFO),
            (r"/\*\*\s+\w+", "Javadoc", "Good: Javadoc", Severity.INFO),
            (r"\"\"\"", "Docstring", "Good: docstring", Severity.INFO),
            (r"'''\s*$", "Docstring", "Good: docstring", Severity.INFO),
            (r"#\s*TODO\s*:", "TODO", "Address the TODO", Severity.INFO),
            (r"#\s*FIXME\s*:", "FIXME", "Fix the issue", Severity.INFO),
            (r"#\s*HACK\s*:", "HACK", "Refactor the hack", Severity.INFO),
            (r"#\s*XXX\s*:", "XXX", "Address the XXX", Severity.INFO),
            (r"#\s*NOTE\s*:", "NOTE", "Good: note comment", Severity.INFO),
            (r"#\s*REVIEW\s*:", "REVIEW", "Review the code", Severity.INFO),
            (r"#\s*BUG\s*:", "BUG", "Fix the bug", Severity.INFO),
            (r"#\s*WORKAROUND\s*:", "WORKAROUND", "Find proper solution", Severity.INFO),
            # Version control docs
            (r"README\.md|readme\.md|CONTRIBUTING\.md|contributing\.md|CHANGELOG\.md|changelog\.md|LICENSE\.md|license\.md|CODE_OF_CONDUCT\.md", "Repository docs", "Good: repository documentation", Severity.INFO),
            # API documentation
            (r"@param|@return|@throws|@exception|@deprecated|@since|@version|@author|@see|@link|@example|@code|@endcode|@verbatim|@endverbatim", "Doc tags", "Good: documentation tags", Severity.INFO),
            # Documentation structure
            (r"##\s+\w+", "Section heading", "Good: section heading", Severity.INFO),
            (r"###\s+\w+", "Subsection heading", "Good: subsection heading", Severity.INFO),
            (r"####\s+\w+", "Subsubsection heading", "Good: subsubsection heading", Severity.INFO),
            (r"#####\s+\w+", "Heading level 5", "Good: heading level 5", Severity.INFO),
            (r"######\s+\w+", "Heading level 6", "Good: heading level 6", Severity.INFO),
            (r"```", "Code block", "Good: code block", Severity.INFO),
            (r"~~~", "Code block", "Good: code block", Severity.INFO),
            (r"`[^`]+`", "Inline code", "Good: inline code", Severity.INFO),
            (r"\[[^\]]+\]\([^)]+\)", "Link", "Good: link", Severity.INFO),
            (r"!\[[^\]]*\]\([^)]+\)", "Image", "Good: image", Severity.INFO),
            (r"\|[^|]+\|[^|]+\|", "Table", "Good: table", Severity.INFO),
            (r"^- \w+", "List item", "Good: list item", Severity.INFO),
            (r"^\d+\. \w+", "Numbered list", "Good: numbered list", Severity.INFO),
            (r"^>\s+\w+", "Blockquote", "Good: blockquote", Severity.INFO),
            (r"^---$", "Horizontal rule", "Good: horizontal rule", Severity.INFO),
            (r"^\*\*\*+$", "Horizontal rule", "Good: horizontal rule", Severity.INFO),
            # Documentation best practices
            (r"example|Example|EXAMPLE|usage|Usage|USAGE|tutorial|Tutorial|TUTORIAL|guide|Guide|GUIDE|howto|HowTo|HOWTO", "Documentation type", "Good: documentation types", Severity.INFO),
            (r"architecture|Architecture|ARCHITECTURE|design|Design|DESIGN|overview|Overview|OVERVIEW|introduction|Introduction|INTRODUCTION", "Documentation type", "Good: documentation types", Severity.INFO),
            (r"installation|Installation|INSTALLATION|setup|Setup|SETUP|getting.?started|GettingStarted|GETTING_STARTED|quickstart|QuickStart|QUICKSTART", "Documentation type", "Good: documentation types", Severity.INFO),
            (r"reference|Reference|REFERENCE|api|API|documentation|Documentation|DOCUMENTATION|specification|Specification|SPECIFICATION", "Documentation type", "Good: documentation types", Severity.INFO),
            (r"changelog|Changelog|CHANGELOG|release.?notes|ReleaseNotes|RELEASE_NOTES|history|History|HISTORY", "Changelog", "Good: changelog", Severity.INFO),
            (r"contributing|Contributing|CONTRIBUTING|contribution|Contribution|CONTRIBUTION|guidelines|Guidelines|GUIDELINES", "Contributing guide", "Good: contributing guide", Severity.INFO),
            (r"code.?of.?conduct|CodeOfConduct|CODE_OF_CONDUCT|behavior|Behavior|BEHAVIOR|community|Community|COMMUNITY", "Community docs", "Good: community docs", Severity.INFO),
            (r"license|License|LICENSE|copyright|Copyright|COPYRIGHT|terms|Terms|TERMS|privacy|Privacy|PRIVACY", "Legal docs", "Good: legal docs", Severity.INFO),
            (r"security|Security|SECURITY|vulnerability|Vulnerability|VULNERABILITY|disclosure|Disclosure|DISCLOSURE", "Security docs", "Good: security docs", Severity.INFO),
            (r"support|Support|SUPPORT|help|Help|HELP|faq|FAQ|troubleshooting|Troubleshooting|TROUBLESHOOTING", "Support docs", "Good: support docs", Severity.INFO),
            (r"roadmap|Roadmap|ROADMAP|future|Future|FUTURE|plans|Plans|PLANS|milestones|Milestones|MILESTONES", "Roadmap", "Good: roadmap", Severity.INFO),
            (r"badge|Badge|BADGE|shield|Shield|SHIELD|icon|Icon|ICON|logo|Logo|LOGO", "Badge/Logo", "Good: badges/logos", Severity.INFO),
            (r"table.?of.?contents|TableOfContents|TABLE_OF_CONTENTS|toc|TOC", "Table of contents", "Good: table of contents", Severity.INFO),
            (r"navigation|Navigation|NAVIGATION|sidebar|Sidebar|SIDEBAR|menu|Menu|MENU", "Navigation", "Good: navigation", Severity.INFO),
            (r"search|Search|SEARCH|index|Index|INDEX|glossary|Glossary|GLOSSARY", "Search/Index", "Good: search/index", Severity.INFO),
            (r"tutorial|Tutorial|TUTORIAL|walkthrough|Walkthrough|WALKTHROUGH|step.?by.?step|StepByStep|STEP_BY_STEP", "Tutorial", "Good: tutorial", Severity.INFO),
            (r"example|Example|EXAMPLE|sample|Sample|SAMPLE|demo|Demo|DEMO|snippet|Snippet|SNIPPET", "Example", "Good: examples", Severity.INFO),
            (r"recipe|Recipe|RECOIPatterns|pattern|Pattern|PATTERN|idiom|Idiom|IDIOM|best.?practice|BestPractice|BEST_PRACTICE", "Pattern", "Good: patterns", Severity.INFO),
            (r"troubleshooting|Troubleshooting|TROUBLESHOOTING|debugging|Debugging|DEBUGGING|diagnostics|Diagnostics|DIAGNOSTICS", "Troubleshooting", "Good: troubleshooting", Severity.INFO),
            (r"migration|Migration|MIGRATION|upgrade|Upgrade|UPGRADE|breaking.?change|BreakingChange|BREAKING_CHANGE", "Migration guide", "Good: migration guide", Severity.INFO),
            (r"benchmark|Benchmark|BENCHMARK|performance|Performance|PERFORMANCE|optimization|Optimization|OPTIMIZATION", "Performance guide", "Good: performance guide", Severity.INFO),
            (r"security|Security|SECURITY|hardening|Hardening|HARDENING|best.?practice|BestPractice|BEST_PRACTICE", "Security guide", "Good: security guide", Severity.INFO),
            (r"deployment|Deployment|DEPLOYMENT|operations|Operations|OPERATIONS|infrastructure|Infrastructure|INFRASTRUCTURE", "Operations guide", "Good: operations guide", Severity.INFO),
            (r"monitoring|Monitoring|MONITORING|logging|Logging|LOGGING|tracing|Tracing|TRACING|observability|Observability|OBSERVABILITY", "Monitoring guide", "Good: monitoring guide", Severity.INFO),
            (r"testing|Testing|TESTING|qa|QA|quality|Quality|QUALITY|coverage|Coverage|COVERAGE", "Testing guide", "Good: testing guide", Severity.INFO),
            (r"ci/?cd|CI/?CD|continuous|Continuous|CONTINUOUS|pipeline|Pipeline|PIPELINE|automation|Automation|AUTOMATION", "CI/CD guide", "Good: CI/CD guide", Severity.INFO),
            (r"docker|Docker|DOCKER|container|Container|CONTAINER|kubernetes|Kubernetes|KUBERNETES", "Container guide", "Good: container guide", Severity.INFO),
            (r"cloud|Cloud|CLOUD|aws|AWS|azure|Azure|AZURE|gcp|GCP", "Cloud guide", "Good: cloud guide", Severity.INFO),
            (r"database|Database|DATABASE|sql|SQL|nosql|NoSQL|orm|ORM", "Database guide", "Good: database guide", Severity.INFO),
            (r"api|API|rest|REST|graphql|GraphQL|grpc|gRPC|websocket|WebSocket", "API guide", "Good: API guide", Severity.INFO),
            (r"frontend|Frontend|FRONTEND|backend|Backend|BACKEND|fullstack|FullStack|FULLSTACK", "Architecture guide", "Good: architecture guide", Severity.INFO),
            (r"mobile|Mobile|MOBILE|ios|IOS|android|Android|ANDROID", "Mobile guide", "Good: mobile guide", Severity.INFO),
            (r"security|Security|SECURITY|authentication|Authentication|AUTHENTICATION|authorization|Authorization|AUTHORIZATION", "Security guide", "Good: security guide", Severity.INFO),
            (r"performance|Performance|PERFORMANCE|optimization|Optimization|OPTIMIZATION|caching|Caching|CACHING", "Performance guide", "Good: performance guide", Severity.INFO),
            (r"scalability|Scalability|SCALABILITY|reliability|Reliability|RELIABILITY|availability|Availability|AVAILABILITY", "Scalability guide", "Good: scalability guide", Severity.INFO),
            (r"disaster|Disaster|DISASTER|recovery|Recovery|RECOVERY|backup|Backup|BACKUP|restore|Restore|RESTORE", "Disaster recovery guide", "Good: disaster recovery guide", Severity.INFO),
            (r"compliance|Compliance|COMPLIANCE|regulation|Regulation|REGULATION|gdpr|GDPR|hipaa|HIPAA|pci|PCI", "Compliance guide", "Good: compliance guide", Severity.INFO),
            (r"accessibility|Accessibility|ACCESSIBILITY|a11y|A11Y|wcag|WCAG|aria|ARIA", "Accessibility guide", "Good: accessibility guide", Severity.INFO),
            (r"internationalization|Internationalization|INTERNATIONALIZATION|i18n|I18N|localization|Localization|LOCALIZATION|l10n|L10N", "Internationalization guide", "Good: i18n guide", Severity.INFO),
            (r"versioning|Versioning|VERSIONING|semver|SemVer|SEMVER|release|Release|RELEASE", "Versioning guide", "Good: versioning guide", Severity.INFO),
            (r"changelog|Changelog|CHANGELOG|history|History|HISTORY|release.?notes|ReleaseNotes|RELEASE_NOTES", "Changelog", "Good: changelog", Severity.INFO),
            (r"contributing|Contributing|CONTRIBUTING|guidelines|Guidelines|GUIDELINES|code.?of.?conduct|CodeOfConduct|CODE_OF_CONDUCT", "Contributing guide", "Good: contributing guide", Severity.INFO),
            (r"license|License|LICENSE|copyright|Copyright|COPYRIGHT|terms|Terms|TERMS|privacy|Privacy|PRIVACY", "Legal docs", "Good: legal docs", Severity.INFO),
            (r"security|Security|SECURITY|vulnerability|Vulnerability|VULNERABILITY|disclosure|Disclosure|DISCLOSURE", "Security docs", "Good: security docs", Severity.INFO),
            (r"support|Support|SUPPORT|help|Help|HELP|faq|FAQ|troubleshooting|Troubleshooting|TROUBLESHOOTING", "Support docs", "Good: support docs", Severity.INFO),
            (r"roadmap|Roadmap|ROADMAP|future|Future|FUTURE|plans|Plans|PLANS|milestones|Milestones|MILESTONES", "Roadmap", "Good: roadmap", Severity.INFO),
            (r"badge|Badge|BADGE|shield|Shield|SHIELD|icon|Icon|ICON|logo|Logo|LOGO", "Badge/Logo", "Good: badges/logos", Severity.INFO),
            (r"table.?of.?contents|TableOfContents|TABLE_OF_CONTENTS|toc|TOC", "Table of contents", "Good: table of contents", Severity.INFO),
            (r"navigation|Navigation|NAVIGATION|sidebar|Sidebar|SIDEBAR|menu|Menu|MENU", "Navigation", "Good: navigation", Severity.INFO),
            (r"search|Search|SEARCH|index|Index|INDEX|glossary|Glossary|GLOSSARY", "Search/Index", "Good: search/index", Severity.INFO),
            (r"tutorial|Tutorial|TUTORIAL|walkthrough|Walkthrough|WALKTHROUGH|step.?by.?step|StepByStep|STEP_BY_STEP", "Tutorial", "Good: tutorial", Severity.INFO),
            (r"example|Example|EXAMPLE|sample|Sample|SAMPLE|demo|Demo|DEMO|snippet|Snippet|SNIPPET", "Example", "Good: examples", Severity.INFO),
            (r"recipe|Recipe|RECIPE|pattern|Pattern|PATTERN|idiom|Idiom|IDIOM|best.?practice|BestPractice|BEST_PRACTICE", "Pattern", "Good: patterns", Severity.INFO),
            (r"troubleshooting|Troubleshooting|TROUBLESHOOTING|debugging|Debugging|DEBUGGING|diagnostics|Diagnostics|DIAGNOSTICS", "Troubleshooting", "Good: troubleshooting", Severity.INFO),
            (r"migration|Migration|MIGRATION|upgrade|Upgrade|UPGRADE|breaking.?change|BreakingChange|BREAKING_CHANGE", "Migration guide", "Good: migration guide", Severity.INFO),
            (r"benchmark|Benchmark|BENCHMARK|performance|Performance|PERFORMANCE|optimization|Optimization|OPTIMIZATION", "Performance guide", "Good: performance guide", Severity.INFO),
            (r"security|Security|SECURITY|hardening|Hardening|HARDENING|best.?practice|BestPractice|BEST_PRACTICE", "Security guide", "Good: security guide", Severity.INFO),
            (r"deployment|Deployment|DEPLOYMENT|operations|Operations|OPERATIONS|infrastructure|Infrastructure|INFRASTRUCTURE", "Operations guide", "Good: operations guide", Severity.INFO),
            (r"monitoring|Monitoring|MONITORING|logging|Logging|LOGGING|tracing|Tracing|TRACING|observability|Observability|OBSERVABILITY", "Monitoring guide", "Good: monitoring guide", Severity.INFO),
            (r"testing|Testing|TESTING|qa|QA|quality|Quality|QUALITY|coverage|Coverage|COVERAGE", "Testing guide", "Good: testing guide", Severity.INFO),
            (r"ci/?cd|CI/?CD|continuous|Continuous|CONTINUOUS|pipeline|Pipeline|PIPELINE|automation|Automation|AUTOMATION", "CI/CD guide", "Good: CI/CD guide", Severity.INFO),
            (r"docker|Docker|DOCKER|container|Container|CONTAINER|kubernetes|Kubernetes|KUBERNETES", "Container guide", "Good: container guide", Severity.INFO),
            (r"cloud|Cloud|CLOUD|aws|AWS|azure|Azure|AZURE|gcp|GCP", "Cloud guide", "Good: cloud guide", Severity.INFO),
            (r"database|Database|DATABASE|sql|SQL|nosql|NoSQL|orm|ORM", "Database guide", "Good: database guide", Severity.INFO),
            (r"api|API|rest|REST|graphql|GraphQL|grpc|gRPC|websocket|WebSocket", "API guide", "Good: API guide", Severity.INFO),
            (r"frontend|Frontend|FRONTEND|backend|Backend|BACKEND|fullstack|FullStack|FULLSTACK", "Architecture guide", "Good: architecture guide", Severity.INFO),
            (r"mobile|Mobile|MOBILE|ios|IOS|android|Android|ANDROID", "Mobile guide", "Good: mobile guide", Severity.INFO),
            (r"security|Security|SECURITY|authentication|Authentication|AUTHENTICATION|authorization|Authorization|AUTHORIZATION", "Security guide", "Good: security guide", Severity.INFO),
            (r"performance|Performance|PERFORMANCE|optimization|Optimization|OPTIMIZATION|caching|Caching|CACHING", "Performance guide", "Good: performance guide", Severity.INFO),
            (r"scalability|Scalability|SCALABILITY|reliability|Reliability|RELIABILITY|availability|Availability|AVAILABILITY", "Scalability guide", "Good: scalability guide", Severity.INFO),
            (r"disaster|Disaster|DISASTER|recovery|Recovery|RECOVERY|backup|Backup|BACKUP|restore|Restore|RESTORE", "Disaster recovery guide", "Good: disaster recovery guide", Severity.INFO),
            (r"compliance|Compliance|COMPLIANCE|regulation|Regulation|REGULATION|gdpr|GDPR|hipaa|HIPAA|pci|PCI", "Compliance guide", "Good: compliance guide", Severity.INFO),
            (r"accessibility|Accessibility|ACCESSIBILITY|a11y|A11Y|wcag|WCAG|aria|ARIA", "Accessibility guide", "Good: accessibility guide", Severity.INFO),
            (r"internationalization|Internationalization|INTERNATIONALIZATION|i18n|I18N|localization|Localization|LOCALIZATION|l10n|L10N", "Internationalization guide", "Good: i18n guide", Severity.INFO),
            (r"versioning|Versioning|VERSIONING|semver|SemVer|SEMVER|release|Release|RELEASE", "Versioning guide", "Good: versioning guide", Severity.INFO),
            (r"changelog|Changelog|CHANGELOG|history|History|HISTORY|release.?notes|ReleaseNotes|RELEASE_NOTES", "Changelog", "Good: changelog", Severity.INFO),
            (r"contributing|Contributing|CONTRIBUTING|guidelines|Guidelines|GUIDELINES|code.?of.?conduct|CodeOfConduct|CODE_OF_CONDUCT", "Contributing guide", "Good: contributing guide", Severity.INFO),
            (r"license|License|LICENSE|copyright|Copyright|COPYRIGHT|terms|Terms|TERMS|privacy|Privacy|PRIVACY", "Legal docs", "Good: legal docs", Severity.INFO),
            (r"security|Security|SECURITY|vulnerability|Vulnerability|VULNERABILITY|disclosure|Disclosure|DISCLOSURE", "Security docs", "Good: security docs", Severity.INFO),
            (r"support|Support|SUPPORT|help|Help|HELP|faq|FAQ|troubleshooting|Troubleshooting|TROUBLESHOOTING", "Support docs", "Good: support docs", Severity.INFO),
            (r"roadmap|Roadmap|ROADMAP|future|Future|FUTURE|plans|Plans|PLANS|milestones|Milestones|MILESTONES", "Roadmap", "Good: roadmap", Severity.INFO),
            (r"badge|Badge|BADGE|shield|Shield|SHIELD|icon|Icon|ICON|logo|Logo|LOGO", "Badge/Logo", "Good: badges/logos", Severity.INFO),
            (r"table.?of.?contents|TableOfContents|TABLE_OF_CONTENTS|toc|TOC", "Table of contents", "Good: table of contents", Severity.INFO),
            (r"navigation|Navigation|NAVIGATION|sidebar|Sidebar|SIDEBAR|menu|Menu|MENU", "Navigation", "Good: navigation", Severity.INFO),
            (r"search|Search|SEARCH|index|Index|INDEX|glossary|Glossary|GLOSSARY", "Search/Index", "Good: search/index", Severity.INFO),
            (r"tutorial|Tutorial|TUTORIAL|walkthrough|Walkthrough|WALKTHROUGH|step.?by.?step|StepByStep|STEP_BY_STEP", "Tutorial", "Good: tutorial", Severity.INFO),
            (r"example|Example|EXAMPLE|sample|Sample|SAMPLE|demo|Demo|DEMO|snippet|Snippet|SNIPPET", "Example", "Good: examples", Severity.INFO),
            (r"recipe|Recipe|RECIPE|pattern|Pattern|PATTERN|idiom|Idiom|IDIOM|best.?practice|BestPractice|BEST_PRACTICE", "Pattern", "Good: patterns", Severity.INFO),
            (r"troubleshooting|Troubleshooting|TROUBLESHOOTING|debugging|Debugging|DEBUGGING|diagnostics|Diagnostics|DIAGNOSTICS", "Troubleshooting", "Good: troubleshooting", Severity.INFO),
            (r"migration|Migration|MIGRATION|upgrade|Upgrade|UPGRADE|breaking.?change|BreakingChange|BREAKING_CHANGE", "Migration guide", "Good: migration guide", Severity.INFO),
            (r"benchmark|Benchmark|BENCHMARK|performance|Performance|PERFORMANCE|optimization|Optimization|OPTIMIZATION", "Performance guide", "Good: performance guide", Severity.INFO),
            (r"security|Security|SECURITY|hardening|Hardening|HARDENING|best.?practice|BestPractice|BEST_PRACTICE", "Security guide", "Good: security guide", Severity.INFO),
            (r"deployment|Deployment|DEPLOYMENT|operations|Operations|OPERATIONS|infrastructure|Infrastructure|INFRASTRUCTURE", "Operations guide", "Good: operations guide", Severity.INFO),
            (r"monitoring|Monitoring|MONITORING|logging|Logging|LOGGING|tracing|Tracing|TRACING|observability|Observability|OBSERVABILITY", "Monitoring guide", "Good: monitoring guide", Severity.INFO),
            (r"testing|Testing|TESTING|qa|QA|quality|Quality|QUALITY|coverage|Coverage|COVERAGE", "Testing guide", "Good: testing guide", Severity.INFO),
            (r"ci/?cd|CI/?CD|continuous|Continuous|CONTINUOUS|pipeline|Pipeline|PIPELINE|automation|Automation|AUTOMATION", "CI/CD guide", "Good: CI/CD guide", Severity.INFO),
            (r"docker|Docker|DOCKER|container|Container|CONTAINER|kubernetes|Kubernetes|KUBERNETES", "Container guide", "Good: container guide", Severity.INFO),
            (r"cloud|Cloud|CLOUD|aws|AWS|azure|Azure|AZURE|gcp|GCP", "Cloud guide", "Good: cloud guide", Severity.INFO),
            (r"database|Database|DATABASE|sql|SQL|nosql|NoSQL|orm|ORM", "Database guide", "Good: database guide", Severity.INFO),
            (r"api|API|rest|REST|graphql|GraphQL|grpc|gRPC|websocket|WebSocket", "API guide", "Good: API guide", Severity.INFO),
            (r"frontend|Frontend|FRONTEND|backend|Backend|BACKEND|fullstack|FullStack|FULLSTACK", "Architecture guide", "Good: architecture guide", Severity.INFO),
            (r"mobile|Mobile|MOBILE|ios|IOS|android|Android|ANDROID", "Mobile guide", "Good: mobile guide", Severity.INFO),
        ]
        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith('#') or stripped.startswith('//') or stripped.startswith('/*'):
                continue
            for pattern, message, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    issues.append(self._create_issue(
                        file_path=file_path, line=line_num, message=message,
                        suggestion=message, severity=severity, code_snippet=stripped,
                    ))
        return issues
