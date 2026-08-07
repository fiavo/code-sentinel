"""
Security patterns for common vulnerabilities and best practices.
"""

import re
from typing import Optional

from ..core.models import CodeIssue, Severity, IssueCategory
from ..core.rules import BaseRule


class SecurityPatternsRules(BaseRule):
    """Security pattern detection."""

    @property
    def name(self) -> str:
        return "security_patterns"

    @property
    def description(self) -> str:
        return "Security pattern detection"

    @property
    def category(self) -> IssueCategory:
        return IssueCategory.SECURITY

    @property
    def severity(self) -> Severity:
        return Severity.WARNING

    def check(self, file_path: str, content: str) -> list[CodeIssue]:
        issues = []
        lines = content.splitlines()

        patterns = [
            # Injection patterns
            (r"(?:sql|nosql|ldap|xpath|css|command|code|os|header|crlf|ssrf|xss|csrf|xxe)", "Injection vulnerability", "Validate and sanitize input", Severity.CRITICAL),
            (r"(?:exec|eval|system|passthru|shell_exec|popen|proc_open)", "Shell execution", "Use safe command execution", Severity.CRITICAL),
            (r"(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)", "SQL operation", "Use parameterized queries", Severity.CRITICAL),
            (r"(?:innerHTML|outerHTML|document\.write|v-html)", "XSS vulnerability", "Sanitize output", Severity.CRITICAL),
            (r"(?:eval|Function|setTimeout|setInterval).*string", "Code injection", "Avoid dynamic code execution", Severity.CRITICAL),
            (r"(?:fetch|http|request|curl|axios).*\+", "SSRF vulnerability", "Validate URLs", Severity.CRITICAL),
            (r"(?:password|secret|key|token|credential)", "Hardcoded secret", "Use environment variables", Severity.CRITICAL),
            (r"(?:md5|sha1|DES|RC4|Blowfish)", "Weak cryptography", "Use strong algorithms", Severity.WARNING),
            (r"(?:random|rand|uuid|token)", "Insecure random", "Use cryptographically secure random", Severity.WARNING),
            (r"(?:ssl|tls|certificate|private)", "TLS/SSL", "Use proper TLS configuration", Severity.INFO),
            (r"(?:cors|origin|referer|host)", "CORS/origin", "Configure CORS properly", Severity.INFO),
            (r"(?:session|cookie|token|jwt)", "Session management", "Use secure session management", Severity.INFO),
            (r"(?:upload|download|file|path|directory)", "File operation", "Validate file paths", Severity.WARNING),
            (r"(?:email|phone|address|ssn|credit)", "Sensitive data", "Protect sensitive data", Severity.WARNING),
            (r"(?:admin|root|superuser)", "Privileged access", "Verify access control", Severity.INFO),
            (r"(?:role|permission|auth)", "Access control", "Implement proper access control", Severity.INFO),
            (r"(?:rate.?limit|throttle|brute.?force)", "Rate limiting", "Implement rate limiting", Severity.INFO),
            (r"(?:hash|bcrypt|scrypt|argon2)", "Password hashing", "Use proper password hashing", Severity.INFO),
            (r"(?:encrypt|decrypt|cipher)", "Encryption", "Use proper encryption", Severity.INFO),
            (r"(?:sign|verify|hmac)", "Digital signature", "Use proper signatures", Severity.INFO),
            (r"(?:certificate|ca|pkcs|x509)", "Certificate", "Use proper certificates", Severity.INFO),
            (r"(?:keychain|keystore|vault|secret)", "Secret management", "Use proper secret management", Severity.INFO),
            (r"(?:audit|log|trace|monitor)", "Security logging", "Implement security logging", Severity.INFO),
            (r"(?:firewall|waf|ids|ips)", "Network security", "Use network security tools", Severity.INFO),
            (r"(?:antivirus|malware|virus)", "Malware protection", "Use antivirus software", Severity.INFO),
            (r"(?:backup|restore|recovery)", "Disaster recovery", "Implement disaster recovery", Severity.INFO),
            (r"(?:disaster|incident|breach|response)", "Incident response", "Have incident response plan", Severity.INFO),
            (r"(?:policy|compliance|gdpr|hipaa|pci)", "Compliance", "Ensure compliance", Severity.INFO),
            (r"(?:vulnerability|cve|patch|update)", "Vulnerability management", "Keep systems updated", Severity.INFO),
            (r"(?:penetration|pentest|security.?audit)", "Security testing", "Perform security testing", Severity.INFO),
            (r"(?:owasp|top.?10|security.?guideline)", "Security guidelines", "Follow security guidelines", Severity.INFO),
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
