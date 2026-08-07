"""
Security patterns for common vulnerabilities (OWASP Top 10).
"""

import re
from typing import Optional

from ..core.models import CodeIssue, Severity, IssueCategory
from ..core.rules import BaseRule


class OWASPRules(BaseRule):
    """OWASP Top 10 vulnerability patterns."""

    @property
    def name(self) -> str:
        return "owasp"

    @property
    def description(self) -> str:
        return "OWASP Top 10 vulnerability detection"

    @property
    def category(self) -> IssueCategory:
        return IssueCategory.SECURITY

    @property
    def severity(self) -> Severity:
        return Severity.CRITICAL

    def check(self, file_path: str, content: str) -> list[CodeIssue]:
        issues = []
        lines = content.splitlines()

        patterns = [
            # A01: Broken Access Control
            (r'(?:for|while)\s*\(.*\)', "Loop without access control", "Add authorization checks", Severity.WARNING),
            (r'(?:GET|POST|PUT|DELETE|PATCH)\s*\(', "HTTP method without auth", "Add authorization middleware", Severity.WARNING),
            (r'(?:admin|root|superuser)', "Admin/root reference", "Verify access control", Severity.INFO),
            (r'(?:role|permission|auth)', "Role/permission reference", "Good: using access control", Severity.INFO),

            # A02: Cryptographic Failures
            (r'(?:md5|sha1|sha256|sha512|bcrypt|scrypt|argon2)', "Hashing algorithm", "Use appropriate hashing", Severity.INFO),
            (r'(?:AES|DES|RSA|ECDSA|HMAC|PBKDF2)', "Encryption algorithm", "Use appropriate encryption", Severity.INFO),
            (r'(?:ssl|tls|certificate|private|public|key|secret)', "Cryptographic operation", "Use proper cryptographic practices", Severity.INFO),
            (r'(?:random|uuid|token|nonce|salt)', "Random/token generation", "Use cryptographically secure random", Severity.INFO),

            # A03: Injection
            (r'(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC)', "SQL operation", "Use parameterized queries", Severity.WARNING),
            (r'(?:exec|system|passthru|shell_exec|popen|proc_open)', "Shell command", "Use safe command execution", Severity.CRITICAL),
            (r'(?:eval|exec|compile|__import__|getattr|setattr|delattr)', "Dynamic execution", "Avoid dynamic code execution", Severity.CRITICAL),
            (r'(?:xpath|css|jq|regex)', "Query language", "Validate and sanitize queries", Severity.WARNING),

            # A04: Insecure Design
            (r'(?:trust|validate|sanitize|escape|encode|decode)', "Trust/validation", "Validate all inputs", Severity.INFO),
            (r'(?:password|secret|key|token|credential)', "Credential handling", "Use secure credential management", Severity.INFO),
            (r'(?:upload|download|file|path|directory)', "File operation", "Validate file paths and types", Severity.INFO),
            (r'(?:email|phone|address|ssn|credit)', "Sensitive data", "Protect sensitive data", Severity.INFO),

            # A05: Security Misconfiguration
            (r'(?:debug|verbose|trace|log)', "Debug/logging", "Disable debug in production", Severity.INFO),
            (r'(?:cors|origin|referer|host)', "CORS/origin", "Configure CORS properly", Severity.INFO),
            (r'(?:error|exception|stack|trace)', "Error handling", "Handle errors securely", Severity.INFO),
            (r'(?:header|cookie|session|token)', "HTTP header/cookie", "Configure headers/cookies securely", Severity.INFO),

            # A06: Vulnerable Components
            (r'(?:package|dependency|library|module|version)', "Dependency", "Keep dependencies updated", Severity.INFO),
            (r'(?:npm|pip|cargo|go|mod)', "Package manager", "Audit dependencies regularly", Severity.INFO),
            (r'(?:CVE|vulnerability|patch|update|upgrade)', "Security update", "Apply security patches", Severity.INFO),

            # A07: Authentication Failures
            (r'(?:login|logout|signup|register|password|auth)', "Authentication", "Implement proper authentication", Severity.INFO),
            (r'(?:session|cookie|token|jwt|oauth|saml)', "Session management", "Use secure session management", Severity.INFO),
            (r'(?:rate.?limit|throttle|brute.?force)', "Rate limiting", "Implement rate limiting", Severity.INFO),
            (r'(?:mfa|2fa|totp|sms|email)', "Multi-factor auth", "Implement MFA for sensitive operations", Severity.INFO),

            # A08: Software and Data Integrity Failures
            (r'(?:integrity|checksum|hash|verify|sign)', "Integrity checking", "Verify data integrity", Severity.INFO),
            (r'(?:deserializ|marshal|pickle|yaml\.load|eval)', "Deserialization", "Validate deserialized data", Severity.CRITICAL),
            (r'(?:ci|cd|pipeline|build|deploy)', "CI/CD pipeline", "Secure CI/CD pipelines", Severity.INFO),
            (r'(?:auto.?update|self.?update)', "Auto-update", "Verify update integrity", Severity.INFO),

            # A09: Security Logging and Monitoring Failures
            (r'(?:log|audit|trace|monitor|alert)', "Logging/monitoring", "Implement security logging", Severity.INFO),
            (r'(?:event|action|change|access|modification)', "Audit trail", "Log security-relevant events", Severity.INFO),
            (r'(?:incident|breach|attack|intrusion)', "Incident response", "Have incident response plan", Severity.INFO),

            # A10: Server-Side Request Forgery (SSRF)
            (r'(?:fetch|request|curl|http|url|uri)', "HTTP request", "Validate and sanitize URLs", Severity.WARNING),
            (r'(?:redirect|proxy|forward|relay)', "Request forwarding", "Validate redirect targets", Severity.WARNING),
            (r'(?:internal|private|localhost|127\.0\.0\.1|10\.|172\.|192\.168\.)', "Internal network", "Prevent access to internal resources", Severity.CRITICAL),
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
