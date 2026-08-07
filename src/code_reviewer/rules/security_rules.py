"""
Comprehensive security rules for code analysis.
Covers OWASP Top 10, common vulnerabilities, and best practices.
"""

import re
from typing import Optional

from ..core.models import CodeIssue, Severity, IssueCategory
from ..core.rules import BaseRule


class InjectionRules(BaseRule):
    """SQL, NoSQL, LDAP, OS Command Injection detection."""

    @property
    def name(self) -> str:
        return "injection"

    @property
    def description(self) -> str:
        return "Injection vulnerability detection (SQL, NoSQL, LDAP, OS Command)"

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
            # SQL Injection
            (r'(?:execute|cursor\.execute|query|raw)\s*\(\s*[\"\'].*%s', "SQL Injection via string formatting",
             "Use parameterized queries or prepared statements", Severity.CRITICAL),
            (r'(?:execute|cursor\.execute|query|raw)\s*\(\s*[\"\'].*\+', "SQL Injection via concatenation",
             "Use parameterized queries or prepared statements", Severity.CRITICAL),
            (r'(?:execute|cursor\.execute|query|raw)\s*\(\s*f[\"\']', "SQL Injection via f-string",
             "Use parameterized queries or prepared statements", Severity.CRITICAL),
            (r'(?:execute|cursor\.execute|query|raw)\s*\(\s*["\'].*\.format\(', "SQL Injection via .format()",
             "Use parameterized queries or prepared statements", Severity.CRITICAL),
            (r'(?:execute|cursor\.execute|query|raw)\s*\(\s*["\'].*\$\{', "SQL Injection via template literal",
             "Use parameterized queries or prepared statements", Severity.CRITICAL),
            (r'(?:execute|cursor\.execute|query|raw)\s*\(\s*["\'].*\?\s*', "SQL Injection via ? placeholder",
             "Use parameterized queries properly", Severity.WARNING),

            # NoSQL Injection
            (r'(?:find|findOne|update|delete)\s*\(\s*\{.*\$', "NoSQL Injection via template literal",
             "Use parameterized queries", Severity.CRITICAL),
            (r'(?:find|findOne|update|delete)\s*\(\s*\{.*\+', "NoSQL Injection via concatenation",
             "Use parameterized queries", Severity.CRITICAL),
            (r'\$where\s*:', "NoSQL $where injection risk",
             "Avoid $where; use standard query operators", Severity.CRITICAL),
            (r'\$regex\s*:', "NoSQL $regex injection risk",
             "Validate and sanitize regex patterns", Severity.WARNING),

            # LDAP Injection
            (r'(?:search|bind|modify)\s*\(.*\+', "LDAP Injection via concatenation",
             "Use proper LDAP escaping", Severity.CRITICAL),
            (r'(?:search|bind|modify)\s*\(.*%s', "LDAP Injection via string formatting",
             "Use proper LDAP escaping", Severity.CRITICAL),

            # OS Command Injection
            (r'(?:os\.system|os\.popen|subprocess\.call|subprocess\.run|subprocess\.Popen)\s*\(.*\+', "OS Command Injection via concatenation",
             "Use subprocess with shell=False and list arguments", Severity.CRITICAL),
            (r'(?:os\.system|os\.popen|subprocess\.call|subprocess\.run|subprocess\.Popen)\s*\(.*%', "OS Command Injection via string formatting",
             "Use subprocess with shell=False and list arguments", Severity.CRITICAL),
            (r'(?:os\.system|os\.popen|subprocess\.call|subprocess\.run|subprocess\.Popen)\s*\(\s*f[\"\']', "OS Command Injection via f-string",
             "Use subprocess with shell=False and list arguments", Severity.CRITICAL),
            (r'shell\s*=\s*True', "subprocess with shell=True",
             "Use shell=False with a list of arguments", Severity.CRITICAL),
            (r'(?:system|popen)\s*\(.*\$', "Shell injection via template literal",
             "Use proper escaping or parameterized commands", Severity.CRITICAL),

            # XSS (Cross-Site Scripting)
            (r'innerHTML\s*=', "innerHTML assignment - XSS risk",
             "Use textContent or sanitize input", Severity.CRITICAL),
            (r'outerHTML\s*=', "outerHTML assignment - XSS risk",
             "Use textContent or sanitize input", Severity.CRITICAL),
            (r'document\.write\s*\(', "document.write() - XSS risk",
             "Use DOM manipulation methods", Severity.WARNING),
            (r'eval\s*\(', "eval() - XSS/Code Injection risk",
             "Avoid eval(); use JSON.parse() or safe alternatives", Severity.CRITICAL),
            (r'setTimeout\s*\(\s*["\']', "setTimeout with string - code injection risk",
             "Pass a function reference instead", Severity.WARNING),
            (r'setInterval\s*\(\s*["\']', "setInterval with string - code injection risk",
             "Pass a function reference instead", Severity.WARNING),
            (r'new\s+Function\s*\(', "new Function() - code injection risk",
             "Avoid dynamic function creation", Severity.WARNING),
            (r'v-html\s*=', "Vue v-html directive - XSS risk",
             "Use v-text or sanitize HTML", Severity.WARNING),
            (r'\{\{\s*.*\|\s*safe\s*\}\}', "Template |safe filter - XSS risk",
             "Avoid marking untrusted content as safe", Severity.WARNING),
            (r'ng-bind-html\s*=', "Angular ng-bind-html - XSS risk",
             "Use $sce.trustAsHtml() or sanitize", Severity.WARNING),
            (r'dangerouslySetInnerHTML', "React dangerouslySetInnerHTML - XSS risk",
             "Sanitize HTML before rendering", Severity.WARNING),

            # Path Traversal
            (r'(?:open|read|write|unlink|rmdir)\s*\(.*\.\.', "Path traversal detected",
             "Validate and sanitize file paths", Severity.CRITICAL),
            (r'(?:open|read|write|unlink|rmdir)\s*\(.*\+', "Path traversal via concatenation",
             "Use os.path.join() or Path objects", Severity.WARNING),
            (r'(?:open|read|write|unlink|rmdir)\s*\(.*%', "Path traversal via string formatting",
             "Use os.path.join() or Path objects", Severity.WARNING),
            (r'(?:open|read|write|unlink|rmdir)\s*\(.*\$\{', "Path traversal via template literal",
             "Use os.path.join() or Path objects", Severity.WARNING),

            # XML External Entity (XXE)
            (r'XMLParser\s*\(.*resolve_entities\s*=\s*True', "XXE: resolve_entities enabled",
             "Disable entity resolution", Severity.CRITICAL),
            (r'parseString\s*\(', "XML parsing - potential XXE",
             "Use defusedxml library", Severity.WARNING),
            (r'xml\.etree\.ElementTree\.parse\s*\(', "XML parsing - potential XXE",
             "Use defusedxml library", Severity.WARNING),
            (r'xml\.dom\.minidom\.parse\s*\(', "XML parsing - potential XXE",
             "Use defusedxml library", Severity.WARNING),
            (r'xml\.sax\.parse\s*\(', "XML parsing - potential XXE",
             "Use defusedxml library", Severity.WARNING),
            (r'DOMParser\s*\(', "XML parsing - potential XXE",
             "Validate and sanitize XML input", Severity.WARNING),

            # Server-Side Request Forgery (SSRF)
            (r'requests\.(?:get|post|put|delete|patch)\s*\(.*\+', "SSRF via URL concatenation",
             "Validate and whitelist URLs", Severity.CRITICAL),
            (r'urllib\.request\.urlopen\s*\(.*\+', "SSRF via URL concatenation",
             "Validate and whitelist URLs", Severity.CRITICAL),
            (r'fetch\s*\(.*\+', "SSRF via URL concatenation",
             "Validate and whitelist URLs", Severity.WARNING),
            (r'axios\.(?:get|post|put|delete)\s*\(.*\+', "SSRF via URL concatenation",
             "Validate and whitelist URLs", Severity.WARNING),
        ]

        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith('//') or stripped.startswith('#') or stripped.startswith('*'):
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


class SecretsDetectionRules(BaseRule):
    """Hardcoded secrets, API keys, passwords, and tokens detection."""

    @property
    def name(self) -> str:
        return "secrets"

    @property
    def description(self) -> str:
        return "Hardcoded secrets and credentials detection"

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
            # API Keys
            (r'(?:api[_-]?key|apikey)\s*[=:]\s*["\'][A-Za-z0-9_\-]{20,}["\']', "Hardcoded API key",
             "Use environment variables or a secrets manager", Severity.CRITICAL),
            (r'(?:secret[_-]?key|secretkey)\s*[=:]\s*["\'][A-Za-z0-9_\-]{20,}["\']', "Hardcoded secret key",
             "Use environment variables or a secrets manager", Severity.CRITICAL),
            (r'(?i)(?:access[_-]?key|accesskey)\s*[=:]\s*["\'][A-Za-z0-9_\-]{20,}["\']', "Hardcoded access key",
             "Use environment variables or a secrets manager", Severity.CRITICAL),

            # AWS Keys
            (r'AKIA[0-9A-Z]{16}', "AWS Access Key ID",
             "Remove and rotate immediately; use IAM roles", Severity.CRITICAL),
            (r'(?i)aws[_-]?secret[_-]?access[_-]?key\s*[=:]\s*["\'][A-Za-z0-9/+=]{40}["\']', "AWS Secret Access Key",
             "Remove and rotate immediately; use IAM roles", Severity.CRITICAL),

            # GitHub/GitLab/Bitbucket Tokens
            (r'ghp_[A-Za-z0-9]{36}', "GitHub Personal Access Token",
             "Remove and rotate immediately", Severity.CRITICAL),
            (r'gho_[A-Za-z0-9]{36}', "GitHub OAuth Token",
             "Remove and rotate immediately", Severity.CRITICAL),
            (r'github_pat_[A-Za-z0-9_]{82}', "GitHub Fine-grained PAT",
             "Remove and rotate immediately", Severity.CRITICAL),
            (r'glpat-[A-Za-z0-9\-_]{20,}', "GitLab Personal Access Token",
             "Remove and rotate immediately", Severity.CRITICAL),
            (r'(?i)bitbucket[_-]?app[_-]?password\s*[=:]', "Bitbucket App Password",
             "Use environment variables", Severity.CRITICAL),

            # Google API Keys
            (r'AIza[0-9A-Za-z_\-]{35}', "Google API Key",
             "Remove and rotate immediately", Severity.CRITICAL),
            (r'(?i)google[_-]?api[_-]?key\s*[=:]\s*["\'][A-Za-z0-9_\-]{35}["\']', "Google API Key",
             "Remove and rotate immediately", Severity.CRITICAL),

            # Slack Tokens
            (r'xox[baprs]-[A-Za-z0-9\-]{10,}', "Slack Token",
             "Remove and rotate immediately", Severity.CRITICAL),
            (r'xoxb-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{24}', "Slack Bot Token",
             "Remove and rotate immediately", Severity.CRITICAL),
            (r'xoxp-[0-9]{10,}-[0-9]{10,}-[0-9]{10,}-[a-z0-9]{32}', "Slack User Token",
             "Remove and rotate immediately", Severity.CRITICAL),

            # Stripe Keys
            (r'sk_live_[0-9a-zA-Z]{24,}', "Stripe Secret Key",
             "Remove and rotate immediately", Severity.CRITICAL),
            (r'pk_live_[0-9a-zA-Z]{24,}', "Stripe Publishable Key",
             "Use environment variables", Severity.WARNING),
            (r'sk_test_[0-9a-zA-Z]{24,}', "Stripe Test Key",
             "Use environment variables", Severity.WARNING),

            # Twilio
            (r'(?i)twilio[_-]?account[_-]?sid\s*[=:]\s*["\']AC[a-f0-9]{32}["\']', "Twilio Account SID",
             "Use environment variables", Severity.CRITICAL),
            (r'(?i)twilio[_-]?auth[_-]?token\s*[=:]\s*["\'][a-f0-9]{32}["\']', "Twilio Auth Token",
             "Use environment variables", Severity.CRITICAL),

            # Generic patterns
            (r'(?i)(?:password|passwd|pwd)\s*[=:]\s*["\'][^"\']{8,}["\']', "Hardcoded password",
             "Use environment variables or a secrets manager", Severity.CRITICAL),
            (r'(?i)(?:secret|token|auth)\s*[=:]\s*["\'][A-Za-z0-9_\-]{20,}["\']', "Hardcoded secret/token",
             "Use environment variables or a secrets manager", Severity.CRITICAL),
            (r'(?i)(?:private[_-]?key|privatekey)\s*[=:]\s*["\'][A-Za-z0-9/+=\-]{40,}["\']', "Hardcoded private key",
             "Use environment variables or a secrets manager", Severity.CRITICAL),
            (r'(?i)(?:connection[_-]?string|conn[_-]?str)\s*[=:]\s*["\'][^"\']*(?:password|pwd)[^"\']*["\']', "Hardcoded connection string with password",
             "Use environment variables", Severity.CRITICAL),
            (r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----', "Hardcoded private key in code",
             "Remove immediately and use secure key storage", Severity.CRITICAL),

            # JWT
            (r'(?i)(?:jwt|token)\s*[=:]\s*["\'][A-Za-z0-9_\-\.]{50,}["\']', "Hardcoded JWT token",
             "Use environment variables", Severity.CRITICAL),

            # Database credentials
            (r'(?i)(?:db[_-]?password|database[_-]?password)\s*[=:]\s*["\'][^"\']+["\']', "Hardcoded database password",
             "Use environment variables", Severity.CRITICAL),
            (r'(?i)mysql://[^"\']*:[^@"\s]+@', "Database credentials in URL",
             "Use environment variables for credentials", Severity.CRITICAL),
            (r'(?i)postgres(?:ql)?://[^"\']*:[^@"\s]+@', "Database credentials in URL",
             "Use environment variables for credentials", Severity.CRITICAL),
            (r'(?i)mongodb(?:\+srv)?://[^"\']*:[^@"\s]+@', "Database credentials in URL",
             "Use environment variables for credentials", Severity.CRITICAL),
            (r'(?i)redis://[^"\']*:[^@"\s]+@', "Database credentials in URL",
             "Use environment variables for credentials", Severity.CRITICAL),
        ]

        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith('#') or stripped.startswith('//'):
                continue

            for pattern, message, suggestion, severity in patterns:
                if re.search(pattern, line):
                    issues.append(self._create_issue(
                        file_path=file_path,
                        line=line_num,
                        message=message,
                        suggestion=suggestion,
                        severity=severity,
                        code_snippet=stripped[:100],  # Truncate to avoid leaking secrets
                    ))

        return issues


class CryptoRules(BaseRule):
    """Weak cryptography and insecure random number generation."""

    @property
    def name(self) -> str:
        return "crypto"

    @property
    def description(self) -> str:
        return "Weak cryptography detection"

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
            # Weak hashing
            (r'\bmd5\s*\(', "Weak hash algorithm: MD5",
             "Use SHA-256 or stronger", Severity.WARNING),
            (r'\bsha1\s*\(', "Weak hash algorithm: SHA-1",
             "Use SHA-256 or stronger", Severity.WARNING),
            (r'hashlib\.md5\s*\(', "Weak hash algorithm: MD5",
             "Use hashlib.sha256() or stronger", Severity.WARNING),
            (r'hashlib\.sha1\s*\(', "Weak hash algorithm: SHA-1",
             "Use hashlib.sha256() or stronger", Severity.WARNING),
            (r'Crypto\.Hash\.MD5', "Weak hash algorithm: MD5",
             "Use SHA-256 or stronger", Severity.WARNING),
            (r'Crypto\.Hash\.SHA1', "Weak hash algorithm: SHA-1",
             "Use SHA-256 or stronger", Severity.WARNING),
            (r'md5\.create\s*\(', "Weak hash algorithm: MD5",
             "Use SHA-256 or stronger", Severity.WARNING),
            (r'sha1\.create\s*\(', "Weak hash algorithm: SHA-1",
             "Use SHA-256 or stronger", Severity.WARNING),

            # Insecure random
            (r'random\.(?:random|randint|choice|randrange)\s*\(', "Insecure random number generator",
             "Use secrets module for security-sensitive random values", Severity.WARNING),
            (r'Math\.random\s*\(', "Insecure random number generator (JavaScript)",
             "Use crypto.getRandomValues() for security-sensitive values", Severity.WARNING),
            (r'rand\s*\(', "Insecure random number generator (C)",
             "Use cryptographically secure random for security", Severity.INFO),
            (r'srand\s*\(', "Insecure random seed (C)",
             "Use /dev/urandom or arc4random", Severity.INFO),
            (r'java\.util\.Random', "Insecure random number generator (Java)",
             "Use java.security.SecureRandom", Severity.WARNING),

            # Weak encryption
            (r'\bDES\b', "Weak encryption algorithm: DES",
             "Use AES-256 or stronger", Severity.WARNING),
            (r'\bRC4\b', "Weak encryption algorithm: RC4",
             "Use AES-GCM or ChaCha20", Severity.WARNING),
            (r'\bBlowfish\b', "Weak encryption algorithm: Blowfish",
             "Use AES-256 or stronger", Severity.WARNING),
            (r'\b3DES\b', "Weak encryption algorithm: 3DES",
             "Use AES-256 or stronger", Severity.WARNING),
            (r'\bDESede\b', "Weak encryption algorithm: 3DES",
             "Use AES-256 or stronger", Severity.WARNING),

            # ECB mode
            (r'AES\.new\s*\(.*AES\.MODE_ECB', "AES in ECB mode - insecure",
             "Use CBC, GCM, or CTR mode", Severity.WARNING),
            (r'ALGO_MODE_ECB', "ECB mode detected",
             "Use CBC, GCM, or CTR mode", Severity.WARNING),

            # Hardcoded IV
            (r'(?:iv|nonce|initialization[_-]?vector)\s*[=:]\s*["\'][^"\']+["\']', "Hardcoded IV/nonce",
             "Generate IV/nonce randomly for each encryption", Severity.WARNING),

            # Insecure SSL/TLS
            (r'SSLv[23]', "Insecure SSL version",
             "Use TLS 1.2 or higher", Severity.CRITICAL),
            (r'PROTOCOL_SSLv2', "SSLv2 protocol - insecure",
             "Use TLS 1.2 or higher", Severity.CRITICAL),
            (r'PROTOCOL_SSLv3', "SSLv3 protocol - insecure",
             "Use TLS 1.2 or higher", Severity.CRITICAL),
            (r'verify\s*=\s*False', "SSL verification disabled",
             "Enable SSL verification in production", Severity.WARNING),
            (r'CERT_NONE', "SSL certificate verification disabled",
             "Enable certificate verification", Severity.WARNING),
            (r'check_hostname\s*=\s*False', "Hostname verification disabled",
             "Enable hostname verification", Severity.WARNING),
        ]

        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith('#') or stripped.startswith('//'):
                continue

            for pattern, message, suggestion, severity in patterns:
                if re.search(pattern, line):
                    issues.append(self._create_issue(
                        file_path=file_path,
                        line=line_num,
                        message=message,
                        suggestion=suggestion,
                        severity=severity,
                        code_snippet=stripped,
                    ))

        return issues


class AuthenticationRules(BaseRule):
    """Authentication and authorization vulnerabilities."""

    @property
    def name(self) -> str:
        return "authentication"

    @property
    def description(self) -> str:
        return "Authentication and authorization vulnerability detection"

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
            # Hardcoded credentials
            (r'(?i)(?:user|username)\s*[=:]\s*["\'][^"\']+["\'].*(?:password|pwd)\s*[=:]\s*["\'][^"\']+["\']', "Hardcoded credentials",
             "Use environment variables or a secrets manager", Severity.CRITICAL),

            # Weak password hashing
            (r'(?:hash|digest)\s*\(\s*["\'][^"\']+["\']\s*\)', "Password hashing with weak algorithm",
             "Use bcrypt, scrypt, or argon2", Severity.CRITICAL),
            (r'(?i)md5\s*\(.*(?:password|pwd)', "MD5 for password hashing",
             "Use bcrypt, scrypt, or argon2", Severity.CRITICAL),
            (r'(?i)sha1\s*\(.*(?:password|pwd)', "SHA-1 for password hashing",
             "Use bcrypt, scrypt, or argon2", Severity.CRITICAL),
            (r'(?i)sha256\s*\(.*(?:password|pwd)', "SHA-256 for password hashing (no salt)",
             "Use bcrypt, scrypt, or argon2 with proper salting", Severity.WARNING),

            # Missing authentication
            (r'@app\.route\s*\([^)]*\)\s*\ndef\s+\w+', "Route without authentication check",
             "Add authentication middleware or @login_required", Severity.WARNING),
            (r'(?:get|post|put|delete|patch)\s*\(\s*["\']/[^"\']*["\']', "API endpoint without auth check",
             "Add authentication middleware", Severity.WARNING),

            # Session management
            (r'session\[.*\]\s*=\s*["\'](?:admin|root|superuser)["\']', "Hardcoded admin session",
             "Use dynamic role assignment", Severity.CRITICAL),
            (r'(?i)(?:session[_-]?timeout|session[_-]? expiry)\s*[=:]\s*(?:0|None|null)', "Session timeout disabled",
             "Set appropriate session timeout", Severity.WARNING),
            (r'httponly\s*=\s*False', "HttpOnly flag disabled",
             "Enable HttpOnly for session cookies", Severity.WARNING),
            (r'secure\s*=\s*False', "Secure flag disabled",
             "Enable Secure flag for HTTPS cookies", Severity.WARNING),
            (r'samesite\s*=\s*["\']None["\']', "SameSite=None for cookies",
             "Use Lax or Strict for better CSRF protection", Severity.WARNING),

            # JWT issues
            (r'(?i)verify\s*:\s*false', "JWT signature verification disabled",
             "Enable JWT signature verification", Severity.CRITICAL),
            (r'(?i)algorithm\s*[=:]\s*["\']none["\']', "JWT algorithm 'none' allowed",
             "Require strong JWT algorithms (RS256, ES256)", Severity.CRITICAL),
            (r'jwt\.decode\s*\(.*verify\s*=\s*False', "JWT verification disabled",
             "Enable JWT verification", Severity.CRITICAL),

            # Authorization bypass
            (r'(?i)is[_-]?admin\s*=\s*True', "Hardcoded admin flag",
             "Use role-based access control", Severity.WARNING),
            (r'(?i)role\s*[=:]\s*["\']admin["\']', "Hardcoded admin role",
             "Use dynamic role assignment", Severity.WARNING),
            (r'(?i)admin\s*=\s*True', "Hardcoded admin flag",
             "Use role-based access control", Severity.WARNING),
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
