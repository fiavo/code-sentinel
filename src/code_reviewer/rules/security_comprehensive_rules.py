"""
Comprehensive security rules for all languages.
"""
import re
from ..core.models import CodeIssue, Severity, IssueCategory
from ..core.rules import BaseRule


class SecurityComprehensiveRules(BaseRule):
    @property
    def name(self) -> str:
        return "security_comprehensive"
    @property
    def description(self) -> str:
        return "Comprehensive security rules"
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
            # SQL injection
            (r"(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE).*\+", "SQL injection risk", "Use parameterized queries", Severity.CRITICAL),
            (r"(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE).*\%", "SQL injection risk", "Use parameterized queries", Severity.CRITICAL),
            (r"(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE).*\$\{", "SQL injection risk", "Use parameterized queries", Severity.CRITICAL),
            (r"(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE).*format\(", "SQL injection risk", "Use parameterized queries", Severity.CRITICAL),
            (r"(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE).*\.format\(", "SQL injection risk", "Use parameterized queries", Severity.CRITICAL),
            (r"(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE).*f\"", "SQL injection risk", "Use parameterized queries", Severity.CRITICAL),
            (r"(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE).*f'", "SQL injection risk", "Use parameterized queries", Severity.CRITICAL),
            # Command injection
            (r"exec\(|eval\(|system\(|passthru\(|shell_exec\(|popen\(|proc_open\(|pcntl_exec\(", "Command injection risk", "Use safe command execution", Severity.CRITICAL),
            (r"subprocess\.(?:call|run|Popen|check_output|check_call)\(", "Command execution", "Validate inputs to subprocess", Severity.WARNING),
            (r"os\.system\(", "os.system() call", "Use subprocess instead", Severity.WARNING),
            (r"os\.popen\(", "os.popen() call", "Use subprocess instead", Severity.WARNING),
            (r"child_process\.(?:exec|execSync|execFile|execFileSync|spawn|spawnSync)\(", "Node.js command execution", "Validate inputs", Severity.WARNING),
            (r"Runtime\.exec\(", "Java Runtime.exec()", "Validate inputs", Severity.WARNING),
            (r"Process\.start\(", "C# Process.start()", "Validate inputs", Severity.WARNING),
            (r"Command\.new\(", "Ruby Command.new()", "Validate inputs", Severity.WARNING),
            (r"system\(\[", "Ruby system call", "Validate inputs", Severity.WARNING),
            (r"IO\.popen\(", "Ruby IO.popen()", "Validate inputs", Severity.WARNING),
            (r"`.*`", "Backtick execution", "Validate inputs", Severity.WARNING),
            # XSS
            (r"innerHTML|outerHTML|document\.write|v-html|dangerouslySetInnerHTML|__html", "XSS risk", "Sanitize output", Severity.CRITICAL),
            (r"(?:\bdocument\.write\s*\(|\bdocument\.writeln\s*\()", "document.write()", "Avoid document.write", Severity.WARNING),
            (r"(?:\beval\s*\()", "eval() call", "Avoid eval()", Severity.CRITICAL),
            (r"(?:\bsetTimeout\s*\(\s*[\"'])", "setTimeout with string", "Use function instead of string", Severity.WARNING),
            (r"(?:\bsetInterval\s*\(\s*[\"'])", "setInterval with string", "Use function instead of string", Severity.WARNING),
            (r"(?:\bnew\s+Function\s*\()", "new Function()", "Avoid new Function()", Severity.WARNING),
            (r"(?:\blocation\s*=|\blocation\.href\s*=|\blocation\.replace\s*\(|\blocation\.assign\s*\()", "URL redirect", "Validate redirect target", Severity.WARNING),
            (r"(?:\bwindow\.open\s*\()", "window.open()", "Validate URL", Severity.WARNING),
            # CSRF
            (r"(?:\bcsrf\b|\bxsrf\b|\bcrsf\b|\bxsfr\b|\btoken\b)", "CSRF token", "Good: using CSRF protection", Severity.INFO),
            (r"(?:\bSameSite\b|\bHttpOnly\b|\bSecure\b)", "Cookie flags", "Good: using secure cookie flags", Severity.INFO),
            # Path traversal
            (r"(?:\.\.\/|\.\.\\|\.\.%2[fF]|\.\.%5[cC])", "Path traversal attempt", "Validate file paths", Severity.CRITICAL),
            (r"(?:open\s*\(|File\.open\(|fs\.readFile|fs\.readFileSync|readFile|readFileSync)", "File read", "Validate file paths", Severity.WARNING),
            (r"(?:writeFile|writeFileSync|fs\.writeFile|fs\.writeFileSync)", "File write", "Validate file paths", Severity.WARNING),
            # Hardcoded secrets
            (r"(?:password|Password|PASSWORD)\s*=\s*[\"'][^\"']+[\"']", "Hardcoded password", "Use environment variables", Severity.CRITICAL),
            (r"(?:api.?key|API.?KEY|apikey|ApiKey)\s*=\s*[\"'][^\"']+[\"']", "Hardcoded API key", "Use environment variables", Severity.CRITICAL),
            (r"(?:secret|SECRET|Secret)\s*=\s*[\"'][^\"']+[\"']", "Hardcoded secret", "Use environment variables", Severity.CRITICAL),
            (r"(?:token|TOKEN|Token)\s*=\s*[\"'][^\"']+[\"']", "Hardcoded token", "Use environment variables", Severity.CRITICAL),
            (r"(?:private.?key|PRIVATE.?KEY|PrivateKey)\s*=\s*[\"'][^\"']+[\"']", "Hardcoded private key", "Use environment variables", Severity.CRITICAL),
            (r"(?:aws.?secret|AWS.?SECRET|awsAccessKey|AWS_ACCESS_KEY)\s*=\s*[\"'][^\"']+[\"']", "Hardcoded AWS secret", "Use environment variables", Severity.CRITICAL),
            (r"(?:connection.?string|CONNECTION.?STRING|database.?url|DATABASE_URL)\s*=\s*[\"'][^\"']+[\"']", "Hardcoded connection string", "Use environment variables", Severity.CRITICAL),
            # Weak cryptography
            (r"(?:MD5|md5)\s*\(", "MD5 usage", "Use SHA-256 or better", Severity.WARNING),
            (r"(?:SHA-1|sha1)\s*\(", "SHA-1 usage", "Use SHA-256 or better", Severity.WARNING),
            (r"(?:DES|des)\s*\(", "DES usage", "Use AES-256", Severity.WARNING),
            (r"(?:RC4|rc4)\s*\(", "RC4 usage", "Use AES-256", Severity.WARNING),
            (r"(?:Blowfish|blowfish)\s*\(", "Blowfish usage", "Use AES-256", Severity.WARNING),
            (r"(?:random\.random|Math\.random|rand\(\))", "Insecure random", "Use cryptographically secure random", Severity.WARNING),
            (r"(?:rand\(\)|rand\s*%|srand\()", "C random", "Use secure random", Severity.WARNING),
            # Insecure deserialization
            (r"(?:pickle\.loads|yaml\.load|yaml\.unmarshal|unserialize|JSON\.parse|json\.loads)", "Deserialization", "Validate deserialized data", Severity.WARNING),
            (r"(?:marshal\.loads|pickle\.load)", "Pickle/marshal load", "Avoid pickle; use JSON", Severity.CRITICAL),
            # SSRF
            (r"(?:requests\.get|requests\.post|requests\.put|requests\.delete|requests\.patch|urllib\.request|http\.client|aiohttp|httpx|fetch\()", "HTTP request", "Validate URLs; prevent SSRF", Severity.WARNING),
            (r"(?:curl|wget|http_request|httpGet|httpClient)", "HTTP request function", "Validate URLs; prevent SSRF", Severity.WARNING),
            # Insecure TLS
            (r"(?:verify\s*=\s*False|SSL_VERIFY.*false|NODE_TLS_REJECT_UNAUTHORIZED.*0|InsecureSkipVerify.*true|--insecure|verify_ssl.*False)", "Disabled TLS verification", "Enable TLS verification", Severity.CRITICAL),
            (r"(?:TLSv1\.0|TLSv1\.1|SSLv3|SSLv2)", "Weak TLS version", "Use TLSv1.2 or higher", Severity.CRITICAL),
            # Open redirect
            (r"(?:redirect|Redirect|REDIRECT|location\.href|location\.replace|location\.assign)", "Redirect", "Validate redirect targets", Severity.WARNING),
            # LDAP injection
            (r"(?:ldap_search|ldap_add|ldap_modify|ldap_delete|ldap_bind)", "LDAP operation", "Validate LDAP inputs", Severity.WARNING),
            # XML injection (XXE)
            (r"(?:XMLParser|xml\.etree|lxml\.etree|xml\.sax|xml\.dom|DocumentBuilder|SAXParser)", "XML parsing", "Disable external entities", Severity.WARNING),
            (r"(?:DOCTYPE|ENTITY|SYSTEM|PUBLIC|CDATA)", "XML entity", "Disable external entities", Severity.WARNING),
            # Insecure file permissions
            (r"(?:chmod\s+777|0o777|777)", "Insecure file permissions", "Use restrictive permissions", Severity.WARNING),
            (r"(?:world.?readable|world.?writable|group.?readable|group.?writable)", "Insecure permissions", "Use restrictive permissions", Severity.WARNING),
            # Insecure HTTP
            (r"(?:http://|HTTP://)", "Insecure HTTP", "Use HTTPS", Severity.WARNING),
            (r"(?:plaintext|PLAINTEXT|clear.?text|CLEAR.?TEXT)", "Plaintext data", "Encrypt sensitive data", Severity.WARNING),
            # Insecure dependencies
            (r"(?:eval|exec|Function|setTimeout|setInterval).*\buser\b", "User input in code execution", "Sanitize user input", Severity.CRITICAL),
            # Debug information
            (r"(?:stack.?trace|printStackTrace|debug|DEBUG|verbose|VERBOSE|trace|TRACE)", "Debug info", "Remove debug info in production", Severity.INFO),
            (r"(?:console\.log|console\.debug|console\.info|console\.warn|console\.error)", "Console output", "Remove console output in production", Severity.INFO),
            (r"(?:var_dump|print_r|echo|print\(|System\.out\.println|fmt\.Print|puts|pp|p)", "Debug output", "Remove debug output in production", Severity.INFO),
            # Insecure session
            (r"(?:session_id|SESSION_ID|session\.id|sessionId)", "Session ID", "Use secure session management", Severity.INFO),
            (r"(?:cookie|Cookie|COOKIE)", "Cookie", "Use secure cookie settings", Severity.INFO),
            # Insecure CORS
            (r"(?:Access-Control-Allow-Origin.*\*)", "CORS wildcard", "Restrict CORS origins", Severity.WARNING),
            (r"(?:cors.*origin.*\*|allowOrigin.*\*)", "CORS wildcard", "Restrict CORS origins", Severity.WARNING),
            # Insecure headers
            (r"(?:X-Frame-Options|X-XSS-Protection|X-Content-Type-Options|Content-Security-Policy|Strict-Transport-Security|X-DNS-Prefetch-Control|Referrer-Policy|Permissions-Policy)", "Security header", "Good: using security headers", Severity.INFO),
            # Insecure password storage
            (r"(?:MD5|md5).*password|password.*(?:MD5|md5)", "MD5 for passwords", "Use bcrypt/scrypt/argon2", Severity.CRITICAL),
            (r"(?:SHA-1|sha1).*password|password.*(?:SHA-1|sha1)", "SHA-1 for passwords", "Use bcrypt/scrypt/argon2", Severity.CRITICAL),
            # Insecure session fixation
            (r"(?:session_regenerate_id|session\.regenerate)", "Session regeneration", "Good: regenerating session ID", Severity.INFO),
            # Insecure token generation
            (r"(?:Math\.random|random\.random|rand\(\)|time\(\)|Date\.now\(\))", "Weak token generation", "Use crypto.randomBytes()", Severity.WARNING),
            # Insecure password comparison
            (r"(?:===\s*[\"']|==\s*[\"']|\.equals\(|string_compare|strcmp)", "Password comparison", "Use constant-time comparison", Severity.WARNING),
            # Insecure file upload
            (r"(?:upload|Upload|UPLOAD|multipart|Multipart)", "File upload", "Validate file types and sizes", Severity.INFO),
            # Insecure file download
            (r"(?:download|Download|DOWNLOAD|sendFile|send_file)", "File download", "Validate file paths", Severity.INFO),
            # Insecure directory listing
            (r"(?:directory.?listing|DirectoryListing|listDir|listFiles|readdir|scandir)", "Directory listing", "Disable directory listing", Severity.WARNING),
            # Insecure error messages
            (r"(?:stack.?trace|Stack Trace|Traceback|at\s+\w+\s+\()", "Stack trace in response", "Hide stack traces in production", Severity.WARNING),
            # Insecure logging
            (r"(?:log.*password|log.*secret|log.*token|log.*key|log.*credential)", "Sensitive data in logs", "Never log sensitive data", Severity.CRITICAL),
            # Insecure configuration
            (r"(?:DEBUG\s*=\s*True|debug\s*=\s*true|NODE_ENV.*development)", "Debug mode", "Disable debug in production", Severity.WARNING),
            (r"(?:SECRET_KEY|JWT_SECRET|SESSION_SECRET)\s*=\s*[\"'][^\"']+[\"']", "Hardcoded secret", "Use environment variables", Severity.CRITICAL),
            # Insecure authentication
            (r"(?:password.*==|==.*password|password\.equals)", "Password comparison", "Use secure comparison", Severity.WARNING),
            (r"(?:bcrypt|scrypt|argon2|pbkdf2)", "Password hashing", "Good: using secure hashing", Severity.INFO),
            # Insecure authorization
            (r"(?:isAdmin|is_admin|role.*admin|admin.*role)", "Admin check", "Use proper authorization", Severity.INFO),
            # Insecure session management
            (r"(?:session\.destroy|session\.invalidate|session\.clear)", "Session cleanup", "Good: cleaning sessions", Severity.INFO),
            # Insecure token management
            (r"(?:exp|iat|nbf|iss|aud|sub|jti)", "JWT claims", "Good: using JWT claims", Severity.INFO),
            (r"(?:refreshToken|refresh_token|REFRESH_TOKEN)", "Refresh token", "Handle refresh tokens securely", Severity.INFO),
            # Insecure CORS
            (r"(?:allowOrigin|Access-Control-Allow-Origin|cors.*origin)", "CORS configuration", "Good: CORS configured", Severity.INFO),
            # Insecure CSP
            (r"(?:Content-Security-Policy|CSP|contentSecurityPolicy)", "CSP header", "Good: using CSP", Severity.INFO),
            # Insecure HSTS
            (r"(?:Strict-Transport-Security|HSTS|strictTransportSecurity)", "HSTS header", "Good: using HSTS", Severity.INFO),
            # Insecure X-Frame-Options
            (r"(?:X-Frame-Options|XFO|xFrameOptions)", "X-Frame-Options", "Good: using X-Frame-Options", Severity.INFO),
            # Insecure X-Content-Type-Options
            (r"(?:X-Content-Type-Options|XCTO|xContentTypeOptions)", "X-Content-Type-Options", "Good: using X-Content-Type-Options", Severity.INFO),
            # Insecure X-XSS-Protection
            (r"(?:X-XSS-Protection|XXSS|xXSSProtection)", "X-XSS-Protection", "Good: using X-XSS-Protection", Severity.INFO),
            # Insecure Referrer-Policy
            (r"(?:Referrer-Policy|referrerPolicy)", "Referrer-Policy", "Good: using Referrer-Policy", Severity.INFO),
            # Insecure Permissions-Policy
            (r"(?:Permissions-Policy|permissionsPolicy)", "Permissions-Policy", "Good: using Permissions-Policy", Severity.INFO),
            # Insecure Feature-Policy
            (r"(?:Feature-Policy|featurePolicy)", "Feature-Policy", "Good: using Feature-Policy", Severity.INFO),
            # Insecure X-Powered-By
            (r"(?:X-Powered-By|xPoweredBy)", "X-Powered-By", "Remove X-Powered-By header", Severity.INFO),
            # Insecure Server header
            (r"(?:Server.*:|X-AspNet-Version|X-AspNetMvc-Version|X-Generator)", "Server header", "Remove server version headers", Severity.INFO),
            # Insecure cookies
            (r"(?:HttpOnly|httpOnly|secure|Secure|SameSite|sameSite)", "Cookie attributes", "Good: using secure cookie attributes", Severity.INFO),
            # Insecure JWT
            (r"(?:alg.*none|ALG.*NONE|algorithm.*none)", "Insecure JWT algorithm", "Never use 'none' algorithm", Severity.CRITICAL),
            (r"(?:HS256|HS384|HS512|RS256|RS384|RS512|ES256|ES384|ES512|PS256|PS384|PS512)", "JWT algorithm", "Good: using JWT algorithm", Severity.INFO),
            # Insecure OAuth
            (r"(?:implicit.*grant|IMPLICIT.*GRANT|response_type.*token)", "Implicit grant", "Use authorization code flow", Severity.WARNING),
            # Insecure SAML
            (r"(?:assertionConsumerServiceURL|destination|Recipient)", "SAML assertion", "Validate SAML assertions", Severity.INFO),
            # Insecure XML
            (r"(?:entityExpansionLimit|externalGeneralEntities|externalParameterEntities|disallowDoctypeDecl|setFeature.*external)", "XML security", "Good: XML security settings", Severity.INFO),
            # Insecure YAML
            (r"(?:yaml\.safe_load|yaml\.safe_dump|yaml\.load.*Loader)", "YAML safety", "Good: using safe YAML", Severity.INFO),
            # Insecure JSON
            (r"(?:JSON\.parse|json\.loads|json_decode)", "JSON parsing", "Validate JSON input", Severity.INFO),
            # Insecure file operations
            (r"(?:symlink|symlink_read|readlink|realpath)", "Symlink operation", "Validate symlink targets", Severity.WARNING),
            (r"(?:chmod|chown|chgrp|utime)", "File permission change", "Use secure permissions", Severity.INFO),
            # Insecure network
            (r"(?:telnet|ftp|http://|HTTP://)", "Insecure protocol", "Use secure protocols", Severity.WARNING),
            (r"(?:0\.0\.0\.0|:::|\*:)", "Bind all interfaces", "Bind to specific interface", Severity.INFO),
            # Insecure crypto
            (r"(?:ECB|ecb|CBC|cbc|CTR|ctr|OFB|ofb|CFB|cfb)", "Block cipher mode", "Use authenticated encryption", Severity.INFO),
            (r"(?:RSA|rsa|DSA|dsa|ECDSA|ecdsa|EdDSA|eddsa|Ed25519|ed25519|X25519|x25519)", "Key exchange/signature", "Good: using modern crypto", Severity.INFO),
            (r"(?:AES|aes|ChaCha20|chacha20|Poly1305|poly1305|GCM|gcm|CCM|ccm|SIV|siv)", "Encryption algorithm", "Good: using authenticated encryption", Severity.INFO),
            (r"(?:PBKDF2|pbkdf2|bcrypt|scrypt|argon2|Argon2|scrypt|Scrypt)", "Key derivation", "Good: using key derivation", Severity.INFO),
            (r"(?:HKDF|hkdf|HMAC|hmac|CMAC|cmac|Poly1305|poly1305)", "MAC algorithm", "Good: using MAC", Severity.INFO),
            (r"(?:XChaCha20|xchacha20|XChaCha20Poly1305|xchacha20poly1305)", "Modern cipher", "Good: using modern ciphers", Severity.INFO),
            (r"(?:AES-256-GCM|aes-256-gcm|AES-128-GCM|aes-128-gcm|ChaCha20-Poly1305|chacha20-poly1305)", "Authenticated encryption", "Good: using authenticated encryption", Severity.INFO),
            (r"(?:TLSv1\.2|TLSv1\.3|tls1_2|tls1_3)", "Secure TLS version", "Good: using secure TLS", Severity.INFO),
            (r"(?:ECDHE|ecdhe|DHE|dhe|X25519|x25519|P-256|P-384|P-521)", "Key exchange", "Good: using forward secrecy", Severity.INFO),
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
