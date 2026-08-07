"""
Cryptography and security patterns.
"""
import re
from ..core.models import CodeIssue, Severity, IssueCategory
from ..core.rules import BaseRule


class CryptographyRules(BaseRule):
    @property
    def name(self) -> str:
        return "cryptography"
    @property
    def description(self) -> str:
        return "Cryptography and security patterns"
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
            # Hashing
            (r"md5|MD5", "MD5 hash", "Use SHA-256 or better", Severity.WARNING),
            (r"sha1|SHA1", "SHA-1 hash", "Use SHA-256 or better", Severity.WARNING),
            (r"sha256|SHA256|sha512|SHA512|sha224|SHA224|sha384|SHA384", "SHA-2 family", "Good: SHA-2 hashing", Severity.INFO),
            (r"sha3|SHA3|blake2|Blake2|blake3|Blake3|argon2|Argon2|bcrypt|scrypt|PBKDF2|pbkdf2", "Modern hashing", "Good: modern hashing", Severity.INFO),
            (r"hashlib|hashlib\.md5|hashlib\.sha1|hashlib\.sha256|hashlib\.sha512|hashlib\.sha3_256|hashlib\.blake2b|hashlib\.blake2s|hashlib\.sha3_256", "Python hashing", "Good: Python hashing", Severity.INFO),
            (r"crypto\.createHash|crypto\.createHmac|createHash\(|createHmac\(|hash\.pbkdf2|hash\.scrypt|hash\.argon2|hash\.bcrypt", "Node.js crypto", "Good: Node.js crypto", Severity.INFO),
            (r"sha2::Sha256|sha2::Sha512|sha2::Sha224|sha2::Sha384|sha3::Sha3_256|sha3::Sha3_512|blake2::Blake2b|blake2::Blake2s|argon2|bcrypt|scrypt|digest::Digest", "Rust crypto", "Good: Rust crypto", Severity.INFO),
            (r"crypto/sha256|crypto/sha512|crypto/md5|crypto/sha1|crypto/hmac|crypto/rand|crypto/cipher|crypto/elliptic|crypto/x509|crypto/pkcs1|crypto/pkcs8|crypto/ecdsa|crypto/ed25519|crypto/rsa|crypto/aes|crypto/des|crypto/rc4|crypto/chacha20|crypto/poly1305|crypto/blake2|crypto/argon2|crypto/bcrypt|crypto/scrypt", "Go crypto", "Good: Go crypto", Severity.INFO),
            (r"MessageDigest|Cipher|SecretKey|KeyPair|KeyPairGenerator|KeyStore|KeyManager|TrustManager|SSLContext|SSLSocket|SSLEngine|SecureRandom|AlgorithmParameters|AlgorithmParameterGenerator|Certificate|X509Certificate|PrivateKey|PublicKey|KeyFactory|KeyAgreement|Mac|Signature|GCMParameterSpec|IvParameterSpec|PBEKeySpec", "Java crypto", "Good: Java crypto", Severity.INFO),
            (r"openssl_|sodium_|random_bytes|random_int|random_bytes_random_int|crypto_encrypt|crypto_decrypt|crypto_sign|crypto_verify|crypto_pwhash|crypto_secretbox|crypto_box|crypto_scalarmult", "PHP crypto", "Good: PHP crypto", Severity.INFO),
            # Encryption
            (r"AES|aes|DES|des|3DES|TripleDES|Blowfish|blowfish|ChaCha20|chacha20|XOR|xor", "Encryption algorithm", "Good: encryption", Severity.INFO),
            (r"GCM|CBC|ECB|CTR|CFB|OFB|CTR|GCM", "Block cipher mode", "Good: cipher mode", Severity.INFO),
            (r"RSA|rsa|ECDSA|ecdsa|Ed25519|ed25519|Ed448|ed448|ECDH|ecdh|X25519|x25519|X448|x448|DH|Diffie.?Hellman|DSA|dsa|ECDSA", "Asymmetric crypto", "Good: asymmetric crypto", Severity.INFO),
            (r"encrypt|decrypt|Encrypt|Decrypt|cipher|Cipher", "Encryption operation", "Good: encryption operation", Severity.INFO),
            (r"sign|verify|Sign|Verify|signature|Signature", "Digital signature", "Good: digital signature", Severity.INFO),
            # Key management
            (r"key.?generation|key.?rotation|key.?management|key.?storage|key.?exchange|key.?derivation|KDF|HKDF|PBKDF2|bcrypt|scrypt|argon2", "Key management", "Good: key management", Severity.INFO),
            (r"private.?key|public.?key|secret.?key|session.?key|encryption.?key|signing.?key|master.?key|key.?encryption.?key|KEK|DEK|CEK|DEK|TEK|KEK|PEK|AEK", "Key types", "Good: key types", Severity.INFO),
            (r"KeyStore|Keychain|keychain|keyring|Keyring|secrets.?manager|SecretsManager|KeyVault|KeyVault|KMS|kms|HSM|hsm|TPM|tpm|enclave|Enclave", "Key storage", "Good: key storage", Severity.INFO),
            # TLS/SSL
            (r"TLS|tls|SSL|ssl|HTTPS|https|WSS|wss|FTPS|ftps|SFTP|sftp", "TLS/SSL", "Good: TLS/SSL", Severity.INFO),
            (r"TLSv1\.[1-3]|TLSv1\.1|TLSv1\.2|TLSv1\.3|SSLv3|SSLv2", "TLS version", "Good: TLS versions", Severity.INFO),
            (r"certificate|Certificate|cert|Cert|CA|Certificate.?Authority|chain|Chain|trust.?store|TrustStore|keystore|KeyStore|root.?certificate|intermediate.?certificate|leaf.?certificate|end.?entity.?certificate", "Certificate", "Good: certificates", Severity.INFO),
            (r"Let.?s.?Encrypt|ACME|acme|certbot|Certbot|sslstrip|SSLStrip|heartbleed|Heartbleed|POODLE|POODLE|BEAST|BEAST|CRIME|CRIME|BREACH|BREACH|Lucky13|Lucky13|FREAK|FREAK|Logjam|Logjam|DROWN|DROWN", "TLS knowledge", "Good: TLS knowledge", Severity.INFO),
            # Authentication
            (r"OAuth|OAuth2|OIDC|OpenID|SAML|SAML2|JWT|JWT|bearer|Bearer|token|Token|session|Session|cookie|Cookie|API.?key|APIKey|api_key|access.?token|refresh.?token|id.?token|authorization.?code|grant.?type|client.?credentials|authorization.?code|implicit|PKCE|pkce", "Authentication", "Good: authentication", Severity.INFO),
            (r"HMAC|hmac|CMAC|cmac|GMAC|gmac|poly1305|Poly1305|SipHash|siphash|UMAC|umac|KMAC|kmac|KMAC128|KMAC256|KMAC512", "MAC", "Good: MAC", Severity.INFO),
            # Password hashing
            (r"bcrypt|BCrypt|argon2|Argon2|scrypt|Scrypt|PBKDF2|pbkdf2|password_hash|password_verify|password_needs_rehash", "Password hashing", "Good: password hashing", Severity.INFO),
            (r"salt|Salt|SALT|pepper|Pepper|iterations|cost|work.?factor|memory.?cost|time.?cost|parallelism", "Password hashing params", "Good: password hashing params", Severity.INFO),
            # Random number generation
            (r"Random|random|os\.urandom|secrets\.token|secrets\.randbelow|secrets\.choice|secrets\.token_hex|secrets\.token_urlsafe|secrets\.token_bytes|SystemRandom|SecureRandom|CryptoRandom|crypto\.randomBytes|crypto\.randomFillSync|crypto\.randomUUID", "Secure random", "Good: secure random", Severity.INFO),
            (r"rand\(\)|Math\.random\(\)|random\.random\(\)|random\.randint\(\)|random\.choice\(\)|rand\(|random_int_range\(\)|randint\(\)", "Weak random", "Use cryptographically secure random", Severity.WARNING),
            # Security constants
            (r"OWASP|CWE-\d+|CVE-\d+|PCI.?DSS|HIPAA|GDPR|SOC.?2|ISO.?27001|NIST|FIPS|Common.?Criteria|STRIDE|DREAD|CVSS|BSIMM|SAMM", "Security standard", "Good: security standards", Severity.INFO),
            (r"threat.?model|ThreatModel|threat_model|risk.?assessment|RiskAssessment|security.?audit|SecurityAudit|penetration.?test|PenetrationTest|vulnerability.?scan|VulnerabilityScan|code.?review|CodeReview|security.?review|SecurityReview", "Security process", "Good: security processes", Severity.INFO),
            # Input validation
            (r"sanitiz|Sanitiz|escap|Escap|validat|Validat|filtr|Filtr|whitelist|Whitelist|allowlist|Allowlist|blacklist|Blacklist|blocklist|Blocklist|dangerous|Dangerous|injection|Injection|XSS|xss|CSRF|csrf|SSRF|ssrf|SQL.?injection|NoSQL.?injection|command.?injection|LDAP.?injection|XML.?injection|header.?injection|log.?injection|CRLF|crlf|path.?traversal|directory.?traversal|file.?inclusion|LFI|RFI", "Input validation", "Good: input validation", Severity.INFO),
            # Security headers
            (r"Content-Security-Policy|X-Frame-Options|X-Content-Type-Options|X-XSS-Protection|Strict-Transport-Security|Referrer-Policy|Permissions-Policy|Cross-Origin-Opener-Policy|Cross-Origin-Embedder-Policy|Cross-Origin-Resource-Policy|X-Permitted-Cross-Domain-Policies|Expect-CT|NEL|Report-To", "Security header", "Good: security headers", Severity.INFO),
            # Rate limiting
            (r"rate.?limit|rateLimit|rate_limit|throttle|Throttle|THROTTLE|brute.?force|BruteForce|brute_force|account.?lockout|AccountLockout|account_lockout", "Rate limiting", "Good: rate limiting", Severity.INFO),
            # CORS
            (r"CORS|cors|Cross-Origin|cross-origin|Access-Control-Allow-Origin|Access-Control-Allow-Methods|Access-Control-Allow-Headers|Access-Control-Allow-Credentials|Access-Control-Max-Age|Access-Control-Expose-Headers|Access-Control-Request-Headers|Access-Control-Request-Method|Origin|Referer", "CORS", "Good: CORS", Severity.INFO),
        ]
        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith('#') or stripped.startswith('//'):
                continue
            for pattern, message, severity in patterns:
                if re.search(pattern, line):
                    issues.append(self._create_issue(
                        file_path=file_path, line=line_num, message=message,
                        suggestion=message, severity=severity, code_snippet=stripped,
                    ))
        return issues
