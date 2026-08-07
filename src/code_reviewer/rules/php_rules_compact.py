"""
PHP-specific comprehensive rules.
"""
import re
from ..core.models import CodeIssue, Severity, IssueCategory
from ..core.rules import BaseRule


class PHPCompactRules(BaseRule):
    @property
    def name(self) -> str:
        return "php_compact"
    @property
    def description(self) -> str:
        return "PHP-specific comprehensive patterns"
    @property
    def category(self) -> IssueCategory:
        return IssueCategory.BEST_PRACTICE
    @property
    def severity(self) -> Severity:
        return Severity.WARNING

    def check(self, file_path: str, content: str) -> list[CodeIssue]:
        issues = []
        lines = content.splitlines()
        patterns = [
            # PHP features
            (r"<\?php", "PHP tag", "Good: PHP tag", Severity.INFO),
            (r"function\s+\w+\(", "Function definition", "Good: function", Severity.INFO),
            (r"class\s+\w+", "Class definition", "Good: class", Severity.INFO),
            (r"interface\s+\w+", "Interface definition", "Good: interface", Severity.INFO),
            (r"abstract\s+class\s+\w+", "Abstract class", "Good: abstract class", Severity.INFO),
            (r"final\s+class\s+\w+", "Final class", "Good: final class", Severity.INFO),
            (r"trait\s+\w+", "Trait definition", "Good: trait", Severity.INFO),
            (r"enum\s+\w+", "Enum definition", "Good: enum", Severity.INFO),
            (r"namespace\s+\w+", "Namespace", "Good: namespace", Severity.INFO),
            (r"use\s+\w+\\", "Use statement", "Good: use statement", Severity.INFO),
            # PHP types
            (r":\s*(?:string|int|float|bool|array|object|void|never|static|self|parent|null|mixed|\?\\?\\w+)", "Type declaration", "Good: type declaration", Severity.INFO),
            (r"\?\w+", "Nullable type", "Good: nullable type", Severity.INFO),
            (r"readonly\s+(?:class\s+)?\w+", "Readonly", "Good: readonly", Severity.INFO),
            (r"\$\w+\s*:\s*\w+", "Typed property", "Good: typed property", Severity.INFO),
            # PHP modern features
            (r"match\s*\(", "Match expression", "Good: match expression", Severity.INFO),
            (r"\w+\?\->", "Nullsafe operator", "Good: nullsafe operator", Severity.INFO),
            (r"named\s+arguments|:\s*\w+\s*=\s*\w+", "Named arguments", "Good: named arguments", Severity.INFO),
            (r"fiber\s*\(|Fiber\s*\(", "Fiber", "Good: Fiber", Severity.INFO),
            (r"enum\s+\w+\s*:\s*\w+", "Backed enum", "Good: backed enum", Severity.INFO),
            # PHP arrays
            (r"\[.*=>.*\]", "Array", "Good: array", Severity.INFO),
            (r"array_map|array_filter|array_reduce|array_walk|array_search|array_key_exists|array_unique|array_merge|array_combine|array_column|array_slice|array_splice|array_push|array_pop|array_shift|array_unshift|array_count_values|array_flip|array_reverse|array_pad|array_fill|array_keys|array_values|array_sum|array_product|array_min|array_max", "Array function", "Good: array function", Severity.INFO),
            # PHP error handling
            (r"try\s*\{", "Try block", "Good: try block", Severity.INFO),
            (r"catch\s*\(\s*\w+", "Catch block", "Good: catch block", Severity.INFO),
            (r"finally\s*\{", "Finally block", "Good: finally block", Severity.INFO),
            (r"throw\s+new\s+\w+", "Throw exception", "Good: throw exception", Severity.INFO),
            # PHP OOP
            (r"public\s+function\s+\w+", "Public method", "Good: public method", Severity.INFO),
            (r"private\s+function\s+\w+", "Private method", "Good: private method", Severity.INFO),
            (r"protected\s+function\s+\w+", "Protected method", "Good: protected method", Severity.INFO),
            (r"static\s+function\s+\w+", "Static method", "Good: static method", Severity.INFO),
            (r"abstract\s+function\s+\w+", "Abstract method", "Good: abstract method", Severity.INFO),
            (r"final\s+function\s+\w+", "Final method", "Good: final method", Severity.INFO),
            (r"__construct|__destruct|__get|__set|__call|__toString|__clone|__invoke|__serialize|__unserialize", "Magic methods", "Good: magic methods", Severity.INFO),
            (r"self::|static::|parent::", "Scope resolution", "Good: scope resolution", Severity.INFO),
            # PHP attributes
            (r"@\w+\(|#\[\w+\]", "Attribute/annotation", "Good: attributes", Severity.INFO),
            # PHP testing
            (r"test_\w+|it_\w+|assert\w*\(", "PHPUnit test", "Good: PHPUnit test", Severity.INFO),
            (r"\$this->assert|expect\(\w+\)->", "Test assertion", "Good: test assertion", Severity.INFO),
            # PHP frameworks
            (r"Laravel|Symfony|CakePHP|CodeIgniter|Yii|Slim|Lumen|Phalcon|FuelPHP|PHPixie|Drupal|WordPress|Joomla|Magento|WooCommerce", "PHP framework", "Good: PHP framework", Severity.INFO),
            (r"blade|Blade|Twig|twig|Smarty|smarty|Plates|plates", "Template engine", "Good: template engine", Severity.INFO),
            (r"Eloquent|Query Builder|DB::|Schema::|Migration|Seeder|Factory", "Eloquent/DB", "Good: Eloquent/DB", Severity.INFO),
            (r"Route::|Controller|Middleware|ServiceProvider|Config|Event|Queue|Mail|Notification|Auth|Gate|Policy", "Laravel", "Good: Laravel", Severity.INFO),
            (r"Console|Command|Kernel|Schedule|Task|Event|Listener|Observer|EventServiceProvider", "Laravel", "Good: Laravel", Severity.INFO),
            # PHP tools
            (r"Composer|composer|PHPUnit|phpunit|PHPStan|phpstan|Psalm|psalm|PHP_CodeSniffer|phpcs|PHP-CS-Fixer|php-cs-fixer|PHPBench|phpbench|Rector|rector", "PHP tools", "Good: PHP tools", Severity.INFO),
            (r"PSR-[0-9]|PSR-\d+", "PSR standard", "Good: PSR standards", Severity.INFO),
            # PHP security
            (r"htmlspecialchars|htmlentities|strip_tags|addslashes|stripslashes|escapeshellarg|escapeshellcmd|filter_var|filter_input", "Input sanitization", "Good: input sanitization", Severity.INFO),
            (r"password_hash|password_verify|password_needs_rehash", "Password hashing", "Good: password hashing", Severity.INFO),
            (r"\$_GET|\$_POST|\$_REQUEST|\$_COOKIE|\$_SERVER|\$_SESSION|\$_FILES|\$_ENV|\$_GLOBALS", "Superglobals", "Sanitize superglobals", Severity.WARNING),
        ]
        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith('//') or stripped.startswith('#') or stripped.startswith('/*'):
                continue
            for pattern, message, severity in patterns:
                if re.search(pattern, line):
                    issues.append(self._create_issue(
                        file_path=file_path, line=line_num, message=message,
                        suggestion=message, severity=severity, code_snippet=stripped,
                    ))
        return issues
