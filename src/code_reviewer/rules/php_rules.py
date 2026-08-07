"""
PHP-specific rules for code analysis.
Comprehensive rules for PHP error detection, security, and best practices.
"""

import re
from typing import Optional

from ..core.models import CodeIssue, Severity, IssueCategory
from ..core.rules import BaseRule


class PHPRules(BaseRule):
    """PHP-specific error detection."""

    @property
    def name(self) -> str:
        return "php"

    @property
    def description(self) -> str:
        return "PHP error detection"

    @property
    def category(self) -> IssueCategory:
        return IssueCategory.STYLE

    @property
    def severity(self) -> Severity:
        return Severity.WARNING

    def check(self, file_path: str, content: str) -> list[CodeIssue]:
        # Skip if not PHP code
        php_indicators = ['<?php', 'echo ', 'print ', 'function ', 'class ', 'public ', 'private ', 'protected ', 'static ', 'final ', 'abstract ', 'interface ', 'trait ', 'namespace ', 'use ', 'require ', 'include ', '$this->', 'self::', 'parent::', 'array(', 'array[', 'null', 'true', 'false']
        is_php = any(ind in content for ind in php_indicators)
        if not is_php:
            return []

        issues = []
        lines = content.splitlines()

        patterns = [
            # Security
            (r'(?:eval|assert)\s*\(', "eval/assert usage", "Avoid eval(); use proper alternatives", Severity.CRITICAL),
            (r'(?:exec|system|passthru|shell_exec|popen|proc_open)\s*\(', "Shell execution function", "Use escapeshellarg() for arguments", Severity.CRITICAL),
            (r'\$_GET\s*\[', "Direct GET parameter access", "Validate and sanitize input", Severity.WARNING),
            (r'\$_POST\s*\[', "Direct POST parameter access", "Validate and sanitize input", Severity.WARNING),
            (r'\$_REQUEST\s*\[', "Direct REQUEST parameter access", "Use $_GET or $_POST explicitly", Severity.WARNING),
            (r'\$_COOKIE\s*\[', "Direct cookie access", "Validate and sanitize cookies", Severity.WARNING),
            (r'\$_SERVER\s*\[', "Direct server variable access", "Validate server variables", Severity.INFO),
            (r'(?:mysql_query|mysqli_query)\s*\(\s*["\']', "SQL query with string", "Use prepared statements", Severity.CRITICAL),
            (r'(?:mysql_query|mysqli_query)\s*\(\s*\$', "SQL query with variable", "Use prepared statements", Severity.CRITICAL),
            (r'(?:include|require|include_once|require_once)\s*\(?\s*["\']?\s*\$', "Dynamic file inclusion", "Validate file paths; use whitelisting", Severity.CRITICAL),
            (r'(?i)serialize\s*\(', "Unserialization", "Use JSON instead of unserialize", Severity.CRITICAL),
            (r'(?i)unserialize\s*\(', "Unserialization", "Validate data before unserializing", Severity.CRITICAL),
            (r'(?:md5|sha1)\s*\(\s*\$', "Weak hashing with variable", "Use password_hash() for passwords", Severity.WARNING),
            (r'(?i)password_hash\s*\(', "Password hashing", "Good: using password_hash()", Severity.INFO),
            (r'(?i)password_verify\s*\(', "Password verification", "Good: using password_verify()", Severity.INFO),

            # Type safety
            (r'(?i)(?:==|!=)\s*(?:null|NULL)', "Loose null comparison", "Use === or !== for strict comparison", Severity.WARNING),
            (r'(?i)(?:==|!=)\s*["\']', "Loose string comparison", "Use === or !== for strict comparison", Severity.WARNING),
            (r'(?i)isset\s*\(\s*\$', "isset() usage", "Consider using null coalescing (??) operator", Severity.INFO),
            (r'(?i)empty\s*\(\s*\$', "empty() usage", "Consider using explicit checks", Severity.INFO),
            (r'(?i)(?:settype|intval|floatval|strval)\s*\(', "Type casting function", "Use type casting (int)$var instead", Severity.INFO),
            (r'(?i)(?:int|string|float|array|object|bool)\s*\$', "Type casting", "Good: using type casting", Severity.INFO),

            # Error handling
            (r'(?i)try\s*\{', "Try block", "Good: using try-catch", Severity.INFO),
            (r'(?i)catch\s*\(\s*\\\\?\w+(?:\\\\\w+)*\s+\$', "Catch block", "Good: catching exceptions", Severity.INFO),
            (r'(?i)catch\s*\(\s*\\\\?Exception\s+\$', "Catching generic Exception", "Consider catching specific exceptions", Severity.INFO),
            (r'(?i)@\\\\', "Error suppression (@)", "Use try-catch instead of @", Severity.WARNING),
            (r'(?i)trigger_error\s*\(', "trigger_error usage", "Use exceptions instead", Severity.INFO),
            (r'(?i)error_reporting\s*\(', "Error reporting modification", "Use exception handling", Severity.INFO),

            # Performance
            (r'(?i)(?:for|foreach|while)\s*\(.*\$\w+\s*=\s*\w+\s*\(', "Function call in loop", "Cache function results outside loop", Severity.WARNING),
            (r'(?i)str_replace\s*\(\s*["\'][^"\']+["\'].*\$.*\$.*\$', "str_replace with variable", "Consider using preg_replace for complex patterns", Severity.INFO),
            (r'(?i)(?:strlen|strpos|substr|str_split|explode|implode)\s*\(', "String function", "Good: using string functions", Severity.INFO),
            (r'(?i)(?:array_map|array_filter|array_walk)\s*\(', "Array function", "Good: using array functions", Severity.INFO),
            (r'(?i)(?:in_array|array_search|array_key_exists)\s*\(', "Array search function", "Good: using array functions", Severity.INFO),
            (r'(?i)(?:array_push|array_pop|array_shift|array_unshift)\s*\(', "Array operation", "Consider using [] operator for push", Severity.INFO),

            # OOP
            (r'(?i)(?:public|private|protected)\s+(?:static\s+)?(?:function|const)\s+\w+', "Visibility modifier", "Good: using visibility modifiers", Severity.INFO),
            (r'(?i)(?:final|abstract)\s+(?:class|function)\s+', "Class/function modifier", "Good: using modifiers", Severity.INFO),
            (r'(?i)(?:interface|trait)\s+\w+', "Interface/trait declaration", "Good: using interfaces/traits", Severity.INFO),
            (r'(?i)(?:extends|implements)\s+\w+', "Inheritance/implementation", "Good: using OOP patterns", Severity.INFO),
            (r'\$this->', "Property access", "Good: using object property access", Severity.INFO),
            (r'(?:self|parent|static)::', "Static access", "Good: using static access", Severity.INFO),
            (r'(?:\\\\?self|\\\\?parent|\\\\?static)::\$\w+', "Static property", "Good: using static properties", Severity.INFO),

            # Modern PHP
            (r'(?i)(?:match|match\()', "Match expression (PHP 8)", "Good: using match expression", Severity.INFO),
            (r'(?i)(?:named argument|:\s*\w+\s*[=:])', "Named arguments", "Good: using named arguments", Severity.INFO),
            (r'(?i)(?:union type|\w+\|\w+)', "Union types (PHP 8)", "Good: using union types", Severity.INFO),
            (r'(?i)(?:intersection type|\w+&\w+)', "Intersection types (PHP 8.1)", "Good: using intersection types", Severity.INFO),
            (r'(?i)(?:enum\s+\w+\s*\{)', "Enum (PHP 8.1)", "Good: using enums", Severity.INFO),
            (r'(?i)(?:readonly\s+(?:class|property))', "Readonly (PHP 8.1)", "Good: using readonly", Severity.INFO),
            (r'(?i)(?:fiber|Fiber)', "Fiber (PHP 8.1)", "Good: using fibers", Severity.INFO),
            (r'(?i)(?:nullsafe\s+operator|\?\->)', "Nullsafe operator (PHP 8)", "Good: using nullsafe operator", Severity.INFO),
            (r'(?i)(?:str_contains|str_starts_with|str_ends_with)', "String functions (PHP 8)", "Good: using modern string functions", Severity.INFO),

            # PHPDoc
            (r'/\*\*', "PHPDoc block", "Good: using PHPDoc", Severity.INFO),
            (r'(?i)(?:@param|@return|@throws|@var|@property)', "PHPDoc tag", "Good: using PHPDoc tags", Severity.INFO),
            (r'(?i)(?:@deprecated|@todo|@fixme)', "PHPDoc deprecation/todo", "Good: documenting issues", Severity.INFO),

            # Laravel/WordPress patterns
            (r'(?i)(?:Artisan::call|Route::|Eloquent|Blade)', "Laravel pattern", "Good: using Laravel features", Severity.INFO),
            (r'(?i)(?:add_action|add_filter|do_action|apply_filters)', "WordPress hook", "Good: using WordPress hooks", Severity.INFO),
            (r'(?i)(?:wpdb|\\$wpdb)', "WordPress database", "Good: using WordPress DB", Severity.INFO),
        ]

        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith('//') or stripped.startswith('#'):
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
