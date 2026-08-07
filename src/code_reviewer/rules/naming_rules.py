"""
Comprehensive naming conventions and documentation rules.
Covers naming patterns, documentation requirements, and code organization.
"""

import re
from typing import Optional

from ..core.models import CodeIssue, Severity, IssueCategory
from ..core.rules import BaseRule


class NamingConventionRules(BaseRule):
    """Naming convention detection for multiple languages."""

    @property
    def name(self) -> str:
        return "naming"

    @property
    def description(self) -> str:
        return "Naming convention detection"

    @property
    def category(self) -> IssueCategory:
        return IssueCategory.STYLE

    @property
    def severity(self) -> Severity:
        return Severity.INFO

    def check(self, file_path: str, content: str) -> list[CodeIssue]:
        issues = []
        lines = content.splitlines()

        patterns = [
            # Python naming
            (r'class\s+[a-z]', "Class name should use CamelCase (Python)", "Use CamelCase for class names", Severity.INFO),
            (r'def\s+[A-Z]', "Function name should use snake_case (Python)", "Use snake_case for function names", Severity.INFO),
            (r'(?:^|\s)[A-Z][a-z]+[A-Z]\w*\s*=', "Variable should use snake_case (Python)", "Use snake_case for variables", Severity.INFO),
            (r'(?:^|\s)_[a-z]\w*\s*=', "Private variable naming", "Use _prefix for private variables", Severity.INFO),
            (r'def\s+__(?:init|str|repr|eq|ne|lt|gt|le|ge|add|sub|mul|div|mod|pow|and|or|not|hash|call)__\s*\(', "Dunder method", "Good: using Python special methods", Severity.INFO),

            # JavaScript/TypeScript naming
            (r'(?:const|let|var)\s+[a-z]+[A-Z]\w*\s*=', "Variable should use camelCase (JS)", "Use camelCase for variables", Severity.INFO),
            (r'(?:const|let|var)\s+[A-Z][A-Z_]+\s*=', "Constant should use UPPER_SNAKE_CASE", "Good: using UPPER_SNAKE_CASE for constants", Severity.INFO),
            (r'function\s+[A-Z]\w*\s*\(', "Function should use camelCase (JS)", "Use camelCase for functions", Severity.INFO),
            (r'(?:const|let|var)\s+[a-z]+-[a-z]+\s*=', "Variable should use camelCase not kebab-case", "Use camelCase for variables", Severity.INFO),

            # Java naming
            (r'(?:public|private|protected)\s+(?:static\s+)?(?:final\s+)?[A-Z]\w*\s+[a-z]\w*\s*[=;]', "Field should use camelCase (Java)", "Use camelCase for fields", Severity.INFO),
            (r'(?:public|private|protected)\s+(?:static\s+)?void\s+[A-Z]\w*\s*\(', "Method should use camelCase (Java)", "Use camelCase for methods", Severity.INFO),
            (r'(?:public|private|protected)\s+class\s+[a-z]', "Class name should use CamelCase (Java)", "Use CamelCase for classes", Severity.INFO),

            # Go naming
            (r'func\s+[a-z]\w*\s*\(', "Unexported function should use camelCase (Go)", "Use camelCase for unexported functions", Severity.INFO),
            (r'func\s+[A-Z]\w*\s*\(', "Exported function should use CamelCase (Go)", "Good: using CamelCase for exported functions", Severity.INFO),
            (r'type\s+[a-z]\w*\s+struct', "Type should use CamelCase (Go)", "Use CamelCase for type names", Severity.INFO),
            (r'var\s+[a-z]+[A-Z]\w*\s*=', "Variable should use camelCase (Go)", "Use camelCase for variables", Severity.INFO),

            # Rust naming
            (r'fn\s+[a-z]+_[a-z]\w*\s*\(', "Function should use snake_case (Rust)", "Use snake_case for functions", Severity.INFO),
            (r'fn\s+[A-Z]\w*\s*\(', "Function should use snake_case (Rust)", "Use snake_case for functions", Severity.INFO),
            (r'(?:let|const)\s+[A-Z]\w*\s*=', "Variable should use snake_case (Rust)", "Use snake_case for variables", Severity.INFO),
            (r'stuct\s+[A-Z][a-z]+[A-Z]', "Struct should use CamelCase (Rust)", "Use CamelCase for structs", Severity.INFO),
            (r'enum\s+[A-Z][a-z]+[A-Z]', "Enum should use CamelCase (Rust)", "Use CamelCase for enums", Severity.INFO),

            # General naming issues
            (r'(?:var|let|const)\s+[a-z]\s*=', "Single letter variable name", "Use descriptive variable names", Severity.INFO),
            (r'def\s+[a-z]\s*\(', "Single letter function name", "Use descriptive function names", Severity.INFO),
            (r'(?:var|let|const)\s+\w{1,2}\s*=', "Very short variable name", "Use more descriptive names", Severity.INFO),
            (r'(?:temp|tmp|foo|bar|baz)\s*=', "Placeholder variable name", "Use meaningful variable names", Severity.INFO),
            (r'(?:test|xxx|yyy|zzz)\s*=', "Test/placeholder variable name", "Use meaningful variable names", Severity.INFO),

            # Hungarian notation ( discouraged)
            (r'(?:str|int|bool|float|obj|arr|func)\w*\s*[=:]\s*', "Hungarian notation detected",
             "Use descriptive names without type prefixes", Severity.INFO),

            # Boolean naming
            (r'(?:var|let|const|self\.|this\.)\w*(?:is|has|can|should|will|was)\w*\s*=', "Boolean naming with prefix",
             "Good: using boolean naming conventions", Severity.INFO),
            (r'(?:var|let|const|self\.|this\.)\w*\s*=\s*(?:true|false|True|False)\b', "Boolean variable",
             "Consider using descriptive boolean name", Severity.INFO),
        ]

        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith('#') or stripped.startswith('//') or stripped.startswith('*'):
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


class DocumentationRules(BaseRule):
    """Documentation and comment quality rules."""

    @property
    def name(self) -> str:
        return "documentation"

    @property
    def description(self) -> str:
        return "Documentation quality detection"

    @property
    def category(self) -> IssueCategory:
        return IssueCategory.STYLE

    @property
    def severity(self) -> Severity:
        return Severity.INFO

    def check(self, file_path: str, content: str) -> list[CodeIssue]:
        issues = []
        lines = content.splitlines()

        patterns = [
            # Missing docstrings
            (r'def\s+\w+\s*\([^)]*\)\s*(?:->.*)?:\s*\n\s*(?:(?!"""))', "Function without docstring",
             "Add docstring to explain function purpose", Severity.INFO),
            (r'class\s+\w+.*:\s*\n\s*(?:(?!"""))', "Class without docstring",
             "Add docstring to explain class purpose", Severity.INFO),

            # TODO/FIXME/HACK/XXX
            (r'#\s*TODO\b', "TODO comment found",
             "Address the TODO or create an issue", Severity.INFO),
            (r'#\s*FIXME\b', "FIXME comment found",
             "Fix the issue or create an issue", Severity.WARNING),
            (r'#\s*HACK\b', "HACK comment found",
             "Refactor to remove the hack", Severity.WARNING),
            (r'#\s*XXX\b', "XXX comment found",
             "Review and address the issue", Severity.WARNING),
            (r'//\s*TODO\b', "TODO comment found",
             "Address the TODO or create an issue", Severity.INFO),
            (r'//\s*FIXME\b', "FIXME comment found",
             "Fix the issue or create an issue", Severity.WARNING),
            (r'//\s*HACK\b', "HACK comment found",
             "Refactor to remove the hack", Severity.WARNING),

            # Outdated comments
            (r'#\s*(?:old|deprecated|legacy|outdated|obsolete)\b', "Potentially outdated comment",
             "Review and update or remove", Severity.INFO),
            (r'//\s*(?:old|deprecated|legacy|outdated|obsolete)\b', "Potentially outdated comment",
             "Review and update or remove", Severity.INFO),

            # Commented code
            (r'#\s*(?:def|class|import|from|if|for|while|return|print)\s', "Commented code detected",
             "Remove commented code or use version control", Severity.INFO),
            (r'//\s*(?:function|const|let|var|if|for|while|return|console)\s', "Commented code detected",
             "Remove commented code or use version control", Severity.INFO),

            # Magic numbers
            (r'(?<![a-zA-Z_])\d{4,}(?![a-zA-Z_])', "Magic number detected",
             "Extract to named constant", Severity.INFO),
            (r'(?:if|elif|else|while|for)\s*\(.*(?:>|<|>=|<=|==|!=)\s*\d{3,}', "Magic number in condition",
             "Extract to named constant", Severity.INFO),

            # Empty comments
            (r'^\s*#\s*$', "Empty comment",
             "Remove empty comments or add content", Severity.INFO),
            (r'^\s*//\s*$', "Empty comment",
             "Remove empty comments or add content", Severity.INFO),
            (r'^\s*/\*\s*\*/$', "Empty block comment",
             "Remove empty comments or add content", Severity.INFO),
        ]

        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()

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


class CodeOrganizationRules(BaseRule):
    """Code organization and structure rules."""

    @property
    def name(self) -> str:
        return "organization"

    @property
    def description(self) -> str:
        return "Code organization and structure detection"

    @property
    def category(self) -> IssueCategory:
        return IssueCategory.STYLE

    @property
    def severity(self) -> Severity:
        return Severity.INFO

    def check(self, file_path: str, content: str) -> list[CodeIssue]:
        issues = []
        lines = content.splitlines()

        patterns = [
            # Too many parameters
            (r'def\s+\w+\s*\([^)]*,[^)]*,[^)]*,[^)]*,[^)]*\)', "Function has too many parameters (>5)",
             "Refactor to use configuration object or multiple functions", Severity.WARNING),
            (r'function\s+\w+\s*\([^)]*,[^)]*,[^)]*,[^)]*,[^)]*\)', "Function has too many parameters (>5)",
             "Refactor to use options object or multiple functions", Severity.WARNING),

            # God function
            (r'def\s+\w+.*:\s*\n(?:\s+.*\n){50,}', "Function is too long (>50 lines)",
             "Break into smaller functions", Severity.WARNING),
            (r'function\s+\w+.*\{(?:[^}]*\n){50,}', "Function is too long (>50 lines)",
             "Break into smaller functions", Severity.WARNING),

            # God class
            (r'class\s+\w+.*:\s*\n(?:\s+(?:def|async def)\s+\w+.*\n){20,}', "Class has too many methods (>20)",
             "Consider splitting into multiple classes", Severity.WARNING),

            # Deep nesting
            (r'^(?:\s{8,}|\t{2,})\w', "Deeply nested code (3+ levels)",
             "Refactor to reduce nesting depth", Severity.WARNING),
            (r'^(?:\s{16,}|\t{4,})\w', "Very deeply nested code (4+ levels)",
             "Refactor immediately; use early returns", Severity.WARNING),

            # Too many imports
            (r'(?:^import\s+\w+\s*$|^from\s+\w+\s+import)', "Many imports detected",
             "Consider if all imports are necessary", Severity.INFO),

            # Missing type hints
            (r'def\s+\w+\s*\([^)]*\)\s*:', "Function without type hints",
             "Add type hints for better code clarity", Severity.INFO),

            # Magic strings
            (r'(?:==|!=)\s*["\'][^"\']{20,}["\']', "Long magic string in comparison",
             "Extract to named constant", Severity.INFO),
            (r'(?:if|elif|else)\s+.*["\'](?:error|success|failed|true|false)["\']', "Magic string in condition",
             "Extract to named constant or enum", Severity.INFO),

            # Dead code patterns
            (r'return\s+.*\n\s+\w+', "Code after return statement",
             "Remove unreachable code", Severity.WARNING),
            (r'else\s*:\s*\n\s*return', "Else after return",
             "Simplify by removing else after return", Severity.INFO),
            (r'if\s+True\s*:', "if True: always executes",
             "Remove unnecessary condition", Severity.WARNING),
            (r'if\s+False\s*:', "if False: never executes",
             "Remove dead code", Severity.WARNING),

            # Code duplication indicators
            (r'(?:copy|paste|duplicate|重复|复制)\s*(?:from|of|代码)', "Copy-paste comment detected",
             "Refactor duplicated code into functions", Severity.INFO),
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
