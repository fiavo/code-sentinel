"""
Comprehensive design pattern rules for code analysis.
Covers SOLID principles, anti-patterns, and design smells.
"""

import re
from typing import Optional

from ..core.models import CodeIssue, Severity, IssueCategory
from ..core.rules import BaseRule


class SOLIDRules(BaseRule):
    """SOLID principles violations."""

    @property
    def name(self) -> str:
        return "solid"

    @property
    def description(self) -> str:
        return "SOLID principles violation detection"

    @property
    def category(self) -> IssueCategory:
        return IssueCategory.MAINTAINABILITY

    @property
    def severity(self) -> Severity:
        return Severity.WARNING

    def check(self, file_path: str, content: str) -> list[CodeIssue]:
        issues = []
        lines = content.splitlines()

        patterns = [
            # Single Responsibility Principle (SRP)
            (r'class\s+\w+.*:\s*\n(?:\s+(?:def|async def)\s+\w+.*\n){15,}', "Class with too many responsibilities (>15 methods)",
             "Split into smaller classes with single responsibility", Severity.WARNING),
            (r'class\s+\w+.*:\s*\n(?:\s+(?:def|async def)\s+\w+.*\n){25,}', "Class with too many responsibilities (>25 methods)",
             "Refactor immediately; violates Single Responsibility", Severity.WARNING),
            (r'def\s+(?:create|update|delete|send|notify|validate|process|handle)\w+', "Method doing too many things",
             "Split into smaller, focused methods", Severity.INFO),

            # Open/Closed Principle (OCP)
            (r'if\s+\w+\.type\s*==', "Type checking instead of polymorphism",
             "Use polymorphism or strategy pattern", Severity.INFO),
            (r'if\s+isinstance\s*\(\s*\w+\s*,', "isinstance check instead of polymorphism",
             "Use polymorphism or visitor pattern", Severity.INFO),
            (r'if\s+\w+\s+is\s+isinstance', "isinstance check",
             "Consider using polymorphism", Severity.INFO),

            # Liskov Substitution Principle (LSP)
            (r'raise\s+NotImplementedError\s*\(\s*\)', "Abstract method without proper interface",
             "Use ABC and @abstractmethod for proper abstraction", Severity.INFO),
            (r'(?:pass)\s*$', "Empty method body",
             "Consider using abstract base class", Severity.INFO),

            # Interface Segregation Principle (ISP)
            (r'(?:interface|Protocol)\s+\w+.*:\s*\n(?:\s+(?:def|method)\s+\w+.*\n){10,}', "Interface with too many methods",
             "Split into smaller, focused interfaces", Severity.INFO),

            # Dependency Inversion Principle (DIP)
            (r'(?:from|import)\s+mysql', "Direct database import",
             "Use dependency injection for database access", Severity.INFO),
            (r'(?:from|import)\s+(?:requests|urllib)', "Direct HTTP client import",
             "Use dependency injection for HTTP clients", Severity.INFO),
            (r'(?:from|import)\s+(?:redis|pymongo|psycopg2)', "Direct infrastructure import",
             "Use dependency injection", Severity.INFO),

            # God Class
            (r'class\s+\w+.*:\s*\n(?:\s+.*\n){200,}', "God class (>200 lines)",
             "Refactor into smaller classes", Severity.WARNING),
            (r'class\s+\w+.*:\s*\n(?:\s+.*\n){500,}', "Massive god class (>500 lines)",
             "Urgent refactor; split into multiple classes", Severity.CRITICAL),

            # Feature Envy
            (r'self\.\w+\.\w+\.\w+', "Deep property chain",
             "Consider extracting to a method or using composition", Severity.INFO),
            (r'(?:obj|item|data)\.\w+\.\w+\.\w+', "Deep property chain",
             "Consider using a dedicated object or method", Severity.INFO),
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


class AntiPatternRules(BaseRule):
    """Common anti-patterns and code smells."""

    @property
    def name(self) -> str:
        return "anti_patterns"

    @property
    def description(self) -> str:
        return "Anti-pattern and code smell detection"

    @property
    def category(self) -> IssueCategory:
        return IssueCategory.MAINTAINABILITY

    @property
    def severity(self) -> Severity:
        return Severity.WARNING

    def check(self, file_path: str, content: str) -> list[CodeIssue]:
        issues = []
        lines = content.splitlines()

        patterns = [
            # Spaghetti Code
            (r'(?:if|elif|else)\s+.*:\s*\n(?:\s+.*\n)*?\s*(?:if|elif|else)\s+.*:\s*\n(?:\s+.*\n)*?\s*(?:if|elif|else)\s+', "Deeply nested conditionals",
             "Refactor using early returns or extracted methods", Severity.WARNING),
            (r'if\s+.*\{[^}]*if\s+.*\{[^}]*if\s+', "Deeply nested if statements (JS)",
             "Refactor using early returns or extracted methods", Severity.WARNING),

            # Magic Numbers
            (r'(?:wait|sleep|delay|timeout)\s*\(\s*\d{4,}\s*\)', "Magic number for timeout/delay",
             "Extract to named constant", Severity.INFO),
            (r'(?:size|length|count|limit|offset)\s*[=:]\s*\d{4,}\s*$', "Magic number for size/limit",
             "Extract to named constant", Severity.INFO),
            (r'(?:port|host)\s*[=:]\s*\d{2,5}\s*$', "Magic number for port",
             "Extract to named constant", Severity.INFO),

            # Stringly Typed
            (r'(?:if|elif)\s+\w+\s*==\s*["\'](?:GET|POST|PUT|DELETE|PATCH)["\']', "String comparison for HTTP method",
             "Use enum or constants", Severity.INFO),
            (r'(?:if|elif)\s+\w+\s*==\s*["\'](?:admin|user|guest)["\']', "String comparison for role",
             "Use enum or constants", Severity.INFO),
            (r'(?:if|elif)\s+\w+\s*==\s*["\'](?:active|inactive|pending)["\']', "String comparison for status",
             "Use enum or constants", Severity.INFO),

            # God Method
            (r'def\s+\w+.*:\s*\n(?:\s+.*\n){40,}', "God method (>40 lines)",
             "Break into smaller methods", Severity.WARNING),
            (r'function\s+\w+.*\{(?:[^}]*\n){40,}', "God function (>40 lines)",
             "Break into smaller functions", Severity.WARNING),

            # Duplicate Code
            (r'(?s)(def\s+\w+.*?:\s*\n(?:\s+.*\n){5,}).*?\1', "Duplicate function detected",
             "Refactor to eliminate code duplication", Severity.WARNING),

            # Primitive Obsession
            (r'(?:def|function)\s+\w+\s*\([^)]*\b(?:str|int|float|bool)\b[^)]*\)', "Primitive parameter instead of object",
             "Consider using a data class or configuration object", Severity.INFO),

            # Long Parameter List
            (r'(?:def|function)\s+\w+\s*\([^)]*,[^)]*,[^)]*,[^)]*,[^)]*,[^)]*\)', "Too many parameters (>6)",
             "Use configuration object or builder pattern", Severity.WARNING),

            # Data Clumps
            (r'(?:def|function)\s+\w+\s*\([^)]*(?:host|port|url)[^)]*(?:user|pass)[^)]*\)', "Data clump: connection params",
             "Extract to a configuration class", Severity.INFO),
            (r'(?:def|function)\s+\w+\s*\([^)]*(?:x|y|width|height)[^)]*\)', "Data clump: geometry params",
             "Extract to a Point/Rect class", Severity.INFO),

            # Speculative Generality
            (r'(?:def|function)\s+\w+.*:\s*\n\s*pass\s*$', "Empty method",
             "Remove if unused; implement if needed", Severity.INFO),
            (r'(?:def|function)\s+\w+.*:\s*\n\s*\.\.\.', "Empty method with ellipsis",
             "Remove if unused; implement if needed", Severity.INFO),

            # Shotgun Surgery
            (r'(?s)(?:def\s+\w+.*?:\s*\n(?:\s+.*\n){3,}).*?(?:def\s+\w+.*?:\s*\n(?:\s+.*\n){3,}).*?\1', "Similar methods suggest shotgun surgery",
             "Consider extracting common logic", Severity.INFO),

            # Temporary Field
            (r'self\.\w+\s*=\s*None\s*$', "Temporary field (set to None)",
             "Consider using a separate class or removing", Severity.INFO),

            # Lazy Class
            (r'class\s+\w+.*:\s*\n(?:\s+(?:def|async def)\s+\w+.*\n){1,2}\s*pass', "Lazy class (1-2 methods)",
             "Consider converting to a function or removing", Severity.INFO),
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


class DesignSmellRules(BaseRule):
    """Design smell detection."""

    @property
    def name(self) -> str:
        return "design_smells"

    @property
    def description(self) -> str:
        return "Design smell detection"

    @property
    def category(self) -> IssueCategory:
        return IssueCategory.MAINTAINABILITY

    @property
    def severity(self) -> Severity:
        return Severity.INFO

    def check(self, file_path: str, content: str) -> list[CodeIssue]:
        issues = []
        lines = content.splitlines()

        patterns = [
            # Inappropriate Intimacy
            (r'self\.\w+\.\w+\.\w+\.\w+', "Excessive object chain (4+ levels)",
             "Reduce coupling; use composition or delegation", Severity.INFO),
            (r'(?:other|obj|peer)\.\w+\.\w+\.\w+', "Accessing deep properties of another object",
             "Use proper encapsulation", Severity.INFO),

            # Message Chains
            (r'\w+\.\w+\.\w+\.\w+\.\w+', "Long message chain (5+ dots)",
             "Break chain into smaller methods", Severity.WARNING),

            # Middle Man
            (r'def\s+\w+.*:\s*\n\s*return\s+self\.\w+\.\w+\s*\(\s*\)', "Method just delegates to another",
             "Consider removing the delegation", Severity.INFO),
            (r'def\s+\w+\s*\(\s*self\s*\)\s*:\s*\n\s*return\s+self\.\w+\.\w+', "Method just delegates",
             "Direct access may be more appropriate", Severity.INFO),

            # Refused Bequest
            (r'(?:class|interface)\s+\w+.*:\s*\n(?:\s+.*\n)*?\s+(?:def|async def)\s+_\w+', "Protected method in subclass",
             "Consider composition over inheritance", Severity.INFO),
            (r'(?:class|interface)\s+\w+.*:\s*\n(?:\s+.*\n)*?\s+raise\s+NotImplementedError', "Abstract method with NotImplementedError",
             "Use ABC and @abstractmethod", Severity.INFO),

            # Switch Statements
            (r'(?:if|elif)\s+\w+\s*==\s*["\'].*["\'].*:\s*\n(?:\s+.*\n)*?\s*(?:if|elif)\s+\w+\s*==\s*["\']', "Multiple switch-like conditions",
             "Use dictionary dispatch or polymorphism", Severity.INFO),
            (r'switch\s*\(\s*\w+\s*\)', "Switch statement",
             "Consider using dictionary dispatch or polymorphism", Severity.INFO),

            # Parallel Inheritance
            (r'(?:class\s+\w+.*:\s*\n(?:\s+.*\n)*?\s+class\s+\w+)', "Multiple class definitions in same scope",
             "Consider if these classes are related and should be combined", Severity.INFO),

            # Alternative Classes with Different Interfaces
            (r'(?:def|function)\s+(?:get|set|create|update|delete)\w*\s*\(', "Multiple similar methods",
             "Consider unifying interfaces", Severity.INFO),

            # Comments as Code Replacement
            (r'#\s*(?:TODO|FIXME|HACK|XXX|NOTE|REVIEW|BUG|WORKAROUND)', "TODO/FIXME comment",
             "Address the issue or create a ticket", Severity.INFO),
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
