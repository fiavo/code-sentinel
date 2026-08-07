"""
Common programming anti-patterns and code smells.
"""

import re
from typing import Optional

from ..core.models import CodeIssue, Severity, IssueCategory
from ..core.rules import BaseRule


class AntiPatternExtendedRules(BaseRule):
    """Extended anti-pattern detection."""

    @property
    def name(self) -> str:
        return "antipattern_extended"

    @property
    def description(self) -> str:
        return "Extended anti-pattern detection"

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
            # God Object
            (r'class\s+\w+.*:\s*\n(?:\s+(?:def|async def|function|method)\s+\w+.*\n){30,}', "God object (>30 methods)", "Split into smaller classes", Severity.WARNING),
            (r'object\s+\w+.*:\s*\n(?:\s+(?:def|async def)\s+\w+.*\n){20,}', "God object (>20 methods)", "Split into smaller objects", Severity.WARNING),

            # Feature Envy
            (r'\w+\.\w+\.\w+\.\w+\.\w+', "Deep property chain (5+ levels)", "Reduce coupling; use composition", Severity.WARNING),
            (r'(?:obj|item|data)\.\w+\.\w+\.\w+\.\w+', "Deep property chain", "Consider using a dedicated object", Severity.INFO),

            # Data Clumps
            (r'(?:x|y|z)\s*,\s*(?:x|y|z)\s*,\s*(?:x|y|z)', "Data clump (x,y,z)", "Extract to a Point/Vector class", Severity.INFO),
            (r'(?:host|port|url|user|pass)', "Connection parameters", "Extract to configuration class", Severity.INFO),
            (r'(?:width|height|top|left|bottom|right)', "Geometry parameters", "Extract to Rectangle/Bounds class", Severity.INFO),
            (r'(?:min|max|start|end)', "Range parameters", "Extract to Range class", Severity.INFO),

            # Primitive Obsession
            (r'(?:string|int|bool|float)\s+\w+\s*=\s*["\'](?:admin|user|guest)["\']', "String-based type", "Use enum or class hierarchy", Severity.INFO),
            (r'(?:string|int|bool)\s+\w+\s*=\s*(?:true|false|0|1)\b', "Magic value", "Use named constant or enum", Severity.INFO),

            # Switch Statements
            (r'(?:if|elif|else)\s+\w+\s*==\s*["\'](?:GET|POST|PUT|DELETE)["\']', "Switch-like condition", "Use polymorphism or strategy pattern", Severity.INFO),
            (r'(?:if|elif|else)\s+\w+\s*==\s*["\'](?:admin|user|guest)["\']', "Switch-like condition", "Use enum or strategy pattern", Severity.INFO),
            (r'(?:if|elif|else)\s+\w+\s*==\s*["\'](?:active|inactive|pending)["\']', "Switch-like condition", "Use enum or state pattern", Severity.INFO),

            # Parallel Inheritance
            (r'class\s+\w+.*:\s*\n(?:\s+.*\n)*?\s+class\s+\w+', "Multiple class definitions", "Consider if classes are related", Severity.INFO),

            # Refused Bequest
            (r'(?:class|interface)\s+\w+.*:\s*\n(?:\s+.*\n)*?\s+raise\s+NotImplementedError', "Abstract method with NotImplementedError", "Use ABC and @abstractmethod", Severity.INFO),

            # Lazy Class
            (r'class\s+\w+.*:\s*\n(?:\s+(?:def|async def)\s+\w+.*\n){1,2}\s*pass', "Lazy class (1-2 methods)", "Consider converting to function", Severity.INFO),

            # Speculative Generality
            (r'(?:def|function)\s+\w+.*:\s*\n\s*pass\s*$', "Empty method body", "Remove if unused; implement if needed", Severity.INFO),
            (r'(?:def|function)\s+\w+.*:\s*\n\s*\.\.\.', "Empty method with ellipsis", "Remove if unused; implement if needed", Severity.INFO),

            # Temporary Field
            (r'self\.\w+\s*=\s*None\s*$', "Temporary field (set to None)", "Consider using separate class", Severity.INFO),

            # Message Chains
            (r'\w+\.\w+\.\w+\.\w+\.\w+\.\w+', "Long message chain (6+ dots)", "Break chain into smaller methods", Severity.WARNING),

            # Middle Man
            (r'def\s+\w+.*:\s*\n\s*return\s+self\.\w+\.\w+\s*\(\s*\)', "Method just delegates", "Consider removing delegation", Severity.INFO),

            # Inappropriate Intimacy
            (r'self\.\w+\.\w+\.\w+\.\w+\.\w+', "Excessive object chain (5+ levels)", "Reduce coupling; use composition", Severity.INFO),

            # Shotgun Surgery
            (r'(?s)(?:def\s+\w+.*?:\s*\n(?:\s+.*\n){3,}).*?(?:def\s+\w+.*?:\s*\n(?:\s+.*\n){3,})', "Similar methods", "Consider extracting common logic", Severity.INFO),

            # Divergent Change
            (r'(?s)(?:import\s+.*\n){5,}', "Many imports", "Consider splitting responsibilities", Severity.INFO),

            # Rapeseed Change
            (r'(?:class|function)\s+\w+.*:\s*\n(?:\s+.*\n)*?\s+(?:if|elif|else)\s+', "Class/function with many conditions", "Consider using strategy pattern", Severity.INFO),

            # Long Parameter List
            (r'(?:def|function)\s+\w+\s*\([^)]*,[^)]*,[^)]*,[^)]*,[^)]*,[^)]*\)', "Too many parameters (>6)", "Use configuration object", Severity.WARNING),

            # Comments as Code Replacement
            (r'#\s*(?:TODO|FIXME|HACK|XXX|NOTE|REVIEW|BUG|WORKAROUND)', "TODO/FIXME comment", "Address the issue or create ticket", Severity.INFO),

            # Dead Code
            (r'return\s+.*\n\s+\w+', "Code after return statement", "Remove unreachable code", Severity.WARNING),
            (r'else\s*:\s*\n\s*return', "Else after return", "Simplify by removing else", Severity.INFO),
            (r'if\s+True\s*:', "if True: always executes", "Remove unnecessary condition", Severity.WARNING),
            (r'if\s+False\s*:', "if False: never executes", "Remove dead code", Severity.WARNING),

            # Magic Numbers
            (r'(?:wait|sleep|delay|timeout)\s*\(\s*\d{4,}\s*\)', "Magic number for timeout", "Extract to named constant", Severity.INFO),
            (r'(?:size|length|count|limit|offset)\s*[=:]\s*\d{4,}', "Magic number for size", "Extract to named constant", Severity.INFO),
            (r'(?:port|host)\s*[=:]\s*\d{2,5}', "Magic number for port", "Extract to named constant", Severity.INFO),
            (r'(?:max|min|default|limit)\s*[=:]\s*\d{3,}', "Magic number", "Extract to named constant", Severity.INFO),

            # Stringly Typed
            (r'(?:if|elif)\s+\w+\s*==\s*["\'](?:GET|POST|PUT|DELETE|PATCH)["\']', "String comparison for HTTP method", "Use enum or constants", Severity.INFO),
            (r'(?:if|elif)\s+\w+\s*==\s*["\'](?:admin|user|guest)["\']', "String comparison for role", "Use enum or constants", Severity.INFO),
            (r'(?:if|elif)\s+\w+\s*==\s*["\'](?:active|inactive|pending)["\']', "String comparison for status", "Use enum or constants", Severity.INFO),
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
