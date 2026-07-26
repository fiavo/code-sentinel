"""
Built-in code review rules.
"""

import re
from abc import ABC, abstractmethod
from typing import Optional

from ..core.models import CodeIssue, Severity, IssueCategory


class BaseRule(ABC):
    """Base class for all code review rules."""
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Rule name."""
        ...
    
    @property
    @abstractmethod
    def description(self) -> str:
        """Rule description."""
        ...
    
    @property
    @abstractmethod
    def category(self) -> IssueCategory:
        """Rule category."""
        ...
    
    @property
    @abstractmethod
    def severity(self) -> Severity:
        """Default severity."""
        ...
    
    @abstractmethod
    def check(self, file_path: str, content: str) -> list[CodeIssue]:
        """
        Check code for issues.
        
        Args:
            file_path: Path to the file
            content: File content
            
        Returns:
            List of issues found
        """
        ...
    
    def _create_issue(
        self,
        file_path: str,
        line: int,
        message: str,
        suggestion: str = "",
        severity: Optional[Severity] = None,
        column: int = 0,
        code_snippet: str = "",
    ) -> CodeIssue:
        """Helper to create an issue."""
        return CodeIssue(
            file=file_path,
            line=line,
            column=column,
            severity=severity or self.severity,
            category=self.category,
            message=message,
            rule=self.name,
            suggestion=suggestion,
            code_snippet=code_snippet,
        )


class SecurityRules(BaseRule):
    """Security-related rules."""
    
    @property
    def name(self) -> str:
        return "security"
    
    @property
    def description(self) -> str:
        return "Security vulnerability detection"
    
    @property
    def category(self) -> IssueCategory:
        return IssueCategory.SECURITY
    
    @property
    def severity(self) -> Severity:
        return Severity.CRITICAL
    
    def check(self, file_path: str, content: str) -> list[CodeIssue]:
        issues = []
        lines = content.splitlines()
        
        # Patterns to detect
        patterns = [
            # Hardcoded secrets
            (r'(?:password|secret|api_key|apikey|token)\s*=\s*["\'][^"\']+["\']',
             "Hardcoded secret detected",
             "Use environment variables or a secrets manager"),
            
            # SQL injection
            (r'(?:execute|cursor\.execute)\s*\(\s*["\'].*%s',
             "Potential SQL injection (string formatting)",
             "Use parameterized queries"),
            
            # Eval usage
            (r'\beval\s*\(',
             "Use of eval() detected",
             "Avoid eval() - use ast.literal_eval() or safer alternatives"),
            
            # Exec usage
            (r'\bexec\s*\(',
             "Use of exec() detected",
             "Avoid exec() - refactor to use functions"),
            
            # Pickle loading
            (r'pickle\.loads?\s*\(',
             "Pickle deserialization detected",
             "Pickle can execute arbitrary code - use JSON or msgpack"),
            
            # Subprocess shell=True
            (r'subprocess\.\w+\s*\(.*shell\s*=\s*True',
             "Subprocess with shell=True",
             "Use shell=False with a list of arguments"),
            
            # Weak hashing
            (r'\b(?:md5|sha1)\s*\(',
             "Weak hash algorithm detected",
             "Use SHA-256 or stronger"),
            
            # Debug mode in production
            (r'DEBUG\s*=\s*True',
             "Debug mode enabled",
             "Disable debug mode in production"),
        ]
        
        for line_num, line in enumerate(lines, 1):
            for pattern, message, suggestion in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    issues.append(self._create_issue(
                        file_path=file_path,
                        line=line_num,
                        message=message,
                        suggestion=suggestion,
                        code_snippet=line.strip(),
                    ))
        
        return issues


class PerformanceRules(BaseRule):
    """Performance-related rules."""
    
    @property
    def name(self) -> str:
        return "performance"
    
    @property
    def description(self) -> str:
        return "Performance issue detection"
    
    @property
    def category(self) -> IssueCategory:
        return IssueCategory.PERFORMANCE
    
    @property
    def severity(self) -> Severity:
        return Severity.WARNING
    
    def check(self, file_path: str, content: str) -> list[CodeIssue]:
        issues = []
        lines = content.splitlines()
        
        patterns = [
            # N+1 query pattern (SQLAlchemy)
            (r'for\s+\w+\s+in\s+\w+\.query.*\.all\(\)',
             "Potential N+1 query pattern",
             "Use joinedload() or bulk operations"),
            
            # String concatenation in loop
            (r'for\s+.*:\s*\n\s*\w+\s*\+=\s*["\']',
             "String concatenation in loop",
             "Use join() or f-strings with a list"),
            
            # Global variable modification
            (r'global\s+\w+',
             "Global variable usage",
             "Avoid globals - use classes or dependency injection"),
            
            # Bare except
            (r'except\s*:',
             "Bare except clause",
             "Catch specific exceptions"),
            
            # len() in loop condition
            (r'while\s+len\(',
             "len() in while condition",
             "Cache the length or use a different approach"),
        ]
        
        for line_num, line in enumerate(lines, 1):
            for pattern, message, suggestion in patterns:
                if re.search(pattern, line):
                    issues.append(self._create_issue(
                        file_path=file_path,
                        line=line_num,
                        message=message,
                        suggestion=suggestion,
                        code_snippet=line.strip(),
                    ))
        
        return issues


class StyleRules(BaseRule):
    """Code style rules."""
    
    @property
    def name(self) -> str:
        return "style"
    
    @property
    def description(self) -> str:
        return "Code style and readability"
    
    @property
    def category(self) -> IssueCategory:
        return IssueCategory.STYLE
    
    @property
    def severity(self) -> Severity:
        return Severity.INFO
    
    def check(self, file_path: str, content: str) -> list[CodeIssue]:
        issues = []
        lines = content.splitlines()
        
        for line_num, line in enumerate(lines, 1):
            # Long lines
            if len(line) > 120:
                issues.append(self._create_issue(
                    file_path=file_path,
                    line=line_num,
                    message=f"Line too long ({len(line)} > 120 characters)",
                    suggestion="Break line into multiple lines",
                    severity=Severity.INFO,
                ))
            
            # Trailing whitespace
            if line != line.rstrip():
                issues.append(self._create_issue(
                    file_path=file_path,
                    line=line_num,
                    message="Trailing whitespace",
                    suggestion="Remove trailing whitespace",
                    severity=Severity.INFO,
                ))
            
            # TODO/FIXME comments
            if re.search(r'#\s*(?:TODO|FIXME|HACK|XXX)', line):
                issues.append(self._create_issue(
                    file_path=file_path,
                    line=line_num,
                    message="TODO/FIXME comment found",
                    suggestion="Address the TODO/FIXME or create an issue",
                    severity=Severity.INFO,
                ))
        
        return issues


class ComplexityRules(BaseRule):
    """Code complexity rules."""
    
    @property
    def name(self) -> str:
        return "complexity"
    
    @property
    def description(self) -> str:
        return "Code complexity detection"
    
    @property
    def category(self) -> IssueCategory:
        return IssueCategory.COMPLEXITY
    
    @property
    def severity(self) -> Severity:
        return Severity.WARNING
    
    def check(self, file_path: str, content: str) -> list[CodeIssue]:
        issues = []
        lines = content.splitlines()
        
        # Count nested depth
        max_depth = 0
        current_depth = 0
        
        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            
            # Count indentation (assuming 4 spaces)
            if stripped and not stripped.startswith('#'):
                depth = len(line) - len(line.lstrip())
                current_depth = depth // 4
                
                if current_depth > 4:
                    issues.append(self._create_issue(
                        file_path=file_path,
                        line=line_num,
                        message=f"Deeply nested code (depth: {current_depth})",
                        suggestion="Consider refactoring into smaller functions",
                    ))
        
        # Count function length
        in_function = False
        func_start = 0
        func_name = ""
        
        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            
            if re.match(r'(?:async\s+)?def\s+(\w+)', stripped):
                if in_function and (line_num - func_start) > 50:
                    issues.append(self._create_issue(
                        file_path=file_path,
                        line=func_start,
                        message=f"Function '{func_name}' is too long ({line_num - func_start} lines)",
                        suggestion="Break into smaller functions (max 50 lines)",
                    ))
                in_function = True
                func_start = line_num
                match = re.match(r'(?:async\s+)?def\s+(\w+)', stripped)
                func_name = match.group(1) if match else "unknown"
        
        return issues


# Default rules
DEFAULT_RULES = [
    SecurityRules(),
    PerformanceRules(),
    StyleRules(),
    ComplexityRules(),
]
