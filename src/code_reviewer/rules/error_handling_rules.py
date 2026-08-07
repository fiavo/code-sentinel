"""
Comprehensive error handling rules for code analysis.
Covers exception handling, error patterns, and recovery strategies.
"""

import re
from typing import Optional

from ..core.models import CodeIssue, Severity, IssueCategory
from ..core.rules import BaseRule


class ExceptionHandlingRules(BaseRule):
    """Exception handling pattern detection."""

    @property
    def name(self) -> str:
        return "exception_handling"

    @property
    def description(self) -> str:
        return "Exception handling pattern detection"

    @property
    def category(self) -> IssueCategory:
        return IssueCategory.BUG

    @property
    def severity(self) -> Severity:
        return Severity.WARNING

    def check(self, file_path: str, content: str) -> list[CodeIssue]:
        issues = []
        lines = content.splitlines()

        patterns = [
            # Bare except/catch
            (r'except\s*:', "Bare except clause",
             "Catch specific exceptions", Severity.WARNING),
            (r'except\s+Exception\s*:', "Catching broad Exception",
             "Catch more specific exceptions when possible", Severity.INFO),
            (r'catch\s*\(\s*\)', "Bare catch clause (JS)",
             "Catch specific error types", Severity.WARNING),
            (r'catch\s*\(\s*e\s*\)\s*\{\s*\}', "Empty catch block",
             "Handle errors appropriately", Severity.WARNING),
            (r'except\s*:\s*pass', "Silently swallowing exceptions",
             "Log or re-raise the exception", Severity.WARNING),
            (r'catch\s*\([^)]*\)\s*\{\s*\}', "Empty catch block (JS)",
             "Handle errors appropriately", Severity.WARNING),

            # Exception type issues
            (r'except\s+BaseException\s*:', "Catching BaseException",
             "Catch Exception instead; BaseException includes SystemExit", Severity.WARNING),
            (r'except\s+SystemExit\s*:', "Catching SystemExit",
             "Avoid catching SystemExit unless absolutely necessary", Severity.WARNING),
            (r'except\s+KeyboardInterrupt\s*:', "Catching KeyboardInterrupt",
             "Avoid catching KeyboardInterrupt unless absolutely necessary", Severity.INFO),

            # Wrong exception usage
            (r'raise\s+Exception\s*\(', "Raising generic Exception",
             "Raise a more specific exception type", Severity.INFO),
            (r'raise\s+BaseException\s*\(', "Raising BaseException",
             "Raise Exception or a subclass instead", Severity.WARNING),
            (r'throw\s+new\s+Error\s*\(', "Throwing generic Error (JS)",
             "Throw a more specific error type", Severity.INFO),
            (r'throw\s+["\']', "Throwing string (JS)",
             "Throw Error objects instead of strings", Severity.WARNING),

            # Missing finally/cleanup
            (r'except\s+\w+.*:\s*\n(?:\s+.*\n)*?\s*(?:raise|return)', "Exception caught but re-raised",
             "Consider using finally for cleanup instead", Severity.INFO),
            (r'(?:open|read|write)\s*\([^)]*\).*\n(?:(?!with|using|try))', "Resource opened without context manager",
             "Use 'with' statement for automatic cleanup", Severity.WARNING),

            # Return in finally
            (r'finally\s*:\s*\n\s*return', "Return in finally block",
             "Avoid return in finally; it suppresses exceptions", Severity.WARNING),

            # Swallowed errors
            (r'except\s+\w+.*:\s*\n\s*(?:pass|continue)', "Exception swallowed",
             "Log the exception or handle it properly", Severity.WARNING),
            (r'catch\s*\([^)]*\)\s*\{\s*(?:pass|continue)', "Exception swallowed (JS)",
             "Log the error or handle it properly", Severity.WARNING),

            # Nested try blocks
            (r'try\s*:\s*\n(?:\s+.*\n)*?\s+try\s*:', "Nested try blocks",
             "Consider refactoring to reduce nesting", Severity.INFO),

            # Missing error context
            (r'raise\s+\w+\s*\(\s*\)', "Exception raised without message",
             "Add descriptive error message", Severity.INFO),
            (r'throw\s+new\s+\w+\s*\(\s*\)', "Error thrown without message (JS)",
             "Add descriptive error message", Severity.INFO),

            # Assert in production
            (r'^assert\s+', "Assert statement in code",
             "Asserts are removed in optimized mode; use proper validation", Severity.WARNING),

            # sys.exit in library
            (r'sys\.exit\s*\(', "sys.exit() in code",
             "Avoid sys.exit() in libraries; raise SystemExit instead", Severity.INFO),
            (r'exit\s*\(', "exit() in code",
             "Avoid exit() in code; use proper error handling", Severity.WARNING),
            (r'process\.exit\s*\(', "process.exit() in code",
             "Avoid process.exit(); throw proper errors", Severity.WARNING),
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


class ErrorPropagationRules(BaseRule):
    """Error propagation and context rules."""

    @property
    def name(self) -> str:
        return "error_propagation"

    @property
    def description(self) -> str:
        return "Error propagation pattern detection"

    @property
    def category(self) -> IssueCategory:
        return IssueCategory.BUG

    @property
    def severity(self) -> Severity:
        return Severity.WARNING

    def check(self, file_path: str, content: str) -> list[CodeIssue]:
        issues = []
        lines = content.splitlines()

        patterns = [
            # Missing error context
            (r'except\s+\w+.*:\s*\n\s*raise\s+\w+\s*\(\s*\)', "Exception re-raised without context",
             "Use 'raise ... from e' to preserve context", Severity.WARNING),
            (r'catch\s*\([^)]*\)\s*\{\s*throw\s+\w+\s*\(\s*\)', "Error re-thrown without context (JS)",
             "Use 'throw new Error(message, {cause: err})'", Severity.INFO),

            # Lost error info
            (r'except\s+\w+\s+as\s+\w+.*:\s*\n.*str\s*\(\s*\w+\s*\)', "Converting exception to string",
             "Pass the exception object directly to logging", Severity.INFO),

            # Wrong exception type in except
            (r'except\s+\w+Error\s*\(\s*\)', "Catching exception without using it",
             "Consider if you need to handle the exception", Severity.INFO),

            # Generic error messages
            (r'(?:raise|throw)\s+\w+\s*\(\s*["\'](?:error|failed|something went wrong)["\']', "Generic error message",
             "Add specific error details", Severity.INFO),
            (r'console\.error\s*\(\s*["\'](?:error|failed|something went wrong)["\']', "Generic error message (JS)",
             "Add specific error details", Severity.INFO),
            (r'logging\.error\s*\(\s*["\'](?:error|failed|something went wrong)["\']', "Generic error message",
             "Add specific error details", Severity.INFO),

            # Missing logging
            (r'except\s+\w+.*:\s*\n\s*pass', "Exception caught without logging",
             "Log the exception for debugging", Severity.WARNING),
            (r'except\s+\w+.*:\s*\n\s*\w+\.append\s*\(', "Exception caught without logging",
             "Add logging for debugging", Severity.INFO),

            # Wrong return on error
            (r'return\s+None\s*$', "Returning None on error",
             "Consider raising an exception or returning a result type", Severity.INFO),
            (r'return\s+False\s*$', "Returning False on error",
             "Consider raising an exception for clearer error handling", Severity.INFO),
            (r'return\s+(-1|0)\s*$', "Returning magic number on error",
             "Consider raising an exception or using a result type", Severity.INFO),
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
