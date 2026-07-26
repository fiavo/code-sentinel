"""
Data models for code review results.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
from pathlib import Path


class Severity(str, Enum):
    """Issue severity levels."""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class IssueCategory(str, Enum):
    """Issue categories."""
    SECURITY = "security"
    PERFORMANCE = "performance"
    STYLE = "style"
    BUG = "bug"
    MAINTAINABILITY = "maintainability"
    BEST_PRACTICE = "best_practice"
    COMPLEXITY = "complexity"


@dataclass
class CodeIssue:
    """
    Represents a single code issue.
    
    Attributes:
        file: File path
        line: Line number (1-indexed)
        column: Column number (1-indexed)
        severity: Issue severity
        category: Issue category
        message: Human-readable message
        rule: Rule that triggered this issue
        suggestion: Suggested fix
        code_snippet: Relevant code snippet
    """
    file: str
    line: int
    column: int = 0
    severity: Severity = Severity.WARNING
    category: IssueCategory = IssueCategory.BEST_PRACTICE
    message: str = ""
    rule: str = ""
    suggestion: str = ""
    code_snippet: str = ""


@dataclass
class ReviewResult:
    """
    Complete code review result.
    
    Attributes:
        issues: List of issues found
        score: Overall quality score (0-100)
        summary: Summary of findings
        files_analyzed: Number of files analyzed
        lines_analyzed: Number of lines analyzed
        language: Primary language detected
        ai_analysis: AI-generated analysis
    """
    issues: list[CodeIssue] = field(default_factory=list)
    score: float = 100.0
    summary: str = ""
    files_analyzed: int = 0
    lines_analyzed: int = 0
    language: str = "unknown"
    ai_analysis: Optional[str] = None
    
    @property
    def critical_count(self) -> int:
        """Number of critical issues."""
        return len([i for i in self.issues if i.severity == Severity.CRITICAL])
    
    @property
    def error_count(self) -> int:
        """Number of error issues."""
        return len([i for i in self.issues if i.severity == Severity.ERROR])
    
    @property
    def warning_count(self) -> int:
        """Number of warning issues."""
        return len([i for i in self.issues if i.severity == Severity.WARNING])
    
    @property
    def info_count(self) -> int:
        """Number of info issues."""
        return len([i for i in self.issues if i.severity == Severity.INFO])
    
    @property
    def has_critical(self) -> bool:
        """Check if there are critical issues."""
        return self.critical_count > 0
    
    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "score": self.score,
            "summary": self.summary,
            "files_analyzed": self.files_analyzed,
            "lines_analyzed": self.lines_analyzed,
            "language": self.language,
            "issues": [
                {
                    "file": i.file,
                    "line": i.line,
                    "column": i.column,
                    "severity": i.severity.value,
                    "category": i.category.value,
                    "message": i.message,
                    "rule": i.rule,
                    "suggestion": i.suggestion,
                }
                for i in self.issues
            ],
            "ai_analysis": self.ai_analysis,
        }


@dataclass
class FileAnalysis:
    """
    Analysis result for a single file.
    
    Attributes:
        path: File path
        content: File content
        language: Detected language
        issues: Issues found in this file
        metrics: Code metrics (lines, complexity, etc.)
    """
    path: str
    content: str
    language: str = "unknown"
    issues: list[CodeIssue] = field(default_factory=list)
    metrics: dict = field(default_factory=dict)
    
    @property
    def line_count(self) -> int:
        """Number of lines in file."""
        return len(self.content.splitlines())
    
    @property
    def issue_count(self) -> int:
        """Number of issues found."""
        return len(self.issues)
