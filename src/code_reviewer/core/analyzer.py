"""
Code analyzer - main analysis engine.
"""

import os
from pathlib import Path
from typing import Optional
from dataclasses import dataclass

from ..core.models import ReviewResult, FileAnalysis, Severity
from ..core.rules import BaseRule, DEFAULT_RULES


# Language detection by extension
EXTENSION_MAP = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "typescript",
    ".jsx": "javascript",
    ".tsx": "typescript",
    ".java": "java",
    ".go": "go",
    ".rs": "rust",
    ".cpp": "cpp",
    ".c": "c",
    ".cs": "csharp",
    ".rb": "ruby",
    ".php": "php",
    ".swift": "swift",
    ".kt": "kotlin",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".json": "json",
    ".toml": "toml",
    ".md": "markdown",
    ".sql": "sql",
    ".sh": "bash",
    ".bash": "bash",
}

# Files to skip
SKIP_PATTERNS = {
    "__pycache__",
    ".git",
    ".venv",
    "venv",
    "node_modules",
    ".mypy_cache",
    ".pytest_cache",
    "*.pyc",
    "*.pyo",
    "*.so",
    "*.dll",
    "*.exe",
    "*.o",
    "*.a",
    "*.dylib",
}


@dataclass
class AnalyzerConfig:
    """Configuration for the code analyzer."""
    rules: list[BaseRule] | None = None
    max_line_length: int = 120
    max_function_length: int = 50
    max_file_size: int = 1_000_000  # 1MB
    exclude_patterns: set[str] | None = None
    include_tests: bool = True
    
    def __post_init__(self):
        if self.rules is None:
            self.rules = DEFAULT_RULES.copy()
        if self.exclude_patterns is None:
            self.exclude_patterns = SKIP_PATTERNS.copy()


class CodeAnalyzer:
    """
    Main code analyzer.
    
    Analyzes code for quality issues using built-in and custom rules.
    
    Example:
        analyzer = CodeAnalyzer()
        result = analyzer.analyze_path("/path/to/project")
        print(f"Score: {result.score}")
    """
    
    def __init__(self, config: Optional[AnalyzerConfig] = None):
        self.config = config or AnalyzerConfig()
        self._rules = self.config.rules or DEFAULT_RULES.copy()
    
    def add_rule(self, rule: BaseRule):
        """Add a custom rule."""
        self._rules.append(rule)
    
    def remove_rule(self, name: str):
        """Remove a rule by name."""
        self._rules = [r for r in self._rules if r.name != name]
    
    def analyze_path(self, path: str) -> ReviewResult:
        """
        Analyze a file or directory.
        
        Args:
            path: Path to file or directory
            
        Returns:
            ReviewResult with all issues found
        """
        path = Path(path)
        
        if path.is_file():
            return self._analyze_file(path)
        
        if path.is_dir():
            return self._analyze_directory(path)
        
        raise ValueError(f"Path does not exist: {path}")
    
    def analyze_code(self, code: str, language: str = "python", file_path: str = "<string>") -> ReviewResult:
        """
        Analyze code string directly.
        
        Args:
            code: Code to analyze
            language: Programming language
            file_path: Virtual file path for reporting
            
        Returns:
            ReviewResult
        """
        issues = []
        
        for rule in self._rules:
            try:
                rule_issues = rule.check(file_path, code)
                issues.extend(rule_issues)
            except Exception as e:
                # Don't let rule errors break analysis
                continue
        
        score = self._calculate_score(issues)
        lines = code.splitlines()
        
        return ReviewResult(
            issues=issues,
            score=score,
            summary=self._generate_summary(issues),
            files_analyzed=1,
            lines_analyzed=len(lines),
            language=language,
        )
    
    def _analyze_file(self, file_path: Path) -> ReviewResult:
        """Analyze a single file."""
        # Skip if file is too large
        if file_path.stat().st_size > self.config.max_file_size:
            return ReviewResult(
                score=100,
                summary=f"Skipped: file too large ({file_path.stat().st_size} bytes)",
            )
        
        # Skip test files if configured
        if not self.config.include_tests and "test" in file_path.name.lower():
            return ReviewResult(score=100, summary="Skipped: test file")
        
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return ReviewResult(score=100, summary="Could not read file")
        
        # Detect language
        language = EXTENSION_MAP.get(file_path.suffix.lower(), "unknown")
        
        # Skip non-code files
        if language in ("markdown", "json", "yaml", "toml"):
            return ReviewResult(
                score=100,
                summary=f"Skipped: {language} file",
                language=language,
            )
        
        issues = []
        for rule in self._rules:
            try:
                rule_issues = rule.check(str(file_path), content)
                issues.extend(rule_issues)
            except Exception:
                continue
        
        score = self._calculate_score(issues)
        lines = content.splitlines()
        
        return ReviewResult(
            issues=issues,
            score=score,
            summary=self._generate_summary(issues),
            files_analyzed=1,
            lines_analyzed=len(lines),
            language=language,
        )
    
    def _analyze_directory(self, dir_path: Path) -> ReviewResult:
        """Analyze all files in a directory."""
        all_issues = []
        files_analyzed = 0
        lines_analyzed = 0
        languages = {}
        
        for root, dirs, files in os.walk(dir_path):
            # Skip excluded directories
            dirs[:] = [
                d for d in dirs
                if not any(p in d for p in self.config.exclude_patterns)
            ]
            
            for file in files:
                # Skip excluded files
                if any(p in file for p in self.config.exclude_patterns):
                    continue
                
                file_path = Path(root) / file
                
                # Skip non-code files
                if file_path.suffix.lower() not in EXTENSION_MAP:
                    continue
                
                # Skip test files if configured
                if not self.config.include_tests and "test" in file_path.name.lower():
                    continue
                
                try:
                    result = self._analyze_file(file_path)
                    all_issues.extend(result.issues)
                    files_analyzed += 1
                    lines_analyzed += result.lines_analyzed
                    
                    # Track languages
                    lang = result.language
                    if lang != "unknown":
                        languages[lang] = languages.get(lang, 0) + 1
                except Exception:
                    continue
        
        # Determine primary language
        primary_language = max(languages.items(), key=lambda x: x[1])[0] if languages else "unknown"
        
        score = self._calculate_score(all_issues)
        
        return ReviewResult(
            issues=all_issues,
            score=score,
            summary=self._generate_summary(all_issues),
            files_analyzed=files_analyzed,
            lines_analyzed=lines_analyzed,
            language=primary_language,
        )
    
    def _calculate_score(self, issues: list) -> float:
        """Calculate quality score from issues."""
        if not issues:
            return 100.0
        
        score = 100.0
        
        for issue in issues:
            if issue.severity == Severity.CRITICAL:
                score -= 15
            elif issue.severity == Severity.ERROR:
                score -= 10
            elif issue.severity == Severity.WARNING:
                score -= 5
            elif issue.severity == Severity.INFO:
                score -= 1
        
        return max(0.0, score)
    
    def _generate_summary(self, issues: list) -> str:
        """Generate a summary of issues."""
        if not issues:
            return "No issues found! Code looks good. ✅"
        
        critical = len([i for i in issues if i.severity == Severity.CRITICAL])
        errors = len([i for i in issues if i.severity == Severity.ERROR])
        warnings = len([i for i in issues if i.severity == Severity.WARNING])
        info = len([i for i in issues if i.severity == Severity.INFO])
        
        parts = []
        if critical:
            parts.append(f"{critical} critical")
        if errors:
            parts.append(f"{errors} errors")
        if warnings:
            parts.append(f"{warnings} warnings")
        if info:
            parts.append(f"{info} info")
        
        return f"Found {', '.join(parts)} issues"
