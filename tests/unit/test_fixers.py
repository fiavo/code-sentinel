"""
Tests for auto-fixer.
"""

import pytest
from code_reviewer.fixers.auto_fix import AutoFixer, DiffGenerator
from code_reviewer.core.models import CodeIssue, Severity, IssueCategory


class TestAutoFixer:
    def setup_method(self):
        self.fixer = AutoFixer()
    
    def test_fix_trailing_whitespace(self):
        code = "x = 1   "
        issues = [
            CodeIssue(
                file="test.py",
                line=1,
                severity=Severity.INFO,
                category=IssueCategory.STYLE,
                message="Trailing whitespace",
                rule="style",
            )
        ]
        
        fixed = self.fixer.fix(code, issues)
        assert fixed == "x = 1"
    
    def test_fix_bare_except(self):
        code = """
try:
    pass
except:
    pass
"""
        issues = [
            CodeIssue(
                file="test.py",
                line=3,
                severity=Severity.WARNING,
                category=IssueCategory.PERFORMANCE,
                message="Bare except clause",
                rule="performance",
            )
        ]
        
        fixed = self.fixer.fix(code, issues)
        assert "except Exception:" in fixed
    
    def test_fix_no_changes_needed(self):
        code = "x = 1"
        issues = []
        
        fixed = self.fixer.fix(code, issues)
        assert fixed == code
    
    def test_fix_multiple_issues(self):
        code = "x = 1   \ny = 2   "
        issues = [
            CodeIssue(
                file="test.py",
                line=1,
                severity=Severity.INFO,
                category=IssueCategory.STYLE,
                message="Trailing whitespace",
                rule="style",
            ),
            CodeIssue(
                file="test.py",
                line=2,
                severity=Severity.INFO,
                category=IssueCategory.STYLE,
                message="Trailing whitespace",
                rule="style",
            ),
        ]
        
        fixed = self.fixer.fix(code, issues)
        assert fixed == "x = 1\ny = 2"


class TestDiffGenerator:
    def test_generate_diff(self):
        original = "line1\nline2\nline3"
        fixed = "line1\nmodified\nline3"
        
        diff = DiffGenerator.generate_diff(original, fixed, "test.py")
        
        assert "---" in diff
        assert "+++" in diff
        assert "-line2" in diff
        assert "+modified" in diff
    
    def test_generate_diff_no_changes(self):
        code = "same content"
        diff = DiffGenerator.generate_diff(code, code)
        
        assert diff == ""
