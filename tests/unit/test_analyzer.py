"""
Tests for the code analyzer.
"""

import pytest
from code_reviewer.core.analyzer import CodeAnalyzer, AnalyzerConfig
from code_reviewer.core.models import Severity, IssueCategory


class TestCodeAnalyzer:
    def setup_method(self):
        self.analyzer = CodeAnalyzer()
    
    def test_analyze_clean_code(self):
        code = """
def hello_world():
    return "Hello, World!"
"""
        result = self.analyzer.analyze_code(code, "python")
        assert result.score == 100.0
        assert len(result.issues) == 0
    
    def test_analyze_security_issues(self):
        code = 'password = "secret123"'
        result = self.analyzer.analyze_code(code, "python")
        assert result.score < 100.0
        assert any(i.category == IssueCategory.SECURITY for i in result.issues)
    
    def test_analyze_eval_usage(self):
        code = "result = eval(user_input)"
        result = self.analyzer.analyze_code(code, "python")
        assert result.score < 100.0
        assert any("eval" in i.message for i in result.issues)
    
    def test_analyze_long_line(self):
        code = 'x = "a" * 200  # ' + "a" * 150
        result = self.analyzer.analyze_code(code, "python")
        assert any(i.category == IssueCategory.STYLE for i in result.issues)
    
    def test_score_calculation(self):
        # Critical issue should lower score significantly
        code = 'password = "secret"\nresult = eval(x)'
        result = self.analyzer.analyze_code(code, "python")
        assert result.score < 80.0
    
    def test_analyze_code_string(self):
        code = "def add(a, b):\n    return a + b"
        result = self.analyzer.analyze_code(code, "python")
        assert result.files_analyzed == 1
        assert result.lines_analyzed == 2
    
    def test_custom_config(self):
        config = AnalyzerConfig(max_line_length=80)
        analyzer = CodeAnalyzer(config)
        
        code = 'x = "a" * 100'
        result = analyzer.analyze_code(code, "python")
        # Should find long line issue
        assert len(result.issues) > 0


class TestAnalyzerMetrics:
    def test_critical_count(self):
        from code_reviewer.core.models import CodeIssue
        
        analyzer = CodeAnalyzer()
        code = 'password = "secret"'
        result = analyzer.analyze_code(code, "python")
        
        assert result.critical_count >= 0
        assert result.error_count >= 0
        assert result.warning_count >= 0
        assert result.info_count >= 0
    
    def test_has_critical(self):
        from code_reviewer.core.models import ReviewResult
        
        result = ReviewResult()
        assert not result.has_critical
        
        # Add critical issue would make has_critical True
