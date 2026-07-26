"""
Tests for code review rules.
"""

import pytest
from code_reviewer.core.rules import (
    SecurityRules,
    PerformanceRules,
    StyleRules,
    ComplexityRules,
    DEFAULT_RULES,
)
from code_reviewer.core.models import Severity, IssueCategory


class TestSecurityRules:
    def setup_method(self):
        self.rule = SecurityRules()
    
    def test_rule_properties(self):
        assert self.rule.name == "security"
        assert self.rule.category == IssueCategory.SECURITY
        assert self.rule.severity == Severity.CRITICAL
    
    def test_detect_hardcoded_secret(self):
        code = 'api_key = "sk-1234567890"'
        issues = self.rule.check("test.py", code)
        assert len(issues) > 0
        assert any("secret" in i.message.lower() for i in issues)
    
    def test_detect_eval(self):
        code = "result = eval(user_input)"
        issues = self.rule.check("test.py", code)
        assert len(issues) > 0
        assert any("eval" in i.message for i in issues)
    
    def test_detect_exec(self):
        code = "exec(code_string)"
        issues = self.rule.check("test.py", code)
        assert len(issues) > 0
    
    def test_detect_shell_true(self):
        code = "subprocess.run(cmd, shell=True)"
        issues = self.rule.check("test.py", code)
        assert len(issues) > 0
    
    def test_detect_weak_hash(self):
        code = "hash = md5(data)"
        issues = self.rule.check("test.py", code)
        assert len(issues) > 0
    
    def test_no_issues_clean_code(self):
        code = """
def process_data(data):
    return [x * 2 for x in data]
"""
        issues = self.rule.check("test.py", code)
        assert len(issues) == 0


class TestPerformanceRules:
    def setup_method(self):
        self.rule = PerformanceRules()
    
    def test_rule_properties(self):
        assert self.rule.name == "performance"
        assert self.rule.category == IssueCategory.PERFORMANCE
    
    def test_detect_bare_except(self):
        code = """
try:
    pass
except:
    pass
"""
        issues = self.rule.check("test.py", code)
        assert len(issues) > 0
    
    def test_detect_global_usage(self):
        code = """
def modify():
    global x
    x = 10
"""
        issues = self.rule.check("test.py", code)
        assert len(issues) > 0


class TestStyleRules:
    def setup_method(self):
        self.rule = StyleRules()
    
    def test_rule_properties(self):
        assert self.rule.name == "style"
        assert self.rule.category == IssueCategory.STYLE
    
    def test_detect_long_line(self):
        code = 'x = "a" * 200'
        issues = self.rule.check("test.py", code)
        assert len(issues) > 0
    
    def test_detect_todo(self):
        code = "# TODO: Fix this later"
        issues = self.rule.check("test.py", code)
        assert len(issues) > 0
    
    def test_detect_trailing_whitespace(self):
        code = "x = 1   "
        issues = self.rule.check("test.py", code)
        assert len(issues) > 0


class TestComplexityRules:
    def setup_method(self):
        self.rule = ComplexityRules()
    
    def test_rule_properties(self):
        assert self.rule.name == "complexity"
        assert self.rule.category == IssueCategory.COMPLEXITY


class TestDefaultRules:
    def test_default_rules_count(self):
        assert len(DEFAULT_RULES) == 4
    
    def test_all_rules_implement_interface(self):
        for rule in DEFAULT_RULES:
            assert hasattr(rule, "name")
            assert hasattr(rule, "description")
            assert hasattr(rule, "category")
            assert hasattr(rule, "severity")
            assert hasattr(rule, "check")
