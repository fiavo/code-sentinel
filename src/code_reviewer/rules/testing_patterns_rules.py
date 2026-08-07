"""
Testing patterns for unit, integration, and end-to-end testing.
"""

import re
from typing import Optional

from ..core.models import CodeIssue, Severity, IssueCategory
from ..core.rules import BaseRule


class TestingPatternsRules(BaseRule):
    """Testing pattern detection."""

    @property
    def name(self) -> str:
        return "testing_patterns"

    @property
    def description(self) -> str:
        return "Testing pattern detection"

    @property
    def category(self) -> IssueCategory:
        return IssueCategory.BEST_PRACTICE

    @property
    def severity(self) -> Severity:
        return Severity.INFO

    def check(self, file_path: str, content: str) -> list[CodeIssue]:
        issues = []
        lines = content.splitlines()

        patterns = [
            # Test frameworks
            (r"(?:jest|mocha|jasmine|vitest|karma|ava|tape|uvu)", "JavaScript test framework", "Good: using test framework", Severity.INFO),
            (r"(?:pytest|unittest|nose|tox|coverage)", "Python test framework", "Good: using test framework", Severity.INFO),
            (r"(?:junit|testng|mockito|hamcrest|assertj)", "Java test framework", "Good: using test framework", Severity.INFO),
            (r"(?:rspec|minitest|capybara|cucumber|rspec)", "Ruby test framework", "Good: using test framework", Severity.INFO),
            (r"(?:phpunit|codeception|behat|phpspec)", "PHP test framework", "Good: using test framework", Severity.INFO),
            (r"(?:xctest|quick|nimble)", "Swift test framework", "Good: using test framework", Severity.INFO),
            (r"(?:junit|mockito|assertj|hamcrest|spring-test)", "Java test framework", "Good: using test framework", Severity.INFO),
            (r"(?:gtest|catch2|doctest|boost.test)", "C++ test framework", "Good: using test framework", Severity.INFO),
            (r"(?:testing|testify|gocheck)", "Go test framework", "Good: using test framework", Severity.INFO),

            # Test types
            (r"(?:unit|integration|e2e|end.?to.?end|functional|acceptance|smoke|regression|performance|load|stress)", "Test type", "Good: categorizing tests", Severity.INFO),
            (r"(?:describe|it|test|spec|context|feature|scenario)", "Test structure", "Good: organizing tests", Severity.INFO),
            (r"(?:before|after|beforeEach|afterEach|beforeAll|afterAll|setup|teardown)", "Test lifecycle", "Good: managing test lifecycle", Severity.INFO),
            (r"(?:mock|stub|fake|spy|double|mocking|stubbing)", "Test doubles", "Good: using test doubles", Severity.INFO),
            (r"(?:assert|expect|should|verify|check|validate)", "Assertions", "Good: writing assertions", Severity.INFO),
            (r"(?:fixture|factory|builder|generator)", "Test data", "Good: generating test data", Severity.INFO),
            (r"(?:snapshot|visual|screenshot|regression)", "Snapshot testing", "Good: using snapshot testing", Severity.INFO),
            (r"(?:property.?based|generative|fuzz|random)", "Property-based testing", "Good: using property-based testing", Severity.INFO),
            (r"(?:contract|api|schema|consumer)", "Contract testing", "Good: using contract testing", Severity.INFO),
            (r"(?:mutation|mutation.?testing)", "Mutation testing", "Good: using mutation testing", Severity.INFO),
            (r"(?:coverage|codecov|coveralls)", "Test coverage", "Good: tracking test coverage", Severity.INFO),
            (r"(?:ci|cd|pipeline|continuous|automation)", "Test automation", "Good: automating tests", Severity.INFO),
            (r"(?:parallel|concurrent|distributed)", "Parallel testing", "Good: running tests in parallel", Severity.INFO),
            (r"(?:flaky|intermittent|unstable)", "Flaky tests", "Fix flaky tests", Severity.WARNING),
            (r"(?:skip|ignore|pending|todo)", "Skipped tests", "Ensure tests are not permanently skipped", Severity.INFO),
            (r"(?:timeout|slow|performance|benchmark)", "Test performance", "Optimize slow tests", Severity.INFO),
            (r"(?:data.?driven|parameterized|table)", "Data-driven testing", "Good: using data-driven testing", Severity.INFO),
            (r"(?:helper|utility|common|shared)", "Test utilities", "Good: sharing test utilities", Severity.INFO),
            (r"(?:cleanup|isolation|independent)", "Test isolation", "Good: isolating tests", Severity.INFO),
            (r"(?:arrange|act|assert|given|when|then)", "Test structure", "Good: following AAA/Given-When-Then", Severity.INFO),
        ]

        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith('#') or stripped.startswith('//'):
                continue

            for pattern, message, suggestion, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    issues.append(self._create_issue(
                        file_path=file_path,
                        line=line_num,
                        message=message,
                        suggestion=suggestion,
                        severity=severity,
                        code_snippet=stripped,
                    ))

        return issues
