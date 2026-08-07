"""
Comprehensive testing patterns for all languages and frameworks.
"""
import re
from ..core.models import CodeIssue, Severity, IssueCategory
from ..core.rules import BaseRule


class TestingComprehensiveRules(BaseRule):
    @property
    def name(self) -> str:
        return "testing_comprehensive"
    @property
    def description(self) -> str:
        return "Comprehensive testing patterns"
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
            (r"jest|mocha|jasmine|vitest|karma|ava|tape|uvu", "JS test framework", "Good: using test framework", Severity.INFO),
            (r"pytest|unittest|nose|tox|coverage", "Python test framework", "Good: using test framework", Severity.INFO),
            (r"junit|testng|mockito|hamcrest|assertj", "Java test framework", "Good: using test framework", Severity.INFO),
            (r"rspec|minitest|capybara|cucumber", "Ruby test framework", "Good: using test framework", Severity.INFO),
            (r"phpunit|codeception|behat|phpspec", "PHP test framework", "Good: using test framework", Severity.INFO),
            (r"xctest|quick|nimble", "Swift test framework", "Good: using test framework", Severity.INFO),
            (r"gtest|catch2|doctest|boost.test", "C++ test framework", "Good: using test framework", Severity.INFO),
            (r"testing|testify|gocheck", "Go test framework", "Good: using test framework", Severity.INFO),
            (r"criterion|proptest|quickcheck", "Rust test framework", "Good: using test framework", Severity.INFO),
            # Test types
            (r"unit\s+test|integration\s+test|e2e\s+test|end.?to.?end|functional|acceptance|smoke|regression|performance|load|stress", "Test type", "Good: categorizing tests", Severity.INFO),
            (r"describe|it|test|spec|context|feature|scenario", "Test structure", "Good: organizing tests", Severity.INFO),
            (r"before|after|beforeEach|afterEach|beforeAll|afterAll|setup|teardown|setUp|tearDown|setUpClass|tearDownClass", "Test lifecycle", "Good: managing test lifecycle", Severity.INFO),
            (r"mock|stub|fake|spy|double|mocking|stubbing", "Test doubles", "Good: using test doubles", Severity.INFO),
            (r"assert|expect|should|verify|check|validate|assertEquals|assertThat|assertEqual|assertTrue|assertFalse|assertNull|assertNotNull|assertSame|assertNotSame|assertThrows|assertDoesNotThrow|assertThat|assertThat", "Assertions", "Good: writing assertions", Severity.INFO),
            (r"fixture|factory|builder|generator", "Test data", "Good: generating test data", Severity.INFO),
            (r"snapshot|visual|screenshot|regression", "Snapshot testing", "Good: using snapshot testing", Severity.INFO),
            (r"property.?based|generative|fuzz|random|proptest|quickcheck", "Property-based testing", "Good: using property-based testing", Severity.INFO),
            (r"contract|api|schema|consumer", "Contract testing", "Good: using contract testing", Severity.INFO),
            (r"mutation|mutation.?testing|pitest|Stryker", "Mutation testing", "Good: using mutation testing", Severity.INFO),
            (r"coverage|codecov|coveralls|istanbul|nyc|lcov|jacoco", "Test coverage", "Good: tracking test coverage", Severity.INFO),
            (r"ci|cd|pipeline|continuous|automation", "Test automation", "Good: automating tests", Severity.INFO),
            (r"parallel|concurrent|distributed", "Parallel testing", "Good: running tests in parallel", Severity.INFO),
            (r"flaky|intermittent|unstable", "Flaky tests", "Fix flaky tests", Severity.WARNING),
            (r"skip|ignore|pending|todo|xtest|xit|xdescribe", "Skipped tests", "Ensure tests are not permanently skipped", Severity.INFO),
            (r"timeout|slow|performance|benchmark", "Test performance", "Optimize slow tests", Severity.INFO),
            (r"data.?driven|parameterized|table", "Data-driven testing", "Good: using data-driven testing", Severity.INFO),
            (r"helper|utility|common|shared", "Test utilities", "Good: sharing test utilities", Severity.INFO),
            (r"cleanup|isolation|independent", "Test isolation", "Good: isolating tests", Severity.INFO),
            (r"arrange|act|assert|given|when|then|AAA|Given.?When.?Then", "Test structure", "Good: following AAA/Given-When-Then", Severity.INFO),
            # Test annotations
            (r"@test|@spec|@mock|@patch|@fixture|@Before|@After|@BeforeAll|@AfterAll|@BeforeEach|@AfterEach", "Test annotation", "Good: using test annotations", Severity.INFO),
            (r"@pytest\.mark|@pytest\.fixture|@pytest\.param|@pytest\.raises|@pytest\.warns|@pytest\.approx|@pytest\.skip|@pytest\.xfail", "pytest marker", "Good: using pytest markers", Severity.INFO),
            (r"@Test|@Before|@After|@BeforeClass|@AfterClass|@BeforeMethod|@AfterMethod|@BeforeSuite|@AfterSuite|@BeforeTest|@AfterTest", "JUnit annotation", "Good: using JUnit annotations", Severity.INFO),
            (r"#\[test\]|#\[cfg\(test\)\]|#\[should_panic\]|#\[bench\]", "Rust test attribute", "Good: using Rust test attributes", Severity.INFO),
            (r"t\.Run\(|t\.Helper\(\)|t\.Parallel\(\)|testing\.Short\(\)", "Go test function", "Good: using Go test functions", Severity.INFO),
            (r"func\s+Test|func\s+Example|func\s+Benchmark", "Go test function", "Good: writing Go tests", Severity.INFO),
            # Test assertions
            (r"assert\.Equal|assert\.NotEqual|assert\.True|assert\.False|assert\.Nil|assert\.NotNil|assert\.Contains|assert\.NotContains|assert\.Len|assert\.Empty|assert\.NotEmpty|assert\.Error|assert\.NoError|assert\.NilError|assert\.NotNilError|assert\.EqualError|assert\.ContainsError|assert\.Panics|assert\.NotPanics|assert\.WithinDuration|assert\.InDelta|assert\.JSONEq|assert\.ElementsMatch|assert\.IsType|assert\.Implements", "Go assert", "Good: using Go assertions", Severity.INFO),
            (r"assert\.\w+|expect\.\w+|should\.\w+|verify\.\w+|check\.\w+|validate\.\w+", "Assertion call", "Good: using assertions", Severity.INFO),
            # Test mocking
            (r"mock\.Mock|mock\.patch|mock\.call|mock\.ANY|mock\.MagicMock|mock\.PropertyMock", "Python mock", "Good: using Python mock", Severity.INFO),
            (r"jest\.mock|jest\.fn|jest\.spyOn|jest\.requireActual|jest\.requireMock", "Jest mock", "Good: using Jest mock", Severity.INFO),
            (r"sinon\.stub|sinon\.spy|sinon\.mock|sinon\.fake|sinon\.replace|sinon\.restore", "Sinon mock", "Good: using Sinon mock", Severity.INFO),
            (r"mockito|when|verify|never|any|eq|argThat|times|atLeast|atMost|timeout|spy|doReturn|doThrow|doNothing|doCallRealMethod", "Mockito mock", "Good: using Mockito mock", Severity.INFO),
            # Test coverage
            (r"coverage\.report|coverage\.start|coverage\.stop|coverage\.combine|coverage\.erase|coverage\.html|coverage\.xml|coverage\.lcov|coverage\.json", "Coverage report", "Good: generating coverage", Severity.INFO),
            (r"codecov|coveralls|sonarqube|sonarcloud", "Coverage service", "Good: using coverage services", Severity.INFO),
            # Test reporting
            (r"junit\.xml|surefire|failsafe|allure|extent|reportportal", "Test report", "Good: test reporting", Severity.INFO),
            # Test runners
            (r"jest|vitest|mocha|karma|ava|tape|uvu|jasmine", "JS test runner", "Good: using test runners", Severity.INFO),
            (r"pytest|nose|tox|unittest", "Python test runner", "Good: using test runners", Severity.INFO),
            (r"junit|testng|surefire|failsafe", "Java test runner", "Good: using test runners", Severity.INFO),
            # Test data
            (r"faker|factory|builder|fixture|seed|generator|factory_boy|model_bakery", "Test data generator", "Good: generating test data", Severity.INFO),
            # BDD
            (r"Given|When|Then|And|But|Scenario|Feature|Background|Scenario Outline|Examples", "BDD syntax", "Good: using BDD", Severity.INFO),
            (r"cucumber|gherkin|specflow|cypress|playwright", "BDD framework", "Good: using BDD frameworks", Severity.INFO),
            # Integration testing
            (r"docker|testcontainers|wiremock|mockserver|localstack|minio|fakeredis|mongomock", "Integration test tool", "Good: integration test tools", Severity.INFO),
            # E2E testing
            (r"selenium|cypress|playwright|puppeteer|webdriver|appium|detox|maestro", "E2E framework", "Good: E2E testing", Severity.INFO),
            # Performance testing
            (r"k6|artillery|jmeter|locust|wrk|ab|hey|vegeta|ghz|bombardier|fortio", "Performance testing tool", "Good: performance testing", Severity.INFO),
            # Security testing
            (r"owasp|zap|burp|nikto|nmap|sqlmap|xsstrike|nuclei|semgrep|bandit|safety", "Security testing tool", "Good: security testing", Severity.INFO),
            # Chaos testing
            (r"chaos|litmus|chaos.?monkey|chaos.?mesh|gremlin|toxiproxy|pumba", "Chaos testing", "Good: chaos testing", Severity.INFO),
            # Contract testing
            (r"pact|pactum|contract|schema.?validation|openapi|swagger", "Contract testing", "Good: contract testing", Severity.INFO),
            # Visual testing
            (r"percy|chromatic|applitools|backstop|reg-suit|storybook", "Visual testing", "Good: visual testing", Severity.INFO),
            # Snapshot testing
            (r"snapshot|toMatch|toMatchSnapshot|toMatchInlineSnapshot|snap|snapUpdate", "Snapshot testing", "Good: snapshot testing", Severity.INFO),
            # Accessibility testing
            (r"axe|pa11y|lighthouse|jest-axe|cypress-axe|axe-core", "Accessibility testing", "Good: accessibility testing", Severity.INFO),
            # Mobile testing
            (r"appium|detox|maestro|espresso|xctest|uiautomator|calabash|airtest", "Mobile testing", "Good: mobile testing", Severity.INFO),
            # API testing
            (r"postman|insomnia|hoppscotch|bruno|httpie|rest.?client|curl|requests", "API testing tool", "Good: API testing", Severity.INFO),
            # Database testing
            (r"testcontainers|flyway|liquibase|dbmate|migrate", "Database testing", "Good: database testing", Severity.INFO),
            # Load testing
            (r"k6|artillery|jmeter|locust|wrk|ab|hey|vegeta|ghz|bombardier|fortio", "Load testing tool", "Good: load testing", Severity.INFO),
            # Security scanning
            (r"semgrep|bandit|safety|snyk|dependabot|renovate|npm.?audit|pip.?audit|cargo.?audit", "Security scanning", "Good: security scanning", Severity.INFO),
            # Code quality
            (r"eslint|prettier|black|ruff|mypy|pylint|flake8|rubocop|golangci-lint|clippy|shellcheck|hadolint", "Code quality tool", "Good: code quality tools", Severity.INFO),
            # Documentation testing
            (r"doctest|rsdoc|godoc|javadoc|sphinx|mkdocs|docusaurus|vuepress|nextra", "Documentation testing", "Good: documentation testing", Severity.INFO),
            # Mutation testing
            (r"pitest|stryker|mutmut|cosmic-ray|mull|grepmut", "Mutation testing tool", "Good: mutation testing", Severity.INFO),
            # Property-based testing
            (r"hypothesis|quickcheck|proptest|fast-check|test.check|rapidcheck|prop-test", "Property-based testing tool", "Good: property-based testing", Severity.INFO),
            # Fuzzing
            (r"libfuzzer|afl| Honggfuzz|go-fuzz|cargo-fuzz|jazzer|Atheris|Hypothesis", "Fuzzing tool", "Good: fuzzing", Severity.INFO),
            # Benchmarking
            (r"benchmark|criterion|benchmark.js|pytest-benchmark|go test -bench", "Benchmarking tool", "Good: benchmarking", Severity.INFO),
            # Test management
            (r"testrail|zephyr|xray|qase|testmo|kaneo", "Test management", "Good: test management", Severity.INFO),
            # Test environments
            (r"docker|testcontainers|localstack|minio|fakeredis|mongomock|sqlite", "Test environment", "Good: test environment", Severity.INFO),
            # Test data management
            (r"faker|factory_boy|model_bakery|freezegun|time_machine|responses|vcr|betamax", "Test data management", "Good: test data management", Severity.INFO),
        ]
        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith('#') or stripped.startswith('//'):
                continue
            for pattern, message, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    issues.append(self._create_issue(
                        file_path=file_path, line=line_num, message=message,
                        suggestion=message, severity=severity, code_snippet=stripped,
                    ))
        return issues
