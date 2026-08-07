"""
Testing framework patterns for all languages.
"""
import re
from ..core.models import CodeIssue, Severity, IssueCategory
from ..core.rules import BaseRule


class TestingFrameworkRules(BaseRule):
    @property
    def name(self) -> str:
        return "testing_framework"
    @property
    def description(self) -> str:
        return "Testing framework patterns"
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
            # Python testing
            (r"import\s+pytest|from\s+pytest|@pytest\.|pytest\.fixture|pytest\.mark\.|pytest\.param|pytest\.raises|pytest\.warns|pytest\.skip|pytest\.xfail|pytest\.importorskip|pytest\.approx|pytest\.timeout|pytest\.httpserver|pytest-mock|pytest-cov|pytest-xdist|pytest-asyncio|pytest-django|pytest-flask|pytest-benchmark|pytest-httpx|pytest-socket|pytest-recording|pytest-subprocess|pytest-raises|pytest-randomly|pytest-repeat|pytest-rerunfailures|pytest-sugar|pytest-tldr|pytest-clarity|pytest-snapshot|pytest-regress|pytest-brief|pytest-cla", "pytest", "Good: pytest", Severity.INFO),
            (r"def\s+test_\w+|class\s+Test\w+|def\s+setup_method|def\s+teardown_method|def\s+setup_class|def\s+teardown_class|def\s+setup_module|def\s+teardown_module|def\s+setup_function|def\s+teardown_function|def\s+setup_fixture|def\s+teardown_fixture", "pytest test", "Good: pytest test", Severity.INFO),
            (r"assert\s+|assertEqual|assertTrue|assertFalse|assertIn|assertNotIn|assertIsNone|assertIsNotNone|assertIsInstance|assertNotIsInstance|assertAlmostEqual|assertNotAlmostEqual|assertCountEqual|assertDictEqual|assertListEqual|assertSetEqual|assertMultiLineEqual|assertRegex|assertNotRegex|assertRaisesRegex|assertWarnsRegex|assertLogs|assertNoLogs|assertWarns", "Test assertions", "Good: test assertions", Severity.INFO),
            (r"mock|Mock|MagicMock|patch|patch\.object|patch\.dict|patch\.builtin|sentinel|call|PropertyMock|ANY|DEFAULT|NonCallableMagicMock|NonCallableMock|create_autospec|wraps|side_effect|return_value|assert_called|assert_called_with|assert_called_once|assert_called_once_with|assert_any_call|assert_has_calls|assert_not_called|assert_called_with|assert_called_once_with|assert_called_with|assert_called_once_with|assert_called_with|assert_called_once_with", "Mocking", "Good: mocking", Severity.INFO),
            (r"unittest\.TestCase|setUp|tearDown|setUpClass|tearDownClass|setUpModule|tearDownModule", "unittest", "Good: unittest", Severity.INFO),
            # JavaScript testing
            (r"describe\(|it\(|test\(|beforeAll|afterAll|beforeEach|afterEach|expect\(|jest\.|vitest\.|mocha\.|chai\.|sinon\.|proxyquire\.|nock\.|supertest\.|msw\.", "JS testing", "Good: JS testing", Severity.INFO),
            (r"jest\.mock|jest\.spyOn|jest\.fn|jest\.useFakeTimers|jest\.useRealTimers|jest\.clearAllMocks|jest\.resetAllMocks|jest\.restoreAllMocks|jest\.setTimeout|jest\.requireActual|jest\.createMockFromModule|jest\.genMockFromModule|vi\.mock|vi\.spyOn|vi\.fn|vi\.useFakeTimers|vi\.useRealTimers|vi\.clearAllMocks|vi\.resetAllMocks|vi\.restoreAllMocks", "JS mocking", "Good: JS mocking", Severity.INFO),
            (r"toMatchSnapshot|toMatchInlineSnapshot|toThrow|rejects|resolves|toBe|toEqual|toBeUndefined|toBeNull|toBeDefined|toBeTruthy|toBeFalsy|toContain|toContainEqual|toHaveLength|toHaveProperty|toHaveClass|toHaveProperty|toMatch|toBeCalled|toBeCalledWith|toBeCalledTimes|toHaveBeenCalledTimes|toHaveBeenCalledWith|toHaveBeenLastCalledWith|toHaveBeenNthCalledWith|toHaveLastReturnedWith|toHaveNthReturnedWith|toHaveReturned|toHaveReturnedTimes|toHaveReturnedWith|toHaveLastReturnedWith|toHaveNthReturnedWith|toContainEqual|toStrictEqual|toMatchObject|toEqual|toContain|toContainEqual", "JS matchers", "Good: JS matchers", Severity.INFO),
            # Java testing
            (r"JUnit|junit|@Test|@BeforeAll|@AfterAll|@BeforeEach|@AfterEach|@Disabled|@DisplayName|@Nested|@ParameterizedTest|@RepeatedTest|@TestFactory|@TestInstance|@TestMethodOrder|@ExtendWith|@MockitoSettings|@Captor|@Mock|@Spy|@InjectMocks|@ValueSource|@CsvSource|@CsvFileSource|@MethodSource|@ArgumentsSource|@EnumSource|@NullSource|@EmptySource", "JUnit", "Good: JUnit", Severity.INFO),
            (r"Mockito|mockito|when\(|verify\(|doReturn|doThrow|doNothing|doCallRealMethod|given\(|willReturn|willThrow|willDoNothing|willCallRealMethod|spy\(|mock\(|capture\(|eq\(|any\(|anyInt\(|anyLong\(|anyString\(|anyBoolean\(|anyByte\(|anyChar\(|anyDouble\(|anyFloat\(|anyShort\(|argThat\(|nullable\(|isA\(|startsWith\(|endsWith\(|contains\(|matches\(|not\(|times\(|atLeast|atMost|never\(|clearInvocations\(|reset\(|verifyNoInteractions\(|verifyNoMoreInteractions\(|verifyZeroInteractions\(|inOrder\(", "Mockito", "Good: Mockito", Severity.INFO),
            (r"assertThat\(|assertEquals\(|assertNotNull\(|assertNull\(|assertTrue\(|assertFalse\(|assertSame\(|assertNotSame\(|assertThrows\(|assertDoesNotThrow\(|assertTimeout\(|assertTimeoutPreemptively\(|assertAll\(|fail\(|Assumptions\.", "JUnit assertions", "Good: JUnit assertions", Severity.INFO),
            # Go testing
            (r"func\s+Test\w+\(t\s+\*testing\.T\)|func\s+Test\w+\(t\s+\*testing\.B\)|func\s+Example\w+\(\)|func\s+TestMain\(m\s+\*testing\.M\)", "Go test", "Good: Go test", Severity.INFO),
            (r"t\.Error\(|t\.Errorf\(|t\.Fatal\(|t\.Fatalf\(|t\.Skip\(|t\.Skipf\(|t\.Parallel\(|t\.Run\(|t\.Helper\(|t\.Cleanup\(|t\.TempDir\(|t\.Setenv\(|t\.Log\(|t\.Logf\(|t\.Name\(", "Go test methods", "Good: Go test methods", Severity.INFO),
            (r"b\.Error\(|b\.Errorf\(|b\.Fatal\(|b\.Fatalf\(|b\.Skip\(|b\.Skipf\(|b\.Parallel\(|b\.Run\(|b\.Helper\(|b\.ResetTimer\(|b\.StartTimer\(|b\.StopTimer\(|b\.SetBytes\(|b\.ReportAllocs\(|b\.ReportMetric\(", "Go benchmark", "Good: Go benchmark", Severity.INFO),
            # Rust testing
            (r"#\[test\]|#\[cfg\(test\)\]|#\[should_panic\]|#\[should_panic\(|assert!\(|assert_eq!\(|assert_ne!\(|assert_matches!\(|debug_assert!\(|debug_assert_eq!\(|debug_assert_ne!\(", "Rust test", "Good: Rust test", Severity.INFO),
            (r"assert!\(|assert_eq!\(|assert_ne!\(|assert_matches!\(|debug_assert!\(|debug_assert_eq!\(|debug_assert_ne!\(|assert_json_eq!\(|assert_display_error_eq!\(|assert_contains!\(|assert_that!\(|assert_err!\(|assert_ok!\(|assert_some!\(|assert_none!\(|assert_true!\(|assert_false!\(|assert_ge!\(|assert_le!\(|assert_gt!\(|assert_lt!\(", "Rust assertions", "Good: Rust assertions", Severity.INFO),
            # PHP testing
            (r"PHPUnit|phpunit|@test|@dataProvider|@depends|@group|@covers|@uses|@before|@after|@beforeClass|@afterClass|@backupGlobals|@backupStaticAttributes|@preserveGlobalState|@runTestsInSeparateProcesses|@runInSeparateProcess|@requires|@ticket|@requiresPhp|@requiresPhpExtension|@requiresOs|@requiresSetting|@requiresFunction|@requiresMethod|@requiresClass|@requiresInterface|@requiresTrait|@doesNotPerformAssertions", "PHPUnit", "Good: PHPUnit", Severity.INFO),
            (r"->assertEquals\(|->assertNotEquals\(|->assertSame\(|->assertNotSame\(|->assertTrue\(|->assertFalse\(|->assertNull\(|->assertNotNull\(|->assertCount\(|->assertEmpty\(|->assertNotEmpty\(|->assertContains\(|->assertNotContains\(|->assertArrayHasKey\(|->assertArrayNotHasKey\(|->assertInstanceOf\(|->assertNotInstanceOf\(|->assertInternalType\(|->assertIsArray\(|->assertIsBool\(|->assertIsFloat\(|->assertIsInt\(|->assertIsNumeric\(|->assertIsObject\(|->assertIsResource\(|->assertIsString\(|->assertIsCallable\(|->assertIsScalar\(|->assertMatchesRegularExpression\(|->assertFileExists\(|->assertFileNotExists\(|->assertDirectoryExists\(|->assertDirectoryNotExists\(|->assertStringContainsString\(|->assertStringNotContainsString\(|->assertStringStartsWith\(|->assertStringStartsNotWith\(|->assertStringEndsWith\(|->assertStringEndsNotWith\(|->assertJson\(|->assertJsonStringEqualsJsonString\(|->assertJsonStringEqualsJsonFile\(|->assertJsonFileEqualsJsonFile\(|->assertXmlStringEqualsXmlString\(|->assertXmlFileEqualsXmlFile\(", "PHPUnit assertions", "Good: PHPUnit assertions", Severity.INFO),
            # Test patterns
            (r"AAA|Arrange.?Act.?Assert|Given.?When.?Then|GIVEN.?WHEN.?THEN|three.?act|three.?step", "Test pattern", "Good: test patterns", Severity.INFO),
            (r"fixture|Fixture|setup|Setup|teardown|Teardown|mock|Mock|spy|Spy|stub|Stub|fake|Fake|double|Double|dummy|Dummy|test.?data|TestData", "Test patterns", "Good: test patterns", Severity.INFO),
            (r"coverage|Coverage|COVERAGE|codecov|Codecov|coveralls|Coveralls|lcov|LCOV|cobertura|Cobertura|jacoco|JaCoCo|istanbul|Istanbul|nyc|NYC|cover|Cover", "Test coverage", "Good: test coverage", Severity.INFO),
            (r"TDD|tdd|BDD|bdd|ATDD|atdd|property.?based|Property.?Based|fuzz|Fuzz|mutation|Mutation|regression|Regression|snapshot|Snapshot|golden|Golden|baseline|Baseline", "Testing methodology", "Good: testing methodology", Severity.INFO),
            (r"integration|Integration|unit|Unit|end.?to.?end|End.?To.?End|e2e|E2E|acceptance|Acceptance|smoke|Smoke|regression|Regression|load|Load|stress|Stress|performance|Performance|security|Security|chaos|Chaos|contract|Contract|consumer|Consumer|provider|Provider|component|Component", "Test type", "Good: test types", Severity.INFO),
            (r"assert|Assert|ASSERT|verify|Verify|VERIFY|expect|Expect|EXPECT|check|Check|CHECK|validate|Validate|VALIDATE|confirm|Confirm|CONFIRM", "Test verb", "Good: test verbs", Severity.INFO),
        ]
        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith('#') or stripped.startswith('//'):
                continue
            for pattern, message, severity in patterns:
                if re.search(pattern, line):
                    issues.append(self._create_issue(
                        file_path=file_path, line=line_num, message=message,
                        suggestion=message, severity=severity, code_snippet=stripped,
                    ))
        return issues
