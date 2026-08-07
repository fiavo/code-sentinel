"""
Kotlin-specific comprehensive rules.
"""
import re
from ..core.models import CodeIssue, Severity, IssueCategory
from ..core.rules import BaseRule


class KotlinCompactRules(BaseRule):
    @property
    def name(self) -> str:
        return "kotlin_compact"
    @property
    def description(self) -> str:
        return "Kotlin-specific comprehensive patterns"
    @property
    def category(self) -> IssueCategory:
        return IssueCategory.BEST_PRACTICE
    @property
    def severity(self) -> Severity:
        return Severity.WARNING

    def check(self, file_path: str, content: str) -> list[CodeIssue]:
        issues = []
        lines = content.splitlines()
        patterns = [
            # Kotlin features
            (r"fun\s+\w+\(", "Function definition", "Good: function", Severity.INFO),
            (r"val\s+\w+", "Immutable variable", "Good: val", Severity.INFO),
            (r"var\s+\w+", "Mutable variable", "Good: var", Severity.INFO),
            (r"class\s+\w+", "Class definition", "Good: class", Severity.INFO),
            (r"data\s+class\s+\w+", "Data class", "Good: data class", Severity.INFO),
            (r"sealed\s+class\s+\w+", "Sealed class", "Good: sealed class", Severity.INFO),
            (r"enum\s+class\s+\w+", "Enum class", "Good: enum class", Severity.INFO),
            (r"object\s+\w+", "Object declaration", "Good: object", Severity.INFO),
            (r"interface\s+\w+", "Interface", "Good: interface", Severity.INFO),
            (r"abstract\s+class\s+\w+", "Abstract class", "Good: abstract class", Severity.INFO),
            (r"open\s+class\s+\w+", "Open class", "Good: open class", Severity.INFO),
            (r"inner\s+class\s+\w+", "Inner class", "Good: inner class", Severity.INFO),
            (r"companion\s+object", "Companion object", "Good: companion object", Severity.INFO),
            (r"annotation\s+class\s+\w+", "Annotation class", "Good: annotation class", Severity.INFO),
            # Kotlin null safety
            (r"\w+\?\.", "Safe call", "Good: safe call", Severity.INFO),
            (r"\w+\?!", "Non-null assertion", "Good: non-null assertion", Severity.INFO),
            (r"\?:", "Elvis operator", "Good: elvis operator", Severity.INFO),
            (r"as\?", "Safe cast", "Good: safe cast", Severity.INFO),
            (r"!!", "Non-null assertion", "Use safe calls instead", Severity.WARNING),
            # Kotlin lambdas
            (r"\{\s*\w+\s*->", "Lambda with parameter", "Good: lambda", Severity.INFO),
            (r"it\b", "Implicit parameter", "Good: implicit parameter", Severity.INFO),
            (r"\.let\s*\{", "Let scope function", "Good: let", Severity.INFO),
            (r"\.run\s*\{", "Run scope function", "Good: run", Severity.INFO),
            (r"\.apply\s*\{", "Apply scope function", "Good: apply", Severity.INFO),
            (r"\.also\s*\{", "Also scope function", "Good: also", Severity.INFO),
            (r"\.with\s*\(", "With scope function", "Good: with", Severity.INFO),
            # Kotlin coroutines
            (r"suspend\s+fun\s+\w+", "Suspend function", "Good: suspend function", Severity.INFO),
            (r"coroutineScope\s*\{|globalScope\s*\{|launch\s*\{|async\s*\{|runBlocking\s*\{", "Coroutine scope", "Good: coroutine scope", Severity.INFO),
            (r"withContext\s*\(", "withContext", "Good: withContext", Severity.INFO),
            (r"Flow<|flow\s*\{|StateFlow|SharedFlow|MutableStateFlow|MutableSharedFlow", "Flow", "Good: Flow", Severity.INFO),
            (r"Dispatchers\.\w+", "Dispatcher", "Good: dispatcher", Severity.INFO),
            (r"CoroutineScope|Job|Deferred|SupervisorJob|SupervisorScope", "Coroutine primitives", "Good: coroutine primitives", Severity.INFO),
            # Kotlin collections
            (r"listOf\(|mutableListOf\(|arrayListOf\(|setOf\(|mutableSetOf\(|hashSetOf\(|mapOf\(|mutableMapOf\(|hashMapOf\(|sequenceOf\(|emptyList\(\)|emptySet\(\)|emptyMap\(\)", "Collection functions", "Good: collection functions", Severity.INFO),
            (r"\.map\s*\{|\.filter\s*\{|\.flatMap\s*\{|\.groupBy\s*\{|\.associate\s*\{|\.fold\s*\{|\.reduce\s*\{|\.forEach\s*\{|\.any\s*\{|\.all\s*\{|\.none\s*\{|\.find\s*\{|\.first\s*\{|\.last\s*\{|\.count\s*\{|\.sumOf\s*\{|\.sortedBy\s*\{|\.sortedByDescending\s*\{|\.distinct\s*\{|\.take\s*\{|\.drop\s*\{|\.chunked\s*\{|\.windowed\s*\{|\.zip\s*\{|\.unzip\s*\{", "Collection operations", "Good: collection operations", Severity.INFO),
            # Kotlin extensions
            (r"fun\s+\w+\.\w+\(", "Extension function", "Good: extension function", Severity.INFO),
            (r"val\s+<T>|var\s+<T>", "Extension property", "Good: extension property", Severity.INFO),
            # Kotlin delegation
            (r"by\s+\w+\(", "Delegation", "Good: delegation", Severity.INFO),
            (r"by\s+lazy", "Lazy delegation", "Good: lazy delegation", Severity.INFO),
            # Kotlin patterns
            (r"when\s*\(", "When expression", "Good: when expression", Severity.INFO),
            (r"sealed\s+class|sealed\s+interface", "Sealed type", "Good: sealed type", Severity.INFO),
            (r"inline\s+fun\s+\w+", "Inline function", "Good: inline function", Severity.INFO),
            (r"reified\s+\w+", "Reified type", "Good: reified type", Severity.INFO),
            (r"crossinline\s+\w+", "Crossinline", "Good: crossinline", Severity.INFO),
            (r"noinline\s+\w+", "Noinline", "Good: noinline", Severity.INFO),
            (r"typealias\s+\w+", "Type alias", "Good: type alias", Severity.INFO),
            # Kotlin DSLs
            (r"@DslMarker", "DSL marker", "Good: DSL marker", Severity.INFO),
            (r"@JvmStatic|@JvmOverloads|@JvmField|@JvmName|@JvmSynthetic|@JvmMultifileClass", "Jvm annotations", "Good: Jvm annotations", Severity.INFO),
            # Kotlin testing
            (r"should\w+\(|shouldBe|shouldNotBe|shouldHaveSize|shouldBeEmpty|shouldNotBeEmpty|shouldBeNullOrEmpty|shouldContain|shouldNotContain|shouldMatch|shouldNotMatch", "Kotest assertions", "Good: Kotest assertions", Severity.INFO),
            (r"describe\(|it\(|context\(|beforeAll|afterAll|beforeEach|afterEach", "Kotest test", "Good: Kotest tests", Severity.INFO),
            # Kotlin frameworks
            (r"Ktor|kotlinx\.coroutines|kotlinx\.serialization|kotlinx\.datetime|kotlinx\.io|kotlinx\.html|Exposed|Koin|Arrow", "Kotlin libraries", "Good: Kotlin libraries", Severity.INFO),
        ]
        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith('//'):
                continue
            for pattern, message, severity in patterns:
                if re.search(pattern, line):
                    issues.append(self._create_issue(
                        file_path=file_path, line=line_num, message=message,
                        suggestion=message, severity=severity, code_snippet=stripped,
                    ))
        return issues
