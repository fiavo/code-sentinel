"""
Kotlin-specific rules for code analysis.
Comprehensive rules for Kotlin error detection, null safety, and best practices.
"""

import re
from typing import Optional

from ..core.models import CodeIssue, Severity, IssueCategory
from ..core.rules import BaseRule


class KotlinRules(BaseRule):
    """Kotlin-specific error detection."""

    @property
    def name(self) -> str:
        return "kotlin"

    @property
    def description(self) -> str:
        return "Kotlin error detection"

    @property
    def category(self) -> IssueCategory:
        return IssueCategory.STYLE

    @property
    def severity(self) -> Severity:
        return Severity.WARNING

    def check(self, file_path: str, content: str) -> list[CodeIssue]:
        # Skip if not Kotlin code
        kt_indicators = ['fun ', 'val ', 'var ', 'class ', 'object ', 'interface ', 'when ', 'sealed ', 'data ', 'companion ', 'suspend ', 'by ', 'lazy ', 'lateinit ', '?.', '!!', '?:', 'when(', 'println', 'println()']
        is_kt = any(ind in content for ind in kt_indicators)
        if not is_kt:
            return []

        issues = []
        lines = content.splitlines()

        patterns = [
            # Null safety
            (r'!!\s', "Non-null assertion (!!) operator", "Use safe call (?.) or let{} instead", Severity.WARNING),
            (r'!!\.', "Non-null assertion on property access", "Use safe call (?.) or let{}", Severity.WARNING),
            (r'!!\[', "Non-null assertion on index", "Use safe call or null check", Severity.WARNING),
            (r'as\s+\w+\b(?!\?)', "Unsafe cast", "Use safe cast (as?) instead", Severity.WARNING),
            (r'\?:\s*(?:null|throw)', "Elvis operator with null/throw", "Good: using elvis operator", Severity.INFO),
            (r'\.let\s*\{', "let scope function", "Good: using scope function", Severity.INFO),
            (r'\.also\s*\{', "also scope function", "Good: using scope function", Severity.INFO),
            (r'\.apply\s*\{', "apply scope function", "Good: using scope function", Severity.INFO),
            (r'\.run\s*\{', "run scope function", "Good: using scope function", Severity.INFO),
            (r'\.with\s*\(', "with scope function", "Good: using scope function", Severity.INFO),

            # Coroutines
            (r'suspend\s+fun\s+', "Suspend function", "Good: using coroutines", Severity.INFO),
            (r'(?:launch|async)\s*\{', "Coroutine launch/async", "Ensure proper lifecycle management", Severity.INFO),
            (r'runBlocking\s*\{', "runBlocking usage", "Avoid runBlocking in production code", Severity.WARNING),
            (r'GlobalScope\.(?:launch|async)', "GlobalScope usage", "Use structured concurrency instead", Severity.WARNING),
            (r'(?:withContext|Dispatchers)', "Coroutine context", "Good: using coroutine context", Severity.INFO),
            (r'(?:Job|Deferred)', "Coroutine Job/Deferred", "Good: using coroutine primitives", Severity.INFO),
            (r'(?:CancellableContinuation|suspendCancellableCoroutine)', "Cancellation support",
             "Good: supporting cancellation", Severity.INFO),

            # Collection issues
            (r'(?:listOf|setOf|mapOf)\s*\(', "Immutable collection",
             "Good: using immutable collections", Severity.INFO),
            (r'mutableListOf\s*\(', "Mutable list", "Consider using immutable if possible", Severity.INFO),
            (r'mutableSetOf\s*\(', "Mutable set", "Consider using immutable if possible", Severity.INFO),
            (r'mutableMapOf\s*\(', "Mutable map", "Consider using immutable if possible", Severity.INFO),
            (r'(?:filter|map|flatMap|reduce|fold)\s*\{', "Collection operation",
             "Good: using functional operations", Severity.INFO),
            (r'\.toList\s*\(\s*\)', "Convert to list",
             "Good: converting to immutable list", Severity.INFO),
            (r'\.toSet\s*\(\s*\)', "Convert to set",
             "Good: converting to immutable set", Severity.INFO),
            (r'\.toMap\s*\(\s*\)', "Convert to map",
             "Good: converting to immutable map", Severity.INFO),
            (r'\.toMutableList\s*\(\s*\)', "Convert to mutable list",
             "Consider if mutable version is necessary", Severity.INFO),

            # Type issues
            (r'(?:Any|Any?)\b', "Any type", "Use specific types when possible", Severity.INFO),
            (r'Nothing\b', "Nothing type", "Good: using Nothing for throw/return", Severity.INFO),
            (r'(?:var|val)\s+\w+\s*:\s*\w+\s*=', "Typed variable",
             "Good: explicit type declaration", Severity.INFO),
            (r'(?:var|val)\s+\w+\s*=', "Type inference",
             "Good: using type inference", Severity.INFO),
            (r'(?:sealed|data|abstract)\s+class\s+', "Sealed/data/abstract class",
             "Good: using class modifiers", Severity.INFO),
            (r'(?:object|companion)\s+object\s+', "Object declaration",
             "Good: using singleton pattern", Severity.INFO),

            # Function issues
            (r'(?:inline|noinline|crossinline)\s+fun\s+', "Inline function modifier",
             "Good: using inline functions", Severity.INFO),
            (r'fun\s+\w+\s*\([^)]*\)\s*=\s*', "Expression body function",
             "Good: using expression body", Severity.INFO),
            (r'(?:private|protected|internal)\s+fun\s+', "Visibility modifier",
             "Good: proper visibility", Severity.INFO),
            (r'operator\s+fun\s+', "Operator function",
             "Good: using operator overloading", Severity.INFO),
            (r'extension\s+fun\s+', "Extension function",
             "Good: using extension functions", Severity.INFO),

            # Property issues
            (r'lateinit\s+var\s+', "Lateinit variable",
             "Ensure variable is initialized before use", Severity.INFO),
            (r'(?:lazy|by\s+lazy)\s*\{', "Lazy initialization",
             "Good: using lazy initialization", Severity.INFO),
            (r'(?:by\s+Delegates\.(?:observable|vetoable))', "Property delegation",
             "Good: using property delegation", Severity.INFO),
            (r'(?:get\(\)|set\(\))', "Custom getter/setter",
             "Good: using custom accessors", Severity.INFO),
            (r'const\s+val\s+', "Const val",
             "Good: using compile-time constants", Severity.INFO),

            # Delegation
            (r'by\s+lazy\s*\{', "Lazy delegation",
             "Good: using lazy delegation", Severity.INFO),
            (r'by\s+Delegates\.(?:observable|vetoable)', "Property delegation",
             "Good: using property delegation", Severity.INFO),
            (r'(?:Class|Interface)\s+by\s+', "Class delegation",
             "Good: using class delegation", Severity.INFO),

            # DSL
            (r'@DslMarker', "DSL marker annotation",
             "Good: using DSL markers", Severity.INFO),
            (r'@receiver:', "Receiver annotation",
             "Good: using receiver annotations", Severity.INFO),
            (r'fun\s+\w+\.(\w+)\s*\{', "DSL function",
             "Good: using DSL builders", Severity.INFO),

            # Type aliases
            (r'typealias\s+\w+\s*=', "Type alias",
             "Good: using type aliases for readability", Severity.INFO),

            # Sealed classes
            (r'sealed\s+class\s+', "Sealed class",
             "Good: using sealed classes for restricted hierarchies", Severity.INFO),
            (r'(?:object|val)\s+\w+\s*:\s*\w+\s*\{', "Sealed class implementation",
             "Good: implementing sealed class", Severity.INFO),

            # Result type
            (r'Result<(?:Success|Failure|Exception)>', "Result type",
             "Good: using Result type for error handling", Severity.INFO),
            (r'(?:getOrElse|getOrNull|getOrThrow)', "Result accessors",
             "Good: using Result accessors", Severity.INFO),

            # Scope functions
            (r'\.let\s*\{.*\?\s*:', "let with null check",
             "Consider using safe call (?.) instead", Severity.INFO),
            (r'\.run\s*\{', "run scope function",
             "Good: using run for object context", Severity.INFO),
            (r'\.apply\s*\{', "apply scope function",
             "Good: using apply for object initialization", Severity.INFO),
            (r'\.also\s*\{', "also scope function",
             "Good: using also for side effects", Severity.INFO),
            (r'\.with\s*\(', "with scope function",
             "Good: using with for object operations", Severity.INFO),

            # Exception handling
            (r'try\s*\{', "Try block",
             "Good: using try-catch", Severity.INFO),
            (r'catch\s*\(\s*\w+\s*:\s*(?:Exception|Throwable)\s*\)', "Catch block",
             "Consider catching more specific exceptions", Severity.INFO),
            (r'finally\s*\{', "Finally block",
             "Good: using finally for cleanup", Severity.INFO),
            (r'(?:runCatching|recover)', "runCatching usage",
             "Good: using Result-based error handling", Severity.INFO),

            # Coroutine builders
            (r'coroutineScope\s*\{', "coroutineScope builder",
             "Good: using structured concurrency", Severity.INFO),
            (r'supervisorScope\s*\{', "supervisorScope builder",
             "Good: using supervisor scope", Severity.INFO),
            (r'(?:withTimeout|withTimeoutOrNull)', "Timeout builders",
             "Good: adding timeouts to coroutines", Severity.INFO),

            # Flow
            (r'(?:flow|flowOf|asFlow|callbackFlow)', "Flow usage",
             "Good: using Kotlin Flow", Severity.INFO),
            (r'\.(?:collect|collectLatest)\s*\{', "Flow collection",
             "Good: collecting Flow", Severity.INFO),
            (r'\.(?:map|filter|flatMapLatest|transformLatest)\s*\{', "Flow operator",
             "Good: using Flow operators", Severity.INFO),
            (r'(?:StateFlow|SharedFlow)', "StateFlow/SharedFlow",
             "Good: using state flows", Severity.INFO),
        ]

        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith('//') or stripped.startswith('*'):
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
