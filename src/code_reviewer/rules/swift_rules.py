"""
Swift-specific rules for code analysis.
Comprehensive rules for Swift error detection, optionals, and best practices.
"""

import re
from typing import Optional

from ..core.models import CodeIssue, Severity, IssueCategory
from ..core.rules import BaseRule


class SwiftRules(BaseRule):
    """Swift-specific error detection."""

    @property
    def name(self) -> str:
        return "swift"

    @property
    def description(self) -> str:
        return "Swift error detection"

    @property
    def category(self) -> IssueCategory:
        return IssueCategory.STYLE

    @property
    def severity(self) -> Severity:
        return Severity.WARNING

    def check(self, file_path: str, content: str) -> list[CodeIssue]:
        # Skip if not Swift code
        swift_indicators = ['let ', 'var ', 'func ', 'class ', 'struct ', 'enum ', 'protocol ', 'extension ', 'guard ', 'where ', 'switch ', 'case ', 'throws ', 'async ', 'await ', 'actor ', '@MainActor', '@Sendable', 'some ', 'any ', 'Sendable', 'Codable', 'Hashable', 'Equatable', 'Comparable']
        is_swift = any(ind in content for ind in swift_indicators)
        if not is_swift:
            return []

        issues = []
        lines = content.splitlines()

        patterns = [
            # Optional handling
            (r'\!\s*$', "Force unwrap (!)", "Use optional binding or nil coalescing", Severity.WARNING),
            (r'\.\s*!', "Force unwrap on property", "Use safe unwrap or guard let", Severity.WARNING),
            (r'as\!\s', "Force cast (as!)", "Use conditional cast (as?) instead", Severity.WARNING),
            (r'var\s+\w+\s*:\s*\w+\s*!', "Implicitly unwrapped optional", "Use regular Optional with proper unwrapping", Severity.WARNING),
            (r'\?\s*\.', "Optional chaining", "Good: using optional chaining", Severity.INFO),
            (r'\?\?', "Nil coalescing", "Good: using nil coalescing", Severity.INFO),
            (r'guard\s+let\s+\w+\s*=', "Guard let", "Good: using guard for early exit", Severity.INFO),
            (r'if\s+let\s+\w+\s*=', "If let binding", "Good: using optional binding", Severity.INFO),
            (r'(?:map|flatMap|compactMap)\s*\{', "Optional transformation", "Good: using optional transformation", Severity.INFO),
            (r'if\s+#available\s*\(', "Availability check", "Good: using availability API", Severity.INFO),

            # Memory management
            (r'\[weak\s+self\]', "Weak self capture", "Good: avoiding retain cycles", Severity.INFO),
            (r'\[unowned\s+self\]', "Unowned self capture", "Ensure self outlives the closure", Severity.INFO),
            (r'(?:retain|release|autorelease)\s*\(', "Manual memory management", "Use ARC; avoid manual retain/release", Severity.WARNING),
            (r'autoreleasepool\s*\{', "Autorelease pool", "Good: using autorelease pool", Severity.INFO),

            # Error handling
            (r'throws\s+', "Throwing function", "Good: using Swift error handling", Severity.INFO),
            (r'try\s+', "Try expression", "Good: using try for error handling", Severity.INFO),
            (r'try\?\s', "Optional try", "Consider using try for explicit error handling", Severity.INFO),
            (r'try\!\s', "Force try", "Avoid force try; use do-catch instead", Severity.WARNING),
            (r'do\s*\{', "Do block", "Good: using do-catch", Severity.INFO),
            (r'catch\s*\{', "Catch block", "Good: catching errors", Severity.INFO),
            (r'catch\s*_\s*\{', "Catch all errors", "Consider handling specific errors", Severity.INFO),
            (r'(?:Result|\.success|\.failure)', "Result type", "Good: using Result type", Severity.INFO),

            # Concurrency
            (r'(?:async|await)\s', "Async/await", "Good: using structured concurrency", Severity.INFO),
            (r'@Sendable\s', "Sendable annotation", "Good: using Sendable", Severity.INFO),
            (r'@MainActor\s', "MainActor annotation", "Good: using MainActor for UI", Severity.INFO),
            (r'(?:Task|Task\.init|Task\.detached)', "Task usage", "Good: using Task for async work", Severity.INFO),
            (r'(?:actor|nonisolated)', "Actor usage", "Good: using actor model", Severity.INFO),
            (r'(?:async\s+let|withCheckedContinuation)', "Async let/continuation", "Good: using async constructs", Severity.INFO),

            # Protocol issues
            (r'(?:protocol|Protocol)\s+\w+', "Protocol declaration", "Good: using protocols", Severity.INFO),
            (r'(?:extension|Extension)\s+\w+\s*:', "Protocol conformance", "Good: extending protocol conformance", Severity.INFO),
            (r'(?:some|any)\s+\w+', "Opaque/Existential type", "Good: using modern type system", Severity.INFO),
            (r'(?:Equatable|Hashable|Comparable|Codable|Identifiable)', "Protocol conformance", "Good: using standard protocols", Severity.INFO),

            # Value types
            (r'struct\s+\w+', "Struct (value type)", "Good: using value types", Severity.INFO),
            (r'(?:Copyable|Noncopyable)', "Copy control", "Good: using copy control", Severity.INFO),
            (r'@frozen\s', "Frozen enum", "Good: using frozen for performance", Severity.INFO),

            # SwiftUI
            (r'(?:@State|@Binding|@ObservedObject|@StateObject|@EnvironmentObject|@Environment)', "SwiftUI property wrapper", "Good: using SwiftUI state management", Severity.INFO),
            (r'(?:\.body|View\s+protocol)', "SwiftUI body", "Good: implementing View protocol", Severity.INFO),
            (r'(?:\.sheet|\.alert|\.confirmationDialog|\.navigationDestination)', "SwiftUI presentation", "Good: using SwiftUI navigation", Severity.INFO),

            # Property wrappers
            (r'@propertyWrapper', "Property wrapper", "Good: using property wrappers", Severity.INFO),
            (r'(?:@Published|@ObservedObject)', "Combine integration", "Good: using Combine", Severity.INFO),

            # String handling
            (r'(?:\.contains|\.hasPrefix|\.hasSuffix)', "String check", "Good: using string methods", Severity.INFO),
            (r'(?:\.split|\.joined|\.components)', "String splitting", "Good: using string operations", Severity.INFO),
            (r'(?:String|Substring)\b', "String/Substring", "Good: understanding String vs Substring", Severity.INFO),

            # Collection operations
            (r'\.(?:map|filter|reduce|compactMap|flatMap)\s*\{', "Collection transformation", "Good: using functional operations", Severity.INFO),
            (r'\.(?:sorted|reversed|shuffled)\s*\(', "Collection ordering", "Good: using collection methods", Severity.INFO),
            (r'\.(?:contains|first|last|firstIndex|lastIndex)', "Collection search", "Good: using collection methods", Severity.INFO),
            (r'(?:Dictionary|Set|Array)\s*<', "Generic collection", "Good: using typed collections", Severity.INFO),

            # Access control
            (r'(?:public|internal|private|fileprivate|open)\s+(?:class|struct|enum|func|var|let)', "Access control", "Good: using access control", Severity.INFO),
            (r'(?:private|fileprivate)\s+(?:var|let)\s+\w+\s*:', "Private property", "Good: encapsulating state", Severity.INFO),

            # Generics
            (r'<\w+\s*(?:where|:)\s+', "Generic constraint", "Good: using generic constraints", Severity.INFO),
            (r'(?:func|class|struct|enum|protocol)\s+\w+\s*<\w+>', "Generic type", "Good: using generics", Severity.INFO),

            # Result builders
            (r'@resultBuilder', "Result builder", "Good: using result builders", Severity.INFO),
            (r'@ViewBuilder', "View builder", "Good: using ViewBuilder", Severity.INFO),

            # Property observers
            (r'(?:willSet|didSet)', "Property observer", "Good: using property observers", Severity.INFO),

            # Subscripts
            (r'subscript\s*\(', "Subscript", "Good: using subscript syntax", Severity.INFO),

            # Operators
            (r'(?:prefix|postfix|infix)\s+func\s+', "Operator overload", "Good: using operator overloading", Severity.INFO),
            (r'(?:static\s+func\s+\+\+|static\s+func\s+==)', "Operator implementation", "Good: implementing operators", Severity.INFO),

            # Closures
            (r'\{\s*\(\s*\)\s*in', "Closure with explicit return", "Use implicit return for single expressions", Severity.INFO),
            (r'\$0|\$1|\$2', "Shorthand arguments", "Good: using shorthand closure arguments", Severity.INFO),
            (r'(?:map|filter|reduce|sort)\s*\{', "Closure-based collection method", "Good: using closure syntax", Severity.INFO),

            # Patterns
            (r'case\s+let\s+\w+\s*\(', "Pattern matching", "Good: using pattern matching", Severity.INFO),
            (r'case\s+\.', "Enum case matching", "Good: matching enum cases", Severity.INFO),
            (r'(?:where|if)\s+\w+\s*(?:==|!=|<|>|<=|>=)\s*', "Pattern condition", "Good: using pattern conditions", Severity.INFO),

            # Memory
            (r'(?:\.prefix|\.suffix|\.dropFirst|\.dropLast)', "Collection slicing", "Good: using efficient slicing", Severity.INFO),
            (r'(?:\.withUnsafeBufferPointer|\.withUnsafeMutableBufferPointer)', "Unsafe buffer access",
             "Good: using unsafe buffer when needed", Severity.INFO),
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
