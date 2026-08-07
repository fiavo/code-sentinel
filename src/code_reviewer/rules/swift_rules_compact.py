"""
Swift-specific comprehensive rules.
"""
import re
from ..core.models import CodeIssue, Severity, IssueCategory
from ..core.rules import BaseRule


class SwiftCompactRules(BaseRule):
    @property
    def name(self) -> str:
        return "swift_compact"
    @property
    def description(self) -> str:
        return "Swift-specific comprehensive patterns"
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
            # Swift features
            (r"func\s+\w+\(", "Function definition", "Good: function", Severity.INFO),
            (r"let\s+\w+", "Immutable variable", "Good: let", Severity.INFO),
            (r"var\s+\w+", "Mutable variable", "Good: var", Severity.INFO),
            (r"class\s+\w+", "Class definition", "Good: class", Severity.INFO),
            (r"struct\s+\w+", "Struct definition", "Good: struct", Severity.INFO),
            (r"enum\s+\w+", "Enum definition", "Good: enum", Severity.INFO),
            (r"protocol\s+\w+", "Protocol definition", "Good: protocol", Severity.INFO),
            (r"extension\s+\w+", "Extension", "Good: extension", Severity.INFO),
            (r"actor\s+\w+", "Actor definition", "Good: actor", Severity.INFO),
            (r"final\s+class\s+\w+", "Final class", "Good: final class", Severity.INFO),
            (r"open\s+class\s+\w+", "Open class", "Good: open class", Severity.INFO),
            (r"public\s+class\s+\w+", "Public class", "Good: public class", Severity.INFO),
            (r"private\s+class\s+\w+", "Private class", "Good: private class", Severity.INFO),
            (r"internal\s+class\s+\w+", "Internal class", "Good: internal class", Severity.INFO),
            (r"fileprivate\s+class\s+\w+", "Fileprivate class", "Good: fileprivate class", Severity.INFO),
            # Swift optionals
            (r"\w+\?", "Optional type", "Good: optional type", Severity.INFO),
            (r"\w+\!", "Implicitly unwrapped optional", "Avoid implicitly unwrapped optionals", Severity.WARNING),
            (r"\.none|\.some\(|Optional\.", "Optional pattern", "Good: optional pattern", Severity.INFO),
            (r"guard\s+let\s+\w+\s+=", "Guard let", "Good: guard let", Severity.INFO),
            (r"if\s+let\s+\w+\s+=", "If let", "Good: if let", Severity.INFO),
            (r"if\s+case\s+", "Pattern matching", "Good: pattern matching", Severity.INFO),
            (r"guard\s+case\s+", "Guard case", "Good: guard case", Severity.INFO),
            (r"switch\s+\w+\s*\{", "Switch statement", "Good: switch", Severity.INFO),
            # Swift protocols
            (r"protocol\s+\w+\s*\{", "Protocol definition", "Good: protocol", Severity.INFO),
            (r":\s*\w+\s*,\s*\w+", "Protocol conformance", "Good: protocol conformance", Severity.INFO),
            (r"where\s+\w+\s*:\s*\w+", "Protocol constraint", "Good: protocol constraint", Severity.INFO),
            (r"associatedtype\s+\w+", "Associated type", "Good: associated type", Severity.INFO),
            (r"typealias\s+\w+\s*=\s*\w+", "Typealias", "Good: typealias", Severity.INFO),
            # Swift closures
            (r"\{\s*\(\s*\w+\s*:\s*\w+\s*\)\s*->\s*\w+\s+in", "Closure with types", "Good: typed closure", Severity.INFO),
            (r"\$\w+", "Shorthand argument", "Good: shorthand argument", Severity.INFO),
            (r"\.filter\s*\{|\.map\s*\{|\.reduce\s*\{|\.compactMap\s*\{|\.flatMap\s*\{|\.forEach\s*\{|\.sorted\s*\{|\.sorted\s*\{", "Higher-order functions", "Good: HOFs", Severity.INFO),
            # Swift error handling
            (r"throws\s+->\s*\w+", "Throwing function", "Good: throwing function", Severity.INFO),
            (r"try\?|try!", "Try optional/force", "Use do-try-catch", Severity.WARNING),
            (r"do\s*\{", "Do block", "Good: do block", Severity.INFO),
            (r"catch\s+", "Catch clause", "Good: catch clause", Severity.INFO),
            # Swift async/await
            (r"async\s+func\s+\w+", "Async function", "Good: async function", Severity.INFO),
            (r"await\s+", "Await", "Good: await", Severity.INFO),
            (r"Task\s*\{", "Task", "Good: Task", Severity.INFO),
            (r"Task\.detached", "Detached task", "Good: detached task", Severity.INFO),
            (r"@Sendable", "Sendable", "Good: Sendable", Severity.INFO),
            # Swift property wrappers
            (r"@State\b|@Binding\b|@StateObject\b|@ObservedObject\b|@EnvironmentObject\b|@Environment\b|@Published\b|@FetchRequest\b|@AppStorage\b|@SceneStorage\b", "SwiftUI property wrapper", "Good: SwiftUI wrapper", Severity.INFO),
            (r"@propertyWrapper|@ObservedProperty|@PersistedProperty|@CustomPropertyWrapper", "Property wrapper", "Good: property wrapper", Severity.INFO),
            # Swift concurrency
            (r"actor\s+\w+", "Actor definition", "Good: actor", Severity.INFO),
            (r"@MainActor", "Main actor", "Good: MainActor", Severity.INFO),
            (r"nonisolated\s+func", "Nonisolated", "Good: nonisolated", Severity.INFO),
            (r"Sendable|@unchecked Sendable", "Sendable protocol", "Good: Sendable", Severity.INFO),
            # Swift patterns
            (r"@\w+\s+\w+", "Attribute", "Good: attribute", Severity.INFO),
            (r"#if\s+\w+|#elseif\s+\w+|#else|#endif", "Conditional compilation", "Good: conditional compilation", Severity.INFO),
            (r"import\s+\w+", "Import statement", "Good: import", Severity.INFO),
            (r"private\s+set|public\s+private\(set\)", "Access control", "Good: access control", Severity.INFO),
            (r"weak\s+var\s+\w+", "Weak reference", "Good: weak reference", Severity.INFO),
            (r"unowned\s+var\s+\w+", "Unowned reference", "Good: unowned reference", Severity.INFO),
            # Swift Testing
            (r"@Test\s+func|@Suite\s+struct|@Test\(|@Test\(\(", "Swift Testing", "Good: Swift Testing", Severity.INFO),
            (r"XCTAssert|XCTFail|XCTUnwrap|XCTSkip", "XCTest", "Good: XCTest", Severity.INFO),
            # SwiftUI
            (r"View\s*\{|some\s+View\s*\{", "View body", "Good: View body", Severity.INFO),
            (r"NavigationStack|NavigationView|NavigationLink|NavigationSplitView", "Navigation", "Good: navigation", Severity.INFO),
            (r"List\s*\{|VStack\s*\{|HStack\s*\{|ZStack\s*\{|ScrollView\s*\{|LazyVStack\s*\{|LazyHStack\s*\{|LazyVGrid\s*\{|LazyHGrid\s*\{", "SwiftUI layout", "Good: SwiftUI layout", Severity.INFO),
            (r"@Environment\(\.\\\w+\)|\.environment\(\.", "Environment", "Good: environment", Severity.INFO),
            (r"\.animation\(|\.transition\(|\.onAppear\(|\.onDisappear\(|\.task\(|\.onChange\(|\.onTapGesture\(|\.gesture\(", "SwiftUI modifiers", "Good: SwiftUI modifiers", Severity.INFO),
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
