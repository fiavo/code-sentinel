"""
C/C++ specific comprehensive rules.
"""
import re
from ..core.models import CodeIssue, Severity, IssueCategory
from ..core.rules import BaseRule


class CPPComprehensiveRules(BaseRule):
    @property
    def name(self) -> str:
        return "cpp_comprehensive"
    @property
    def description(self) -> str:
        return "C/C++ specific comprehensive patterns"
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
            # C/C++ features
            (r"int\s+main\(", "Main function", "Good: main function", Severity.INFO),
            (r"void\s+\w+\(", "Function definition", "Good: function definition", Severity.INFO),
            (r"struct\s+\w+", "Struct definition", "Good: struct", Severity.INFO),
            (r"enum\s+(?:enum\s+)?\w+", "Enum definition", "Good: enum", Severity.INFO),
            (r"typedef\s+", "Typedef", "Good: typedef", Severity.INFO),
            (r"#define\s+", "Macro", "Good: macro", Severity.INFO),
            (r"#include\s+[<\"]", "Include directive", "Good: include", Severity.INFO),
            (r"namespace\s+\w+", "Namespace", "Good: namespace", Severity.INFO),
            (r"using\s+namespace\s+", "Using namespace", "Avoid using namespace in headers", Severity.WARNING),
            # C++ classes
            (r"class\s+\w+", "Class definition", "Good: class", Severity.INFO),
            (r"struct\s+\w+\s*\{", "Struct definition", "Good: struct", Severity.INFO),
            (r"virtual\s+\w+\s+\w+\(", "Virtual method", "Good: virtual method", Severity.INFO),
            (r"override", "Override specifier", "Good: override", Severity.INFO),
            (r"final", "Final specifier", "Good: final", Severity.INFO),
            (r"friend\s+\w+", "Friend declaration", "Good: friend", Severity.INFO),
            (r"operator\s*\w+", "Operator overloading", "Good: operator overloading", Severity.INFO),
            (r"template\s*<", "Template", "Good: template", Severity.INFO),
            (r"constexpr\s+", "Constexpr", "Good: constexpr", Severity.INFO),
            (r"consteval\s+", "Consteval", "Good: consteval", Severity.INFO),
            (r"constinit\s+", "Constinit", "Good: constinit", Severity.INFO),
            # C++ smart pointers
            (r"std::unique_ptr|std::shared_ptr|std::weak_ptr|std::make_unique|std::make_shared", "Smart pointers", "Good: smart pointers", Severity.INFO),
            (r"new\s+\w+", "Raw new", "Use smart pointers instead", Severity.WARNING),
            (r"delete\s+\w+", "Raw delete", "Use smart pointers instead", Severity.WARNING),
            (r"malloc\(|calloc\(|realloc\(|free\(", "C memory management", "Use C++ allocators", Severity.WARNING),
            # C++ features
            (r"auto\s+\w+", "Auto keyword", "Good: auto usage", Severity.INFO),
            (r"nullptr", "Null pointer", "Good: nullptr", Severity.INFO),
            (r"enum\s+class\s+\w+", "Scoped enum", "Good: scoped enum", Severity.INFO),
            (r"std::optional|std::variant|std::any", "C++17 features", "Good: C++17 features", Severity.INFO),
            (r"std::ranges|std::views", "C++20 ranges", "Good: C++20 ranges", Severity.INFO),
            (r"co_await|co_yield|co_return", "Coroutines", "Good: coroutines", Severity.INFO),
            (r"concept\s+\w+|requires\s+", "Concepts", "Good: C++20 concepts", Severity.INFO),
            (r"std::format|std::print", "C++20 formatting", "Good: C++20 formatting", Severity.INFO),
            (r"std::source_location", "Source location", "Good: source location", Severity.INFO),
            # C++ STL
            (r"std::vector|std::list|std::deque|std::map|std::set|std::unordered_map|std::unordered_set|std::array|std::string|std::string_view", "STL containers", "Good: STL containers", Severity.INFO),
            (r"std::algorithm|std::sort|std::find|std::transform|std::accumulate|std::copy|std::fill|std::remove|std::unique|std::reverse|std::min_element|std::max_element", "STL algorithms", "Good: STL algorithms", Severity.INFO),
            (r"std::function|std::bind|std::ref|std::cref|std::invoke|std::apply|std::forward|std::move|std::swap|std::exchange", "STL utilities", "Good: STL utilities", Severity.INFO),
            (r"std::thread|std::mutex|std::lock_guard|std::unique_lock|std::shared_lock|std::condition_variable|std::atomic|std::future|std::promise|std::async|std::packaged_task", "Concurrency", "Good: concurrency", Severity.INFO),
            (r"std::filesystem|std::path", "Filesystem", "Good: filesystem", Severity.INFO),
            (r"std::chrono", "Chrono", "Good: chrono", Severity.INFO),
            (r"std::span", "Span", "Good: std::span", Severity.INFO),
            (r"std::expected", "Expected", "Good: std::expected", Severity.INFO),
            # Safety
            (r"assert\(|static_assert\(|assert\.h|cassert", "Assertions", "Good: assertions", Severity.INFO),
            (r"reinterpret_cast|const_cast|dynamic_cast|static_cast", "Casts", "Use appropriate cast", Severity.INFO),
            (r"sizeof\s*\(", "Sizeof", "Good: sizeof", Severity.INFO),
            # Build tools
            (r"CMake|cmake|Makefile|make|GCC|gcc|g\+\+|Clang|clang|MSVC|Visual Studio|Xcode|Bazel|Buck|Meson|Ninja|vcpkg|conan|cpm\.cmake", "Build tools", "Good: build tools", Severity.INFO),
        ]
        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith('//') or stripped.startswith('/*'):
                continue
            for pattern, message, severity in patterns:
                if re.search(pattern, line):
                    issues.append(self._create_issue(
                        file_path=file_path, line=line_num, message=message,
                        suggestion=message, severity=severity, code_snippet=stripped,
                    ))
        return issues
