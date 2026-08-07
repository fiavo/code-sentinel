"""
Go-specific comprehensive rules.
"""
import re
from ..core.models import CodeIssue, Severity, IssueCategory
from ..core.rules import BaseRule


class GoLanguageRules(BaseRule):
    @property
    def name(self) -> str:
        return "go_language"
    @property
    def description(self) -> str:
        return "Go-specific comprehensive patterns"
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
            # Go features
            (r"func\s+\w+\(", "Function definition", "Good: function", Severity.INFO),
            (r"func\s+\(\s*\w+\s+\*?\w+\s*\)\s+\w+\(", "Method definition", "Good: method", Severity.INFO),
            (r"func\s+main\(\)", "Main function", "Good: main function", Severity.INFO),
            (r"func\s+init\(\)", "Init function", "Good: init function", Severity.INFO),
            (r"func\s+Test\w+\(t\s+\*testing\.T\)", "Test function", "Good: test function", Severity.INFO),
            (r"func\s+Example\w+\(", "Example function", "Good: example function", Severity.INFO),
            (r"func\s+Benchmark\w+\(b\s+\*testing\.B\)", "Benchmark function", "Good: benchmark function", Severity.INFO),
            # Go types
            (r"type\s+\w+\s+struct", "Struct type", "Good: struct type", Severity.INFO),
            (r"type\s+\w+\s+interface", "Interface type", "Good: interface type", Severity.INFO),
            (r"type\s+\w+\s+\[\w+\]", "Slice type", "Good: slice type", Severity.INFO),
            (r"type\s+\w+\s+map\[", "Map type", "Good: map type", Severity.INFO),
            (r"type\s+\w+\s+func\(", "Function type", "Good: function type", Severity.INFO),
            (r"type\s+\w+\s+\w+", "Type alias", "Good: type alias", Severity.INFO),
            # Go error handling
            (r"if\s+err\s+!=\s+nil\s*\{", "Error check", "Good: error handling", Severity.INFO),
            (r"return\s+fmt\.Errorf\(", "Error wrapping", "Good: error wrapping", Severity.INFO),
            (r"errors\.New\(|fmt\.Errorf\(", "Error creation", "Good: error creation", Severity.INFO),
            (r"errors\.Is\(|errors\.As\(|errors\.Unwrap\(", "Error inspection", "Good: error inspection", Severity.INFO),
            (r"panic\(|recover\(\)", "Panic/recover", "Use error returns instead", Severity.WARNING),
            # Go concurrency
            (r"goroutine|go\s+\w+\(", "Goroutine", "Good: goroutine", Severity.INFO),
            (r"chan\s+\w+|chan\s+<-|<-chan", "Channel", "Good: channel", Severity.INFO),
            (r"make\(chan\s+", "Channel creation", "Good: channel creation", Severity.INFO),
            (r"select\s*\{", "Select statement", "Good: select", Severity.INFO),
            (r"sync\.Mutex|sync\.RwLock|sync\.WaitGroup|sync\.Once|sync\.Map|sync\.Pool|sync\.Cond", "Sync primitives", "Good: sync primitives", Severity.INFO),
            (r"context\.Background\(\)|context\.TODO\(\)|context\.WithCancel|context\.WithDeadline|context\.WithTimeout|context\.WithValue", "Context", "Good: context usage", Severity.INFO),
            # Go idioms
            (r"if\s+err\s*:=\s*\w+\(.*\);\s*err\s+!=\s+nil", "Short error handling", "Good: short error handling", Severity.INFO),
            (r"defer\s+\w+\(", "Defer statement", "Good: defer usage", Severity.INFO),
            (r"iota", "Iota constant", "Good: iota", Severity.INFO),
            (r"make\(\[\]\w+|make\(map\[|make\(chan\s+", "Make builtin", "Good: make usage", Severity.INFO),
            (r"len\(|cap\(", "Length/capacity", "Good: len/cap", Severity.INFO),
            (r"append\(", "Append builtin", "Good: append", Severity.INFO),
            (r"copy\(", "Copy builtin", "Good: copy", Severity.INFO),
            (r"delete\(", "Delete builtin", "Good: delete", Severity.INFO),
            (r"range\s+\w+", "Range loop", "Good: range loop", Severity.INFO),
            # Go packages
            (r"fmt\.|log\.|os\.|io\.|net\.|http\.|json\.|strings\.|strconv\.|math\.|sort\.|time\.|sync\.|context\.|errors\.|path\.|filepath\.|regexp\.|testing\.|bufio\.|bytes\.|encoding\.|crypto\.|database\.|reflect\.|unsafe\.|runtime\.|syscall\.|net/http\.|html/template\.|text/template\.", "Standard library", "Good: standard library usage", Severity.INFO),
            # Go tools
            (r"go\s+build|go\s+run|go\s+test|go\s+vet|go\s+fmt|goimports|golangci-lint|golint|staticcheck|errcheck|ineffassign|gosimple|unused|goconst|gosec|deepcopy|go-critic|revive|bodyclose|noctx|exhaustive|exhaustivestruct|errorlint|forcetypeassert|godot|goheader|gomnd|gomoddirectives|gomodguard|goprintffuncname|nakedret|nestif|nlreturn|prealloc|predeclared|promltp|tagliatelle|thelper|varnamelen|wastedassign|whitespace|wrapcheck|wsl", "Go tools", "Good: Go tools", Severity.INFO),
            # Go modules
            (r"module\s+\w+", "Module declaration", "Good: module declaration", Severity.INFO),
            (r"require\s+\w+", "Require directive", "Good: require directive", Severity.INFO),
            (r"go\s+\d+\.\d+", "Go version", "Good: Go version", Severity.INFO),
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
