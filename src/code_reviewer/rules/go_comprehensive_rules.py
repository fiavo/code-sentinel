"""
Comprehensive Go-specific rules.
"""
import re
from ..core.models import CodeIssue, Severity, IssueCategory
from ..core.rules import BaseRule


class GoComprehensiveRules(BaseRule):
    @property
    def name(self) -> str:
        return "go_comprehensive"
    @property
    def description(self) -> str:
        return "Go-specific comprehensive rules"
    @property
    def category(self) -> IssueCategory:
        return IssueCategory.BEST_PRACTICE
    @property
    def severity(self) -> Severity:
        return Severity.INFO

    def check(self, file_path: str, content: str) -> list[CodeIssue]:
        if not file_path.endswith('.go'):
            return []
        issues = []
        lines = content.splitlines()
        patterns = [
            (r"func\s+\w+", "Function definition", "Good: using functions", Severity.INFO),
            (r"type\s+\w+\s+struct", "Struct definition", "Good: defining structs", Severity.INFO),
            (r"type\s+\w+\s+interface", "Interface definition", "Good: defining interfaces", Severity.INFO),
            (r"type\s+\w+\s+func", "Function type", "Good: using function types", Severity.INFO),
            (r"package\s+\w+", "Package declaration", "Good: declaring packages", Severity.INFO),
            (r"import\s+\(", "Import block", "Good: using import blocks", Severity.INFO),
            (r"import\s+\"[^\"]+\"", "Import statement", "Good: importing packages", Severity.INFO),
            (r"var\s+\w+\s+\w+", "Variable declaration", "Good: declaring variables", Severity.INFO),
            (r":=", "Short variable declaration", "Good: using short declaration", Severity.INFO),
            (r"defer\s+\w+", "Defer statement", "Good: using defer", Severity.INFO),
            (r"go\s+\w+", "Goroutine", "Good: using goroutines", Severity.INFO),
            (r"chan\s+\w+", "Channel", "Good: using channels", Severity.INFO),
            (r"<-\w+", "Channel receive", "Good: receiving from channel", Severity.INFO),
            (r"\w+\s*<-\s*\w+", "Channel send", "Good: sending to channel", Severity.INFO),
            (r"select\s*\{", "Select statement", "Good: using select", Severity.INFO),
            (r"switch\s+\w+", "Switch statement", "Good: using switch", Severity.INFO),
            (r"case\s+\w+", "Case clause", "Good: using case", Severity.INFO),
            (r"default:", "Default case", "Good: using default case", Severity.INFO),
            (r"if\s+\w+\s*:=\s*\w+", "If with short declaration", "Good: using if with init", Severity.INFO),
            (r"for\s+\w+\s*:=\s*\w+", "For loop", "Good: using for loops", Severity.INFO),
            (r"for\s+\w+\s*range\s+\w+", "Range loop", "Good: using range", Severity.INFO),
            (r"return\s+\w+", "Return statement", "Good: using return", Severity.INFO),
            (r"error\b", "Error type", "Good: handling errors", Severity.INFO),
            (r"\w+\s*,\s*err\s*:=\s*\w+", "Error handling", "Good: checking errors", Severity.INFO),
            (r"if\s+err\s*!=\s*nil\s*\{", "Error check", "Good: checking errors", Severity.INFO),
            (r"fmt\.\w+", "fmt package", "Good: using fmt package", Severity.INFO),
            (r"log\.\w+", "log package", "Good: using log package", Severity.INFO),
            (r"strings\.\w+", "strings package", "Good: using strings package", Severity.INFO),
            (r"strconv\.\w+", "strconv package", "Good: using strconv", Severity.INFO),
            (r"math\.\w+", "math package", "Good: using math package", Severity.INFO),
            (r"sort\.\w+", "sort package", "Good: using sort package", Severity.INFO),
            (r"sync\.\w+", "sync package", "Good: using sync package", Severity.INFO),
            (r"context\.\w+", "context package", "Good: using context", Severity.INFO),
            (r"net/http\.\w+", "net/http package", "Good: using net/http", Severity.INFO),
            (r"database/sql\.\w+", "database/sql", "Good: using database/sql", Severity.INFO),
            (r"io\.\w+", "io package", "Good: using io package", Severity.INFO),
            (r"os\.\w+", "os package", "Good: using os package", Severity.INFO),
            (r"path/filepath\.\w+", "path/filepath", "Good: using path/filepath", Severity.INFO),
            (r"json\.\w+", "encoding/json", "Good: using encoding/json", Severity.INFO),
            (r"testing\.\w+", "testing package", "Good: writing tests", Severity.INFO),
            (r"https?://\w+", "URL reference", "Good: using URLs", Severity.INFO),
            (r"struct\s*\{", "Struct literal", "Good: using structs", Severity.INFO),
            (r"interface\s*\{", "Interface literal", "Good: using interfaces", Severity.INFO),
            (r"\w+\.\w+\(\)", "Method call", "Good: calling methods", Severity.INFO),
            (r"\w+\s*:=\s*\w+\.\w+", "Method assignment", "Good: using methods", Severity.INFO),
            (r"func\s*\(\s*\w+\s+\*\w+\s*\)", "Method receiver", "Good: using receivers", Severity.INFO),
            (r"append\s*\(\s*\w+", "append function", "Good: using append", Severity.INFO),
            (r"make\s*\(\s*\w+", "make function", "Good: using make", Severity.INFO),
            (r"new\s*\(\s*\w+", "new function", "Good: using new", Severity.INFO),
            (r"len\s*\(\s*\w+", "len function", "Good: using len", Severity.INFO),
            (r"cap\s*\(\s*\w+", "cap function", "Good: using cap", Severity.INFO),
            (r"close\s*\(\s*\w+", "close function", "Good: closing channels", Severity.INFO),
            (r"panic\s*\(\s*\w+", "panic call", "Avoid panic in production", Severity.WARNING),
            (r"recover\s*\(\s*\)", "recover call", "Good: recovering from panics", Severity.INFO),
            (r"goroutine\s+leak", "Goroutine leak", "Ensure goroutines are cleaned up", Severity.WARNING),
            (r"time\.\w+", "time package", "Good: using time package", Severity.INFO),
            (r"reflect\.\w+", "reflect package", "Use reflect sparingly", Severity.INFO),
            (r"unsafe\.\w+", "unsafe package", "Avoid unsafe code", Severity.WARNING),
            (r"cgo", "cgo usage", "Avoid cgo when possible", Severity.INFO),
            (r"//go:generate", "go:generate directive", "Good: using go generate", Severity.INFO),
            (r"//go:build", "go:build constraint", "Good: using build constraints", Severity.INFO),
            (r"\+build\s+\w+", "Build constraint", "Good: using build constraints", Severity.INFO),
            (r"go\.mod", "go.mod file", "Good: using Go modules", Severity.INFO),
            (r"go\.sum", "go.sum file", "Good: tracking dependencies", Severity.INFO),
            (r"//go:embed", "go:embed directive", "Good: using embed", Severity.INFO),
            (r"t\.Run\(", "Subtest", "Good: using subtests", Severity.INFO),
            (r"t\.Helper\(\)", "Test helper", "Good: marking test helpers", Severity.INFO),
            (r"t\.Parallel\(\)", "Parallel test", "Good: running tests in parallel", Severity.INFO),
            (r"testing\.Short\(\)", "Short test check", "Good: supporting -short flag", Severity.INFO),
            (r"godoc", "Godoc reference", "Good: using godoc", Severity.INFO),
            (r"gofmt", "gofmt", "Good: formatting code", Severity.INFO),
            (r"govet", "go vet", "Good: vetting code", Severity.INFO),
            (r"golangci-lint", "golangci-lint", "Good: using linters", Severity.INFO),
            (r"t\.Errorf?\(", "Test error", "Good: reporting test errors", Severity.INFO),
            (r"t\.Logf?\(", "Test log", "Good: logging in tests", Severity.INFO),
            (r"benchmark", "Benchmark", "Good: benchmarking code", Severity.INFO),
            (r"func\s+Benchmark", "Benchmark function", "Good: writing benchmarks", Severity.INFO),
            (r"func\s+Example", "Example function", "Good: writing examples", Severity.INFO),
            (r"\[\]byte", "Byte slice", "Good: using byte slices", Severity.INFO),
            (r"\[\]string", "String slice", "Good: using string slices", Severity.INFO),
            (r"map\[\w+\]\w+", "Map type", "Good: using maps", Severity.INFO),
            (r"\*\w+", "Pointer", "Good: using pointers", Severity.INFO),
            (r"&\w+", "Address-of", "Good: taking addresses", Severity.INFO),
            (r"\.\*", "Dereference", "Good: dereferencing", Severity.INFO),
            (r"error\s+is\s+nil", "Error is nil", "Good: checking errors", Severity.INFO),
            (r"error\s+!=\s+nil", "Error is not nil", "Good: checking errors", Severity.INFO),
            (r"ioutil\.\w+", "ioutil package (deprecated)", "Use io or os package instead", Severity.WARNING),
            (r"os\.ioutil", "os/ioutil (deprecated)", "Use io or os package instead", Severity.WARNING),
            (r"golang\.org/x/\w+", "golang.org/x package", "Good: using extended packages", Severity.INFO),
            (r"google.golang.org/\w+", "Google API", "Good: using Google APIs", Severity.INFO),
            (r"internal/", "Internal package", "Good: using internal packages", Severity.INFO),
            (r"cmd/\w+", "Command package", "Good: organizing commands", Severity.INFO),
            (r"pkg/\w+", "Package directory", "Good: organizing packages", Severity.INFO),
        ]
        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith('//'):
                continue
            for pattern, message, suggestion, severity in patterns:
                if re.search(pattern, line):
                    issues.append(self._create_issue(
                        file_path=file_path, line=line_num, message=message,
                        suggestion=suggestion, severity=severity, code_snippet=stripped,
                    ))
        return issues
