"""
Expanded multi-language code review rules.
Covers: JavaScript/TypeScript, Java, C/C++, Go, Rust
Each language has comprehensive patterns for common errors, security issues,
performance problems, and best practices violations.
"""

import re
from typing import Optional

from ..core.models import CodeIssue, Severity, IssueCategory
from ..core.rules import BaseRule


class JavaScriptRules(BaseRule):
    """JavaScript/TypeScript common errors and best practices."""

    @property
    def name(self) -> str:
        return "javascript"

    @property
    def description(self) -> str:
        return "JavaScript/TypeScript error detection"

    @property
    def category(self) -> IssueCategory:
        return IssueCategory.STYLE

    @property
    def severity(self) -> Severity:
        return Severity.ERROR

    def check(self, file_path: str, content: str) -> list[CodeIssue]:
        # Skip if not JavaScript/TypeScript code
        js_indicators = ['function ', 'const ', 'let ', 'var ', '=>', 'async ', 'await ', 'console.', 'document.', 'window.', 'undefined', 'null', '===', '!==', 'eval(', 'alert(']
        is_js = any(ind in content for ind in js_indicators)
        if not is_js:
            return []

        issues = []
        lines = content.splitlines()

        patterns = [
            # Comparison errors
            (r'(?<!=)==(?!=)', "Use strict equality (===) instead of ==", "Replace == with === to avoid type coercion bugs", Severity.WARNING),
            (r'!=(?!=)', "Use strict inequality (!==) instead of !=", "Replace != with !== to avoid type coercion bugs", Severity.WARNING),

            # Undefined/null issues
            (r'=\s*undefined\b', "Direct comparison with undefined", "Use typeof x === 'undefined' or x === undefined", Severity.WARNING),
            (r'==\s*null\b', "Loose null comparison", "Use === null || === undefined for explicit checks", Severity.WARNING),
            (r'==\s*undefined\b', "Loose undefined comparison", "Use === undefined for explicit checks", Severity.WARNING),

            # Variable issues
            (r'\bvar\s+', "Use 'let' or 'const' instead of 'var'", "var has function scope; use let/const for block scope", Severity.WARNING),
            (r'(?:let|var)\s+\w+\s*;\s*$', "Uninitialized variable", "Initialize variable or use const", Severity.INFO),
            (r'(?:let|var)\s+(\w+)\s*=\s*(?:let|var)\s+(\w+)', "Chained variable declaration", "Declare variables separately", Severity.INFO),

            # Function issues
            (r'function\s+\w+\s*\([^)]*\)\s*\{[^}]*\breturn\b[^;]*;[^}]*\breturn\b', "Multiple return statements", "Consider simplifying with early returns", Severity.INFO),
            (r'(?:function|=>)\s*\([^)]*\)\s*(?:=>|{)', "Function without error handling", "Add try/catch for error-prone operations", Severity.INFO),

            # Array/Object issues
            (r'new\s+Array\s*\(\s*\)', "Use array literal [] instead of new Array()", "[] is cleaner and faster", Severity.WARNING),
            (r'new\s+Object\s*\(\s*\)', "Use object literal {} instead of new Object()", "{} is cleaner and faster", Severity.WARNING),
            (r'(?:push|unshift)\s*\([^)]+\)\s*\.length', "Checking length after push", "push returns new length; use it directly", Severity.INFO),
            (r'\.length\s*===?\s*0', "Checking .length === 0", "Use .length < 1 or !arr.length for readability", Severity.INFO),

            # Promise issues
            (r'(?:then|catch)\s*\(\s*function', "Promise with old function syntax", "Use arrow functions for cleaner code", Severity.INFO),
            (r'new\s+Promise\s*\(\s*function', "Promise with old function syntax", "Use arrow functions: new Promise((resolve, reject) => ...)", Severity.INFO),
            (r'\.then\s*\(\s*\)', "Empty .then() handler", "Add logic or remove the empty handler", Severity.INFO),
            (r'\.catch\s*\(\s*\)', "Empty .catch() handler", "Handle errors or log them", Severity.WARNING),

            # DOM issues
            (r'getElementById\s*\(', "Use querySelector instead", "querySelector is more flexible and consistent", Severity.INFO),
            (r'getElementsByClassName\s*\(', "Use querySelectorAll instead", "querySelectorAll is more flexible", Severity.INFO),
            (r'getElementsByTagName\s*\(', "Use querySelectorAll instead", "querySelectorAll is more flexible", Severity.INFO),
            (r'document\.write\s*\(', "Use DOM manipulation instead of document.write", "document.write can cause performance issues", Severity.WARNING),
            (r'innerHTML\s*=', "Use textContent or innerHTML carefully", "innerHTML can cause XSS vulnerabilities", Severity.WARNING),
            (r'outerHTML\s*=', "Use textContent instead of outerHTML", "outerHTML can cause XSS vulnerabilities", Severity.WARNING),

            # Event issues
            (r'addEventListener\s*\([^)]+\)(?!.*removeEventListener)', "Event listener without cleanup", "Remove event listeners when component is destroyed", Severity.INFO),
            (r'onclick\s*=', "Inline event handler", "Use addEventListener for better separation of concerns", Severity.INFO),
            (r'onafterprint\s*=', "Inline event handler", "Use addEventListener instead", Severity.INFO),

            # Timer issues
            (r'setTimeout\s*\(\s*["\']', "setTimeout with string - code injection risk", "Pass a function reference instead", Severity.WARNING),
            (r'setInterval\s*\(\s*["\']', "setInterval with string - code injection risk", "Pass a function reference instead", Severity.WARNING),
            (r'setTimeout\s*\([^,]+\)', "setTimeout without delay", "Specify delay parameter explicitly", Severity.INFO),

            # eval issues
            (r'\beval\s*\(', "eval() usage - security risk", "Avoid eval(); use JSON.parse() or safe alternatives", Severity.CRITICAL),
            (r'new\s+Function\s*\(', "Function constructor - code injection risk", "Use function expressions instead", Severity.WARNING),
            (r'setTimeout\s*\(\s*\w+\s*,', "setTimeout with variable", "Ensure variable is not user-controlled", Severity.INFO),

            # JSON issues
            (r'JSON\.parse\s*\(', "JSON.parse without error handling", "Wrap in try/catch for malformed JSON", Severity.INFO),
            (r'JSON\.stringify\s*\(', "JSON.stringify without error handling", "Wrap in try/catch for circular references", Severity.INFO),

            # String issues
            (r'(?:\+\s*["\']|["\']\s*\+)', "String concatenation", "Use template literals for cleaner code", Severity.INFO),
            (r'(?:split|join)\s*\(\s*["\']\\n["\']\s*\)', "Splitting by newline", "Consider using .split(/\\r?\\n/) for cross-platform", Severity.INFO),

            # Regex issues
            (r'new\s+RegExp\s*\(', "Dynamic regex creation", "Ensure regex is safe from ReDoS attacks", Severity.INFO),
            (r'(?:match|test|replace)\s*\(\s*["\'][^"\']*\$', "Regex with $ anchor", "Test for catastrophic backtracking", Severity.INFO),

            # Type issues
            (r'typeof\s+\w+\s*===?\s*["\']undefined["\']', "typeof check for undefined", "Use x === undefined for clarity", Severity.INFO),
            (r'(?:===|!==)\s*(?:NaN|Infinity)', "Comparing with NaN/Infinity", "Use isNaN() or Number.isNaN()", Severity.WARNING),
            (r'parseInt\s*\(\s*[^,]+\)', "parseInt without radix", "Always specify radix: parseInt(str, 10)", Severity.WARNING),
            (r'parseFloat\s*\(\s*[^)]+\)', "parseFloat usage", "Consider using Number() for stricter parsing", Severity.INFO),

            # Module issues
            (r'require\s*\(\s*["\'][^"\']+["\']\s*\)', "CommonJS require", "Consider using ES6 import syntax", Severity.INFO),
            (r'module\.exports\s*=', "CommonJS exports", "Consider using ES6 export syntax", Severity.INFO),

            # Error handling
            (r'catch\s*\(\s*\w+\s*\)', "Caught error not used", "Log or handle the error properly", Severity.INFO),
            (r'\.catch\s*\(\s*\)', "Empty catch handler", "Add error handling logic", Severity.WARNING),

            # Console statements
            (r'console\.(?:log|warn|error|info|debug)\s*\(', "Console statement in code", "Remove console statements in production", Severity.WARNING),
            (r'console\.table\s*\(', "console.table in code", "Remove console.table in production", Severity.INFO),

            # Deprecated APIs
            (r'(?:arguments|callee|caller)\b', "Deprecated arguments/caller/callee", "Use rest parameters or named arguments", Severity.WARNING),
            (r'(?:with|void)\s*\(', "Deprecated with/void statement", "Avoid using deprecated statements", Severity.WARNING),
            (r'(?:__proto__|__defineGetter__|__defineSetter__)', "Deprecated __proto__ methods", "Use Object.defineProperty instead", Severity.WARNING),
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


class JavaRules(BaseRule):
    """Java common errors and best practices."""

    @property
    def name(self) -> str:
        return "java"

    @property
    def description(self) -> str:
        return "Java error detection"

    @property
    def category(self) -> IssueCategory:
        return IssueCategory.STYLE

    @property
    def severity(self) -> Severity:
        return Severity.ERROR

    def check(self, file_path: str, content: str) -> list[CodeIssue]:
        # Skip if not Java code
        java_indicators = ['public class', 'private ', 'protected ', 'import java', 'System.out', 'System.exit', 'new ', 'void ', 'String ', 'int ', 'boolean ', 'throws ', 'implements ', 'extends ']
        is_java = any(ind in content for ind in java_indicators)
        if not is_java:
            return []

        issues = []
        lines = content.splitlines()

        patterns = [
            # String comparison
            (r'(?:if|while|for)\s*\(.*[^!=<>]==\s*["\']', "String comparison with ==", "Use .equals() or .compareTo() for string comparison", Severity.WARNING),
            (r'(?:if|while|for)\s*\(.*[^!=<>]!=\s*["\']', "String comparison with !=", "Use !.equals() for string comparison", Severity.WARNING),
            (r'(?:if|while|for)\s*\(.*\.toString\s*\(\s*\)\s*==', "String comparison after toString", "Use .equals() directly", Severity.WARNING),

            # Resource management
            (r'(?:FileInputStream|FileOutputStream|BufferedReader|BufferedWriter|Connection|Statement|ResultSet)\s+\w+\s*=\s*new', "Resource without try-with-resources", "Use try-with-resources for automatic cleanup", Severity.WARNING),
            (r'(?:Scanner|InputStream|OutputStream)\s+\w+\s*=\s*new', "Resource without try-with-resources", "Use try-with-resources", Severity.WARNING),

            # Null pointer issues
            (r'\.length\s*\(\s*\)', "String.length() usage", "Use .isEmpty() for emptiness checks", Severity.INFO),
            (r'(?:if|while)\s*\(\s*\w+\s*!=\s*null\s*\)', "Manual null check", "Use Optional or Objects.requireNonNull()", Severity.INFO),
            (r'(?:if|while)\s*\(\s*\w+\s*==\s*null\s*\)', "Manual null check", "Use Optional or Objects.requireNonNull()", Severity.INFO),
            (r'\.get\s*\(\s*\)', "Collection.get() without bounds check", "Check size() before accessing by index", Severity.INFO),
            (r'(?:HashMap|ArrayList|LinkedList)\s*\(\s*\)', "Unsized collection", "Specify initial capacity if known", Severity.INFO),

            # Exception handling
            (r'catch\s*\(\s*Exception\s+\w+\s*\)', "Catching broad Exception", "Catch more specific exceptions", Severity.WARNING),
            (r'catch\s*\(\s*Throwable\s+\w+\s*\)', "Catching Throwable", "Catch Exception instead", Severity.WARNING),
            (r'(?:printStackTrace|System\.err\.println)', "Using printStackTrace()", "Use proper logging framework", Severity.WARNING),
            (r'(?:e\.getMessage|ex\.getMessage)\s*\(\s*\)', "Using getMessage() for logging", "Use proper logging with stack trace", Severity.INFO),

            # Thread safety
            (r'(?:synchronized|volatile)\s+\w+', "Synchronization keyword used", "Consider using java.util.concurrent classes", Severity.INFO),
            (r'Thread\.sleep\s*\(', "Thread.sleep() usage", "Consider using ScheduledExecutorService", Severity.INFO),
            (r'\.wait\s*\(\s*\)', "Object.wait() without timeout", "Always use wait(timeout) to prevent deadlocks", Severity.WARNING),
            (r'\.notify\s*\(\s*\)', "Object.notify() usage", "Prefer notifyAll() or Condition variables", Severity.INFO),
            (r'(?:HashMap|ArrayList)\s*\(', "Non-thread-safe collection in multi-threaded code", "Use ConcurrentHashMap or CopyOnWriteArrayList", Severity.WARNING),

            # Performance
            (r'(?:String|StringBuffer)\s*\+\s*"', "String concatenation in loop", "Use StringBuilder for better performance", Severity.WARNING),
            (r'(?:for|while)\s*\(.*\+\s*"', "String concatenation in loop", "Use StringBuilder or String.format()", Severity.WARNING),
            (r'\.toString\s*\(\s*\)', "Calling toString() explicitly", "String.valueOf() is null-safe", Severity.INFO),
            (r'(?:Integer|Long|Double|Float)\.valueOf\s*\(\s*\w+\s*\)', "Autoboxing", "Use primitive types when possible", Severity.INFO),

            # Deprecation
            (r'(?:Date|Calendar)\s*\(\s*\)', "Deprecated Date/Calendar usage", "Use java.time API (LocalDate, LocalDateTime)", Severity.WARNING),
            (r'(?:Hashtable|Vector|Stack)\s*\(', "Legacy collection class", "Use ArrayList, HashMap, or Deque", Severity.WARNING),
            (r'(?:Random)\s*\(\s*\)', "java.util.Random usage", "Use SecureRandom for security-sensitive operations", Severity.INFO),

            # Code style
            (r'(?:public|private|protected)\s+(?:static\s+)?(?:final\s+)?\w+\s+[A-Z]\w+\s*[;=]', "Field naming: use camelCase", "Use camelCase for field names", Severity.INFO),
            (r'System\.out\.println\s*\(', "System.out.println in code", "Use logging framework instead", Severity.WARNING),
            (r'System\.exit\s*\(\s*\)', "System.exit() in code", "Avoid System.exit() in libraries", Severity.WARNING),
            (r'(?:String|int|boolean)\s+\w+\s*=\s*(?:null|"")', "Default initialization", "Rely on Java defaults when appropriate", Severity.INFO),

            # Security
            (r'(?:Runtime|ProcessBuilder)\s*\.getRuntime\s*\(\s*\)\s*\.exec', "Runtime.exec() usage", "Use ProcessBuilder with restricted environment", Severity.WARNING),
            (r'(?:ObjectInputStream|readObject)\s*\(', "Deserialization", "Validate and restrict deserialized objects", Severity.CRITICAL),
            (r'(?:XMLDecoder)\s*\(', "XMLDecoder usage", "XMLDecoder can execute arbitrary code", Severity.CRITICAL),
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


class CppRules(BaseRule):
    """C/C++ common errors and best practices."""

    @property
    def name(self) -> str:
        return "cpp"

    @property
    def description(self) -> str:
        return "C/C++ error detection"

    @property
    def category(self) -> IssueCategory:
        return IssueCategory.STYLE

    @property
    def severity(self) -> Severity:
        return Severity.ERROR

    def check(self, file_path: str, content: str) -> list[CodeIssue]:
        # Skip if not C/C++ code
        cpp_indicators = ['#include', 'int main', 'void ', 'malloc(', 'free(', 'printf(', 'scanf(', 'strlen(', '#define', 'struct ', 'typedef ', 'gets(', 'strcpy(', 'strcat(', 'sprintf(', 'char *', 'int *', 'NULL', 'sizeof(']
        is_cpp = any(ind in content for ind in cpp_indicators)
        if not is_cpp:
            return []

        issues = []
        lines = content.splitlines()

        patterns = [
            # Buffer overflow
            (r'\bgets\s*\(', "gets() - buffer overflow vulnerability", "Use fgets() or getline()", Severity.CRITICAL),
            (r'\bstrcpy\s*\(', "strcpy() - no bounds checking", "Use strncpy() or strlcpy()", Severity.WARNING),
            (r'\bstrcat\s*\(', "strcat() - no bounds checking", "Use strncat() or strlcat()", Severity.WARNING),
            (r'\bsprintf\s*\(', "sprintf() - buffer overflow risk", "Use snprintf() instead", Severity.WARNING),
            (r'\bvsprintf\s*\(', "vsprintf() - buffer overflow risk", "Use vsnprintf() instead", Severity.WARNING),
            (r'\bgets\s*\(', "gets() removed in C11", "Use fgets() or getline()", Severity.CRITICAL),
            (r'\bscanf\s*\(\s*"%s"', "scanf with %s - no width limit", "Use %ns format specifier to limit width", Severity.WARNING),
            (r'\bsscanf\s*\(\s*[^,]+,\s*"%s"', "sscanf with %s - no width limit", "Use %ns format specifier", Severity.WARNING),

            # Memory management
            (r'\bmalloc\s*\([^)]*\)\s*;', "malloc() without null check", "Check for NULL before using allocated memory", Severity.WARNING),
            (r'\bcalloc\s*\([^)]*\)\s*;', "calloc() without null check", "Check for NULL before using allocated memory", Severity.WARNING),
            (r'\brealloc\s*\([^)]*\)\s*;', "realloc() without null check", "Check for NULL; old memory may be lost on failure", Severity.WARNING),
            (r'\bfree\s*\(\s*\w+\s*\)\s*;', "free() without null check", "Check for NULL before freeing", Severity.INFO),
            (r'free\s*\(\s*\w+\s*\)\s*\n\s*\w+\s*=', "Using pointer after free", "Set pointer to NULL after free", Severity.WARNING),
            (r'free\s*\(\s*\w+\s*\).*\n.*\1', "Double free possible", "Avoid double free; set pointer to NULL", Severity.CRITICAL),
            (r'malloc\s*\([^)]*\)\s*\n(?:[^;]*\n)*?\s*free', "malloc followed by early free", "Ensure proper memory lifecycle", Severity.INFO),

            # Null pointer
            (r'\bNULL\b', "NULL usage", "Use nullptr in C++ for type safety", Severity.INFO),
            (r'\bnullptr\b', "nullptr usage (C++)", "Good: using type-safe nullptr", Severity.INFO),
            (r'(?:int|char|void)\s*\*\s*\w+\s*;', "Uninitialized pointer", "Initialize pointers to NULL or nullptr", Severity.WARNING),
            (r'0\s*\)', "Using 0 as null pointer", "Use NULL or nullptr", Severity.INFO),
            (r'(?:if|while)\s*\(\s*!\s*\w+\s*\)', "Checking pointer with !", "Compare with NULL/nullptr explicitly", Severity.INFO),

            # Type safety
            (r'\(void\s*\*\)', "Casting to void*", "Avoid void* casts when possible", Severity.INFO),
            (r'\(char\s*\*\)', "Casting to char*", "Use const char* when possible", Severity.INFO),
            (r'\(int\s*\)', "Casting to int", "Use proper type casting", Severity.INFO),
            (r'\(unsigned\)', "Unsigned conversion", "Be careful with unsigned arithmetic", Severity.INFO),
            (r'\bchar\b.*=\s*\d+\s*;', "Char assigned to integer", "Use proper character constants", Severity.INFO),

            # Dangerous functions
            (r'\bstrcpy\s*\(', "strcpy() - deprecated", "Use strncpy() or string class", Severity.WARNING),
            (r'\bstrncpy\s*\(', "strncpy() - may not null-terminate", "Ensure null termination", Severity.WARNING),
            (r'\bstrcat\s*\(', "strcat() - deprecated", "Use strncat() or string class", Severity.WARNING),
            (r'\bstrncat\s*\(', "strncat() - complex sizing", "Consider using string class", Severity.INFO),
            (r'\bsprintf\s*\(', "sprintf() - unsafe", "Use snprintf()", Severity.WARNING),
            (r'\bvsprintf\s*\(', "vsprintf() - unsafe", "Use vsnprintf()", Severity.WARNING),
            (r'\batoi\s*\(', "atoi() - no error handling", "Use strtol() with error checking", Severity.WARNING),
            (r'\batof\s*\(', "atof() - no error handling", "Use strtod() with error checking", Severity.WARNING),
            (r'\batox\s*\(', "atoi/atof family - no error handling", "Use strtol/strtod family", Severity.WARNING),

            # Undefined behavior
            (r'(?:>>|<<)\s*\w+\s*>>', "Shift by negative or large amount", "Ensure shift amount is valid (0-31 for int)", Severity.WARNING),
            (r'\bint\b\s+\w+\s*=\s*\d{10,}', "Integer overflow possible", "Use long long or int64_t for large values", Severity.WARNING),
            (r'(?:\/|%)', "Division/modulo", "Check for division by zero", Severity.INFO),
            (r'(?:\+\+|\-\-)\s*\w+.*(?:\+\+|\-\-)', "Multiple side effects in expression", "Separate side effects for clarity", Severity.WARNING),
            (r'\w+\s*(?:\+\+|\-\-)\s*\w+', "Multiple side effects", "Separate side effects into statements", Severity.WARNING),

            # Resource management
            (r'\bfopen\s*\(', "fopen() without null check", "Check for NULL before using FILE*", Severity.WARNING),
            (r'\bfclose\s*\(', "fclose() usage", "Ensure fclose() is called on all paths", Severity.INFO),
            (r'\bopen\s*\(\s*[^,]+,\s*[^,]+\s*\)', "open() without mode check", "Use appropriate file permissions", Severity.INFO),
            (r'\bsocket\s*\(', "socket() without error check", "Check for invalid socket descriptor", Severity.INFO),

            # Preprocessor issues
            (r'#define\s+\w+\s+\d+', "Magic number in macro", "Use named constant instead", Severity.INFO),
            (r'#define\s+\w+\([^)]*\)\s+\w+', "Function-like macro", "Consider using inline function", Severity.INFO),
            (r'#include\s*<.*\.h>', "C-style header in C++", "Use C++ headers (<cstring> instead of <string.h>)", Severity.INFO),
            (r'using namespace std', "using namespace std", "Avoid in header files; use specific qualifiers", Severity.WARNING),

            # Modern C++ (C++11 and later)
            (r'\bNULL\b', "NULL in C++", "Use nullptr", Severity.INFO),
            (r'(?:auto|decltype)\s+\w+\s*=\s*\w+', "Auto type deduction", "Good: using modern C++ features", Severity.INFO),
            (r'(?:range-based|for\s*\(\s*auto)', "Range-based for loop", "Good: using modern C++ features", Severity.INFO),
        ]

        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith('//') or stripped.startswith('/*'):
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


class GoRules(BaseRule):
    """Go common errors and best practices."""

    @property
    def name(self) -> str:
        return "go"

    @property
    def description(self) -> str:
        return "Go error detection"

    @property
    def category(self) -> IssueCategory:
        return IssueCategory.STYLE

    @property
    def severity(self) -> Severity:
        return Severity.ERROR

    def check(self, file_path: str, content: str) -> list[CodeIssue]:
        # Skip if not Go code
        go_indicators = ['package ', 'func ', 'import (', 'fmt.', 'context.', 'go func', 'chan ', 'error', ':=', 'goroutine']
        is_go = any(ind in content for ind in go_indicators)
        if not is_go:
            return []

        issues = []
        lines = content.splitlines()

        patterns = [
            # Error handling
            (r'(?:result|_)\s*,\s*_\s*:=\s*\w+', "Ignoring error return value", "Handle all errors properly", Severity.WARNING),
            (r'(?:result|_)\s*:=\s*\w+\([^)]*\)\s*$', "Error not checked", "Always check error return values", Severity.WARNING),
            (r'_\s*=\s*\w+\([^)]*\)', "Assigning to blank identifier", "Ensure this is intentional", Severity.INFO),
            (r'err\s*!=\s*nil\s*\{[^}]*\}', "Error handled", "Good: checking error return", Severity.INFO),
            (r'if\s+err\s*:=\s*\w+', "Error in if statement", "Good: inline error check", Severity.INFO),

            # Goroutine issues
            (r'go\s+func\s*\(', "Goroutine launched", "Ensure goroutine lifecycle is managed", Severity.INFO),
            (r'go\s+\w+\s*\(', "Goroutine launched", "Ensure goroutine lifecycle is managed", Severity.INFO),
            (r'(?:WaitGroup|sync\.WaitGroup)', "WaitGroup usage", "Good: managing goroutine synchronization", Severity.INFO),

            # Channel issues
            (r'(?:make|chan)\s*\(\s*chan', "Channel creation", "Ensure channel is properly closed", Severity.INFO),
            (r'(?:<-|chan\s+\w+)', "Channel operation", "Good: using channels", Severity.INFO),
            (r'(?:range|for)\s+\w+\s*:=\s*range\s+\w+', "Range over channel", "Ensure channel is closed to avoid deadlock", Severity.INFO),

            # Context issues
            (r'context\.TODO\s*\(\s*\)', "context.TODO() placeholder", "Replace with proper context", Severity.WARNING),
            (r'context\.Background\s*\(\s*\)', "context.Background() usage", "Ensure context is properly propagated", Severity.INFO),
            (r'context\.WithCancel\s*\(', "Context with cancel", "Ensure cancel is called to prevent leaks", Severity.INFO),
            (r'context\.WithTimeout\s*\(', "Context with timeout", "Good: adding timeout to context", Severity.INFO),

            # Defer issues
            (r'defer\s+\w+\s*\(', "Defer statement", "Ensure deferred function handles errors", Severity.INFO),
            (r'defer\s+func\s*\(\s*\)', "Deferred anonymous function", "Consider extracting to named function", Severity.INFO),

            # String issues
            (r'(?:fmt\.Sprintf|fmt\.Printf)\s*\(\s*"', "fmt.Sprintf/Printf with format string", "Use fmt.Sprintf for formatting", Severity.INFO),
            (r'fmt\.Print\s*\(', "fmt.Print in production code", "Use logging instead", Severity.WARNING),
            (r'fmt\.Println\s*\(', "fmt.Println in production code", "Use logging instead", Severity.WARNING),
            (r'(?:log|fmt)\.(?:Print|Printf|Println)\s*\(', "fmt.Print/log.Print usage", "Consider using structured logging", Severity.INFO),

            # Interface issues
            (r'interface\s*\{\s*\}', "Empty interface", "Use specific types when possible", Severity.INFO),
            (r'\.\(\*?\w+\)', "Type assertion", "Use type switch or ok pattern for safe assertion", Severity.WARNING),

            # Slice/Map issues
            (r'make\s*\(\s*\[\]\w+\s*,\s*0\s*\)', "make([]type, 0)", "Use var s []type or s := []type{} instead", Severity.INFO),
            (r'(?:len|cap)\s*\(\s*\w+\s*\)\s*==\s*0', "len() == 0 check", "Use len(s) == 0 directly", Severity.INFO),

            # Mutex issues
            (r'sync\.Mutex\s*\(', "Mutex created", "Ensure consistent lock ordering", Severity.INFO),
            (r'\.Lock\s*\(\s*\)', "Lock acquired", "Good: protecting shared state", Severity.INFO),
            (r'\.Unlock\s*\(\s*\)', "Lock released", "Good: releasing lock", Severity.INFO),
            (r'(?:RWMutex|sync\.RWMutex)', "RWMutex usage", "Good: using read-write mutex", Severity.INFO),

            # Package issues
            (r'package\s+main\s*\n.*package\s+main', "Multiple package main declarations", "Only one main package per binary", Severity.WARNING),
            (r'import\s+\(\s*\n(?:\s+.*\n){10,}', "Many imports", "Consider if all imports are necessary", Severity.INFO),
            (r'(?:import|from)\s+["\'][^"\']+["\']', "Import statement", "Ensure imports are necessary", Severity.INFO),
        ]

        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith('//') or stripped.startswith('/*'):
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


class RustRules(BaseRule):
    """Rust common errors and best practices."""

    @property
    def name(self) -> str:
        return "rust"

    @property
    def description(self) -> str:
        return "Rust error detection"

    @property
    def category(self) -> IssueCategory:
        return IssueCategory.STYLE

    @property
    def severity(self) -> Severity:
        return Severity.ERROR

    def check(self, file_path: str, content: str) -> list[CodeIssue]:
        # Skip if not Rust code
        rust_indicators = ['fn ', 'let ', 'mut ', 'impl ', 'pub ', 'use ', 'mod ', 'match ', 'enum ', 'struct ', 'trait ', 'unsafe ', '.unwrap(', 'println!', 'todo!()', 'panic!()']
        is_rust = any(ind in content for ind in rust_indicators)
        if not is_rust:
            return []

        issues = []
        lines = content.splitlines()

        patterns = [
            # Unwrap issues
            (r'\.unwrap\s*\(\s*\)', "unwrap() can panic", "Use ? operator or match for error handling", Severity.WARNING),
            (r'\.expect\s*\(', "expect() can panic", "Use ? operator for error propagation", Severity.INFO),
            (r'\.unwrap_or\s*\(', "unwrap_or() usage", "Good: providing fallback value", Severity.INFO),
            (r'\.unwrap_or_else\s*\(', "unwrap_or_else() usage", "Good: providing fallback function", Severity.INFO),
            (r'\.unwrap_or_default\s*\(', "unwrap_or_default() usage", "Good: using default value", Severity.INFO),

            # Panic issues
            (r'panic!\s*\(', "panic!() usage", "Use Result type for error handling", Severity.WARNING),
            (r'unimplemented!\s*\(\s*\)', "unimplemented!() macro", "Implement the functionality or return error", Severity.WARNING),
            (r'todo!\s*\(\s*\)', "todo!() placeholder", "Implement the functionality", Severity.WARNING),
            (r'unreachable!\s*\(\s*\)', "unreachable!() macro", "Ensure this code path is truly unreachable", Severity.INFO),

            # Unsafe issues
            (r'unsafe\s*\{', "Unsafe block", "Minimize unsafe code; add safety comments", Severity.WARNING),
            (r'unsafe\s+fn\s+', "Unsafe function", "Document safety requirements in doc comments", Severity.WARNING),
            (r'(?:as\s+\*mut|as\s+\*const)', "Raw pointer cast", "Ensure pointer validity", Severity.WARNING),
            (r'deref\s*::\s*deref', "Manual deref", "Consider using Deref trait implementation", Severity.INFO),

            # Lifetime issues
            (r"'[a-z]+\s+'", "Lifetime annotation", "Good: using lifetime annotations", Severity.INFO),
            (r'(?:&|&mut)\s+\w+\s+\'[a-z]+', "Lifetime reference", "Good: explicit lifetime", Severity.INFO),
            (r'(?:impl|fn)\s+\w+.*\'a', "Lifetime 'a", "Good: using named lifetime", Severity.INFO),

            # Clone/Move issues
            (r'\.clone\s*\(\s*\)', "clone() usage", "Consider using references instead of cloning", Severity.INFO),
            (r'\.to_owned\s*\(\s*\)', "to_owned() usage", "Consider using references when possible", Severity.INFO),
            (r'\.to_string\s*\(\s*\)', "to_string() usage", "Consider using Cow<str> for conditional allocation", Severity.INFO),
            (r'\.into\s*\(\s*\)', ".into() conversion", "Ensure type conversion is infallible", Severity.INFO),

            # Iterator issues
            (r'\.collect\s*\(\s*\)\s*:\s*Vec', "collect() to Vec", "Consider using iterator directly when possible", Severity.INFO),
            (r'\.map\s*\(\s*\|', "map() usage", "Good: using functional style", Severity.INFO),
            (r'\.filter\s*\(\s*\|', "filter() usage", "Good: using functional style", Severity.INFO),
            (r'\.for_each\s*\(\s*\|', "for_each() usage", "Good: using functional style", Severity.INFO),
            (r'\.iter\s*\(\s*\).*\.collect\s*\(\s*\)', "iter().collect()", "Consider using iterator adapter chain", Severity.INFO),

            # Concurrency issues
            (r'(?:Arc|Mutex|RwLock)\s*<', "Concurrency primitive usage", "Good: using proper synchronization", Severity.INFO),
            (r'(?:thread|tokio)\.spawn\s*\(', "Thread/task spawned", "Ensure proper error handling for spawned tasks", Severity.INFO),
            (r'send\s*\(\s*\)', "Channel send", "Ensure channel is not closed", Severity.INFO),
            (r'recv\s*\(\s*\)', "Channel receive", "Handle channel closure properly", Severity.INFO),

            # Error handling
            (r'\?\s*;', "Error propagation with ?", "Good: using ? operator", Severity.INFO),
            (r'Box<dyn\s+(?:Error|std::error::Error)>', "Boxed error type", "Consider using thiserror or anyhow crate", Severity.INFO),
            (r'(?:anyhow|thiserror)', "Error handling crate", "Good: using established error handling patterns", Severity.INFO),

            # Macro issues
            (r'(?:vec!|format!|println!|eprintln!|write!|writeln!)', "Macro usage", "Good: using standard macros", Severity.INFO),
            (r'(?:derive|macro_use)', "Derive/macro_use attribute", "Good: using derive macros", Severity.INFO),

            # Pattern matching
            (r'match\s+\w+\s*\{', "match expression", "Good: using pattern matching", Severity.INFO),
            (r'(?:if let|while let)', "if let/while let", "Good: using destructuring", Severity.INFO),

            # Module issues
            (r'mod\s+\w+\s*;', "Module declaration", "Ensure module file exists", Severity.INFO),
            (r'use\s+\w+::\w+', "Use statement", "Good: using proper imports", Severity.INFO),
        ]

        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith('//') or stripped.startswith('/*'):
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


# ============================================================================
# COMPREHENSIVE PATTERNS DATABASE
# ============================================================================

class ComprehensivePythonExtraRules(BaseRule):
    """Extra Python patterns for comprehensive coverage."""

    @property
    def name(self) -> str:
        return "python_extra"

    @property
    def description(self) -> str:
        return "Extra Python patterns"

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
            (r'(?:import|from)\s+typing', "typing module import", "Good: using typing module", Severity.INFO),
            (r'(?:Protocol|runtime_checkable|TypedDict|NamedTuple|Literal|Final|TypeAlias|TypeVar|Generic)', "Advanced typing", "Good: using advanced typing", Severity.INFO),
            (r'(?:dataclass|@dataclass)', "Dataclass", "Good: using dataclasses", Severity.INFO),
            (r'(?:field|Field|InitVar|ClassVar|asdict|astuple|fields|isdataclass)', "Dataclass utilities", "Good: using dataclass utilities", Severity.INFO),
            (r'(?:contextmanager|asynccontextmanager|contextlib|suppress|redirect_stdout|redirect_stderr|ExitStack|closing|chdir|nullcontext)', "Contextlib", "Good: using contextlib", Severity.INFO),
            (r'(?:lru_cache|cache|cached_property|partial|reduce|wraps|total_ordering|cmp_to_key|singledispatch)', "Functools", "Good: using functools", Severity.INFO),
            (r'(?:chain|groupby|product|combinations|permutations|starmap|filterfalse|islice|tee|accumulate|compress|cycle|repeat|count|chain.from_iterable|combinations_with_replacement|permutations)', "Itertools", "Good: using itertools", Severity.INFO),
            (r'(?:defaultdict|OrderedDict|Counter|ChainMap|deque|UserDict|UserList|UserString)', "Collections", "Good: using collections", Severity.INFO),
            (r'(?:abc|ABCMeta|ABCMeta|abstractmethod|abstractproperty|abstractstaticmethod|abstractclassmethod)', "ABC module", "Good: using ABC module", Severity.INFO),
            (r'(?:re\.match|re\.search|re\.findall|re\.finditer|re\.sub|re\.subn|re\.compile|re\.escape|re\.split|re\.fullmatch|re\.PURCASE|re\.IGNORECASE|re\.MULTILINE|re\.DOTALL|re\.VERBOSE|re\.ASCII|re\.UNICODE)', "Regex operations", "Good: using regex module", Severity.INFO),
            (r'(?:json\.load|json\.dump|json\.loads|json\.dumps|json\.decoder|json\.encoder|json\.JSONDecodeError|json\.JSONEncoder)', "JSON handling", "Good: using JSON module", Severity.INFO),
            (r'(?:pathlib\.|Path\s*\(|PurePath|PurePosixPath|PureWindowsPath|PosixPath|WindowsPath|Path\.home|Path\.cwd|Path\.resolve|Path\.exists|Path\.is_file|Path\.is_dir|Path\.mkdir|Path\.unlink|Path\.rename|Path\.glob|Path\.rglob|Path\.read_text|Path\.write_text|Path\.read_bytes|Path\.write_bytes|Path\.stat|Path\.chmod|Path\.symlink_to|Path\.resolve|Path\.absolute|Path\.parent|Path\.name|Path\.stem|Path\.suffix|Path\.suffixes|Path\.parts|Path\.as_posix|Path\.as_uri|Path\.with_name|Path\.with_suffix|Path\.match|Path\.relative_to)', "Pathlib", "Good: using pathlib", Severity.INFO),
            (r'(?:os\.path\.join|os\.path\.exists|os\.path\.isfile|os\.path\.isdir|os\.path\.basename|os\.path\.dirname|os\.path\.splitext|os\.path\.abspath|os\.path\.relpath|os\.path\.normpath|os\.path\.realpath|os\.path\.getsize|os\.path\.getmtime|os\.path\.getatime|os\.path\.getctime)', "os.path", "Good: using os.path", Severity.INFO),
            (r'(?:glob\.glob|glob\.iglob|glob\.escape|fnmatch\.fnmatch|fnmatch\.filter|fnmatch\.translate)', "Glob/fnmatch", "Good: using glob/fnmatch", Severity.INFO),
            (r'(?:shutil\.copy|shutil\.copy2|shutil\.copytree|shutil\.move|shutil\.rmtree|shutil\.disk_usage|shutil\.make_archive|shutil\.unpack_archive|shutil\.which|shutil\.get_terminal_size|shutil\.chown|shutil\.samefile|shutil\.ignore_patterns)', "Shutil", "Good: using shutil", Severity.INFO),
            (r'(?:tempfile\.mkdtemp|tempfile\.mkstemp|tempfile\.NamedTemporaryFile|tempfile\.TemporaryDirectory|tempfile\.SpooledTemporaryFile|tempfile\.tempdir)', "Tempfile", "Good: using tempfile", Severity.INFO),
            (r'(?:csv\.reader|csv\.writer|csv\.DictReader|csv\.DictWriter|csv\.excel|csv\.excel_tab|csv\.Sniffer)', "CSV handling", "Good: using csv module", Severity.INFO),
            (r'(?:xml\.etree\.ElementTree|xml\.dom\.minidom|xml\.dom\.pulldom|xml\.sax|xml\.parsers\.expat|xml\.rpc|xml\.etree\.ElementTree\.parse|xml\.etree\.ElementTree\.fromstring|xml\.etree\.ElementTree\.tostring|xml\.etree\.ElementTree\.SubElement|xml\.etree\.ElementTree\.ElementTree|xml\.etree\.ElementTree\.Element|xml\.etree\.ElementTree\.Comment|xml\.etree\.ElementTree\.ProcessingInstruction)', "XML handling", "Good: using XML module", Severity.INFO),
            (r'(?:hashlib\.md5|hashlib\.sha1|hashlib\.sha224|hashlib\.sha256|hashlib\.sha384|hashlib\.sha512|hashlib\.blake2b|hashlib\.blake2s|hashlib\.pbkdf2_hmac|hashlib\.shake_128|hashlib\.shake_256|hashlib\.new|hashlib\.file_digest)', "Hashing", "Good: using hashlib", Severity.INFO),
            (r'(?:hmac\.new| hmac\.compare_digest|hmac\.HMAC)', "HMAC", "Good: using hmac module", Severity.INFO),
            (r'(?:base64\.b64encode|base64\.b64decode|base64\.b32encode|base64\.b32decode|base64\.b16encode|base64\.b16decode|base64\.urlsafe_b64encode|base64\.urlsafe_b64decode|base64\.encodebytes|base64\.decodebytes|base64\.a85encode|base64\.a85decode|base64\.b85encode|base64\.b85decode)', "Base64", "Good: using base64 module", Severity.INFO),
            (r'(?:uuid\.uuid1|uuid\.uuid3|uuid\.uuid4|uuid\.uuid5|uuid\.UUID)', "UUID generation", "Good: using uuid module", Severity.INFO),
            (r'(?:decimal\.Decimal|decimal\.getcontext|decimal\.setcontext|decimal\.localcontext)', "Decimal arithmetic", "Good: using decimal for precision", Severity.INFO),
            (r'(?:fractions\.Fraction|fractions\.gcd)', "Fraction arithmetic", "Good: using fractions", Severity.INFO),
            (r'(?:statistics\.mean|statistics\.median|statistics\.mode|statistics\.stdev|statistics\.variance|statistics\.pvariance|statistics\.pstdev|statistics\.NormalDist|statistics\.median_low|statistics\.median_high|statistics\.median_grouped|statistics\.quantiles)', "Statistics", "Good: using statistics module", Severity.INFO),
            (r'(?:math\.pi|math\.e|math\.tau|math\.inf|math\.nan|math\.gcd|math\.lcm|math\.factorial|math\.comb|math\.perm|math\.isfinite|math\.isinf|math\.isnan|math\.ceil|math\.floor|math\.trunc|math\.fsum|math\.prod|math\.log|math\.exp|math\.sqrt|math\.pow|math\.sin|math\.cos|math\.tan|math\.asin|math\.acos|math\.atan|math\.atan2|math\.degrees|math\.radians|math\.hypot|math\.dist|math\.isclose|math\.fmod|math\.modf|math\.frexp|math\.ldexp|math\.copysign|math\.nextafter|math\.ulp)', "Math module", "Good: using math module", Severity.INFO),
            (r'(?:random\.random|random\.randint|random\.randrange|random\.choice|random\.choices|random\.sample|random\.shuffle|random\.seed|random\.getrandbits|random\.uniform|random\.triangular|random\.betavariate|random\.expovariate|random\.gammavariate|random\.gauss|random\.lognormvariate|random\.normalvariate|random\.vonmisesvariate|random\.paretovariate|random\.weibullvariate|random\.random|random\.getstate|random\.setstate|random\.SystemRandom)', "Random module", "Good: using random module", Severity.INFO),
            (r'(?:secrets\.randbelow|secrets\.choice|secrets\.randbits|secrets\.token_bytes|secrets\.token_hex|secrets\.token_urlsafe|secrets\.compare_digest|secrets\.SystemRandom|secrets\.choice)', "Secrets module", "Good: using secrets for security", Severity.INFO),
            (r'(?:logging\.basicConfig|logging\.getLogger|logging\.debug|logging\.info|logging\.warning|logging\.error|logging\.critical|logging\.exception|logging\.fatal|logging\.log|logging\.disable|logging\.captureWarnings|logging\.addLevelName|logging\.getLevelName|logging\.Handler|logging\.StreamHandler|logging\.FileHandler|logging\.RotatingFileHandler|logging\.TimedRotatingFileHandler|logging\.NullHandler|logging\.Formatter|logging\.Filter|logging\.LogRecord|logging\.Manager|logging\.root)', "Logging module", "Good: using logging module", Severity.INFO),
            (r'(?:threading\.Thread|threading\.Lock|threading\.RLock|threading\.Condition|threading\.Event|threading\.Semaphore|threading\.BoundedSemaphore|threading\.Barrier|threading\.Timer|threading\.local|threading\.current_thread|threading\.active_count|threading\.enumerate|threading\.main_thread|threading\.get_ident|threading\.get_native_id|threading\.settrace|threading\.setprofile|threading\.stack_size|threading\.excepthook)', "Threading module", "Good: using threading module", Severity.INFO),
            (r'(?:multiprocessing\.Process|multiprocessing\.Pool|multiprocessing\.Queue|multiprocessing\.Pipe|multiprocessing\.Value|multiprocessing\.Array|multiprocessing\.Manager|multiprocessing\.Lock|multiprocessing\.RLock|multiprocessing\.Condition|multiprocessing\.Event|multiprocessing\.Semaphore|multiprocessing\.BoundedSemaphore|multiprocessing\.Barrier|multiprocessing\.JoinableQueue|multiprocessing\.SimpleQueue|multiprocessing\.current_process|multiprocessing\.active_children|multiprocessing\.cpu_count|multiprocessing\.freeze_support)', "Multiprocessing module", "Good: using multiprocessing module", Severity.INFO),
            (r'(?:asyncio\.run|asyncio\.get_event_loop|asyncio\.get_running_loop|asyncio\.get_event_loop_policy|asyncio\.set_event_loop_policy|asyncio\.new_event_loop|asyncio\.ensure_future|asyncio\.gather|asyncio\.wait|asyncio\.wait_for|asyncio\.create_task|asyncio\.sleep|asyncio\.timeout|asyncio\.shield|asyncio\.Queue|asyncio\.Semaphore|asyncio\.Lock|asyncio\.Condition|asyncio\.Event|asyncio\.Barrier|asyncio\.TaskGroup|asyncio\.run_coroutine_threadsafe|asyncio\.to_thread|asyncio\.pipe|asyncio\.start_server|asyncio\.start_unix_server|asyncio\.open_connection|asyncio\.open_unix_connection|asyncio\.create_subprocess_exec|asyncio\.create_subprocess_shell)', "Asyncio module", "Good: using asyncio module", Severity.INFO),
            (r'(?:socket\.socket|socket\.create_connection|socket\.create_server|socket\.getaddrinfo|socket\.gethostname|socket\.gethostbyname|socket\.gethostbyaddr|socket\.getfqdn|socket\.getnameinfo|socket\.getservbyname|socket\.getservbyport|socket\.has_ipv6|socket\.inet_aton|socket\.inet_ntoa|socket\.inet_pton|socket\.inet_ntop|socket\.SOCK_STREAM|socket\.SOCK_DGRAM|socket\.SOCK_RAW|socket\.AF_INET|socket\.AF_INET6|socket\.AF_UNIX|socket\.IPPROTO_TCP|socket\.IPPROTO_UDP|socket\.IPPROTO_IP|socket\.IPPROTO_IPV6)', "Socket module", "Good: using socket module", Severity.INFO),
            (r'(?:ssl\.SSLContext|ssl\.wrap_socket|ssl\.create_default_context|ssl\.CERT_NONE|ssl\.CERT_OPTIONAL|ssl\.CERT_REQUIRED|ssl\.PROTOCOL_TLS|ssl\.PROTOCOL_TLS_CLIENT|ssl\.PROTOCOL_TLS_SERVER|ssl\.OP_NO_SSLv2|ssl\.OP_NO_SSLv3|ssl\.OP_NO_TLSv1|ssl\.OP_NO_TLSv1_1|ssl\.HAS_SNI|ssl\.HAS_ECDH|ssl\.HAS_NPN)', "SSL module", "Good: using SSL module", Severity.INFO),
            (r'(?:subprocess\.run|subprocess\.call|subprocess\.check_call|subprocess\.check_output|subprocess\.Popen|subprocess\.PIPE|subprocess\.STDOUT|subprocess\.DEVNULL|subprocess\.CalledProcessError|subprocess\.TimeoutExpired|subprocess\.SubprocessError)', "Subprocess module", "Good: using subprocess module", Severity.INFO),
            (r'(?:unittest\.TestCase|unittest\.TestLoader|unittest\.TestRunner|unittest\.TestResult|unittest\.TestSuite|unittest\.TestDiscoverer|unittest\.main|unittest\.mock|unittest\.mock\.Mock|unittest\.mock\.MagicMock|unittest\.mock\.patch|unittest\.mock\.sentinel|unittest\.mock\.DEFAULT|unittest\.mock\.call|unittest\.mock\.PropertyMock|unittest\.mock\.create_autospec|unittest\.mock\.ANY|unittest\.skip|unittest\.skipIf|unittest\.skipUnless|unittest\.expectedFailure|unittest\.AssertRaises|unittest\.AssertWarns)', "Unittest module", "Good: using unittest module", Severity.INFO),
            (r'(?:pytest|pytest\.mark|pytest\.fixture|pytest\.param|pytest\.raises|pytest\.warns|pytest\.skip|pytest\.xfail|pytest\.param|pytest\.approx|pytest\.importorskip|pytest\.plugins|pytest\.conftest|pytest\.yield_fixture|pytest\.yield_fixture|pytest\.register_assert_rewrite)', "Pytest", "Good: using pytest", Severity.INFO),
            (r'(?:flask|Flask|Flask\.__name__|Flask\.static|Flask\.template_folder|Flask\.instance_path|Flask\.config|Flask\.logger|Flask\.extensions|Flask\.before_request|Flask\.after_request|Flask\.teardown_request|Flask\.teardown_appcontext|Flask\.errorhandler|Flask\.url_value_preprocessor|Flask\.url_defaults|Flask\.before_first_request|Flask\.shell_context_processor|Flask\.template_global|Flask\.template_filter|Flask\.record|Flask\.add_url_rule|Flask\.route|Flask\.send_static_file|Flask\.send_file|Flask\.make_response|Flask\.jsonify|Flask\.redirect|Flask\.abort|Flask\.render_template|Flask\.render_template_string|Flask\.request|Flask\.current_app|Flask\.g|Flask\.session|Flask\.flash|Flask\.get_flashed_messages|Flask\.url_for|Flask\.json)', "Flask", "Good: using Flask", Severity.INFO),
            (r'(?:django|Django|django\.conf|django\.core|django\.db|django\.forms|django\.http|django\.middleware|django\.shortcuts|django\.template|django\.urls|django\.utils|django\.views)', "Django", "Good: using Django", Severity.INFO),
            (r'(?:fastapi|FastAPI|APIRouter|Depends|Header|Query|Path|Body|File|UploadFile|HTTPException|status|Request|Response|Cookie|Form)', "FastAPI", "Good: using FastAPI", Severity.INFO),
            (r'(?:requests\.get|requests\.post|requests\.put|requests\.delete|requests\.patch|requests\.head|requests\.options|requests\.request|requests\.Session|requests\.prepared_request|requests\.exceptions|requests\.adapters)', "Requests module", "Good: using requests module", Severity.INFO),
            (r'(?:httpx\.Client|httpx\.AsyncClient|httpx\.Response|httpx\.Request|httpx\.HTTPStatusError|httpx\.TimeoutException|httpx\.ConnectError|httpx\.ConnectTimeout|httpx\.ReadTimeout|httpx\.WriteTimeout|httpx\.PoolTimeout)', "httpx", "Good: using httpx", Severity.INFO),
            (r'(?:aiohttp\.ClientSession|aiohttp\.ClientResponse|aiohttp\.ClientError|aiohttp\.ClientTimeout|aiohttp\.TCPConnector|aiohttp\.UnixConnector|aiohttp\.BasicAuth|aiohttp\.FormData|aiohttp\.web|aiohttp\.ClientSession\.get|aiohttp\.ClientSession\.post|aiohttp\.ClientSession\.put|aiohttp\.ClientSession\.delete|aiohttp\.ClientSession\.patch|aiohttp\.ClientSession\.head|aiohttp\.ClientSession\.options|aiohttp\.ClientSession\.request)', "aiohttp", "Good: using aiohttp", Severity.INFO),
            (r'(?:paramiko|SSHClient|AutoAddPolicy|RejectPolicy|WarningPolicy|SFTPClient|Transport|Channel|BufferedFile|PKey|RSAKey|DSSKey|ECDSAKey|Ed25519Key|Agent|AgentKey|HostKeys|known_host)', "Paramiko", "Good: using Paramiko for SSH", Severity.INFO),
            (r'(?:celery|Celery|shared_task|@task|@app\.task|@worker\.task|Celery\.config_from_object|Celery\.autodiscover_tasks|celery\.beat|celery\.result|celery\.backends)', "Celery", "Good: using Celery", Severity.INFO),
            (r'(?:redis|Redis|redis\.Redis|redis\.StrictRedis|redis\.ConnectionPool|redis\.BlockingConnectionPool|redis\.Sentinel|redis\.SentinelConnectionPool|redis\.from_url|redis\.Pipeline|redis\.ClusterPipeline|redis\.Pipeline\.execute|redis\.Pipeline\.multi|redis\.Pipeline\.watch|redis\.Pipeline\.unwatch|redis\.Pipeline\.pipeline|redis\.Pipeline\.immediate_execute_command|redis\.Pipeline\.set|redis\.Pipeline\.get|redis\.Pipeline\.delete|redis\.Pipeline\.exists|redis\.Pipeline\.expire|redis\.Pipeline\.ttl|redis\.Pipeline\.keys|redis\.Pipeline\.scan|redis\.Pipeline\.hset|redis\.Pipeline\.hget|redis\.Pipeline\.hdel|redis\.Pipeline\.hgetall|redis\.Pipeline\.lpush|redis\.Pipeline\.rpush|redis\.Pipeline\.lpop|redis\.Pipeline\.rpop|redis\.Pipeline\.lrange|redis\.Pipeline\.sadd|redis\.Pipeline\.srem|redis\.Pipeline\.smembers|redis\.Pipeline\.zadd|redis\.Pipeline\.zrem|redis\.Pipeline\.zrange|redis\.Pipeline\.zrevrange|redis\.Pipeline\.zrangebyscore|redis\.Pipeline\.publish|redis\.Pipeline\.subscribe)', "Redis", "Good: using Redis", Severity.INFO),
            (r'(?:sqlalchemy|SQLAlchemy|create_engine|sessionmaker|Session|Column|Table|relationship|backref|ForeignKey|Integer|String|Text|Boolean|DateTime|Date|Time|Float|Numeric|LargeBinary|PickleType|JSON|ARRAY|Enum|TypeDecorator|CompositeType|SchemaType|SQLAlchemyError|OperationalError|ProgrammingError|IntegrityError|DataError|InterfaceError|InternalError|NotSupportedError|StatementError|InvalidRequestError|NoResultFound|MultipleResultsFound|NoInspectionAvailable|NoForeignKeysError|AmbiguousForeignKeysError|CircularDependencyError|UnmappedClassError|UnmappedInstanceError|MappedColumn|mapped_column|Mapped|DeclarativeBase|DeclarativeBase|as_declarative)', "SQLAlchemy", "Good: using SQLAlchemy", Severity.INFO),
            (r'(?:pydantic|BaseModel|Field|validator|root_validator|model_validator|field_validator|computed_field|ConfigDict|BaseSettings|FieldInfo|ValidationError)', "Pydantic", "Good: using Pydantic", Severity.INFO),
            (r'(?:click|typer|typer\.Typer|typer\.Argument|typer\.Option|click\.command|click\.group|click\.option|click\.argument|click\.pass_context|click\.echo|click\.style|click\.prompt|click\.confirm|click\.progressbar|click\.clear|click\.get_text_stream|click\.get_binary_stream|click\.get_app_dir|click\.find_config_file|click\.set_exception_handler|click\.get_current_context|click\.Context|click\.Parameter|click\.Option|click\.Argument|click\.Command|click\.Group|click\.MultiCommand|click\.BaseCommand|click\.HelpFormatter|click\.Style|click\.testing)', "Click/Typer", "Good: using Click/Typer", Severity.INFO),
            (r'(?:argparse|argparse\.ArgumentParser|argparse\.add_argument|argparse\.add_mutually_exclusive_group|argparse\.add_argument_group|argparse\.parse_args|argparse\.parse_known_args|argparse\.Namespace|argparse\.FileType|argparse\.Action|argparse\.store_true|argparse\.store_false|argparse\.append_const|argparse\.count|argparse\.version)', "Argparse", "Good: using argparse", Severity.INFO),
            (r'(?:smtplib|SMTP|SMTP_SSL|SMTPAuthenticationError|SMTPHeloError|SMTPNotSupportedError|SMTPRecipientsRefused|SMTPSenderRefused|SMTPDataError|SMTPResponseException|SMTPServerDisconnected)', "SMTP module", "Good: using SMTP module", Severity.INFO),
            (r'(?:imaplib|IMAP4|IMAP4_SSL|IMAP4\.read|IMAP4\.write|IMAP4\.open|IMAP4\.close|IMAP4\.fetch|IMAP4\.search|IMAP4\.select|IMAP4\.examine|IMAP4\.create|IMAP4\.delete|IMAP4\.rename|IMAP4\.subscribe|IMAP4\.unsubscribe|IMAP4\.list|IMAP4\.lsub|IMAP4\.status|IMAP4\.append|IMAP4\.copy|IMAP4\.store|IMAP4\.expunge|IMAP4\.uid|IMAP4\.noop|IMAP4\.login|IMAP4\.logout)', "IMAP module", "Good: using IMAP module", Severity.INFO),
            (r'(?:poplib|POP3|POP3_SSL|POP3\.user|POP3\.pass_|POP3\.stat|POP3\.list|POP3\.retr|POP3\.dele|POP3\.rset|POP3\.quit|POP3\.apop|POP3\.top|POP3\.uidl|POP3\.set_parser|POP3\.welcome|POP3\.apop|POP3\.noop)', "POP3 module", "Good: using POP3 module", Severity.INFO),
            (r'(?:datetime\.datetime|datetime\.date|datetime\.time|datetime\.timedelta|datetime\.timezone|datetime\.tzinfo|datetime\.utcnow|datetime\.fromtimestamp|datetime\.now|datetime\.combine|datetime\.timetuple|datetime\.toordinal|datetime\.weekday|datetime\.isoweekday|datetime\.isocalendar|datetime\.isoformat|datetime\.strftime|datetime\.strptime|datetime\.replace|datetime\.astimezone|datetime\.tzname|datetime\.utcoffset|datetime\.dst|datetime\.fold)', "Datetime module", "Good: using datetime module", Severity.INFO),
            (r'(?:arrow\.|pendulum\.)', "Arrow/Pendulum", "Good: using datetime library", Severity.INFO),
            (r'(?:gzip|gzip\.open|gzip\.GzipFile|gzip\.compress|gzip\.decompress|gzip\.GZIP_HEADER|gzip\.GZIP_TRAILER|gzip\.MAX_WBITS|gzip\.FTEXT|gzip\.FHCRC|gzip\.FEXTRA|gzip\.FNAME|gzip\.FCOMMENT|gzip\.OS_CODE)', "Gzip module", "Good: using gzip module", Severity.INFO),
            (r'(?:bz2|bz2\.open|bz2\.BZ2File|bz2\.compress|bz2\.decompress|bz2\.compressobj|bz2\.decompressobj)', "BZ2 module", "Good: using bz2 module", Severity.INFO),
            (r'(?:lzma|lzma\.open|lzma\.LZMAFile|lzma\.compress|lzma\.decompress|lzma\.compressobj|lzma\.decompressobj|lzma\.FORMAT_ALONE|lzma\.FORMAT_CAB|lzma\.FORMAT_RAW|lzma\.FORMAT_XZ|lzma\.FORMAT_ZIP|lzma\.FILTER_LZMA1|lzma\.FILTER_LZMA2|lzma\.FILTER_POWERPC|lzma\.FILTER_IA64|lzma\.FILTER_ARM|lzma\.FILTER_ARMTHUMB|lzma\.FILTER_SPARC|lzma\.FILTER_ARM|lzma\.FILTER_ARMTHUMB|lzma\.FILTER_SPARC)', "LZMA module", "Good: using lzma module", Severity.INFO),
            (r'(?:zipfile|zipfile\.ZipFile|zipfile\.PyZipFile|zipfile\.is_zipfile|zipfile\.ZIP_STORED|zipfile\.ZIP_DEFLATED|zipfile\.ZIP_BZIP2|zipfile\.ZIP_LZMA)', "Zipfile module", "Good: using zipfile module", Severity.INFO),
            (r'(?:tarfile|tarfile\.open|tarfile\.TarFile|tarfile\.TarInfo|tarfile\.TarError|tarfile\.ReadError|tarfile\.CompressionError|tarfile\.StreamError|tarfile\.ExtractError|tarfile\.HeaderError|tarfile\.TAR_GZipped|tarfile\.TAR_BZ2ipped|tarfile\.TAR_LZMA|tarfile\.CONTTYPE)', "Tarfile module", "Good: using tarfile module", Severity.INFO),
            (r'(?:pickle\.load|pickle\.dump|pickle\.loads|pickle\.dumps|pickle\.Pickler|pickle\.Unpickler|pickle\.HIGHEST_PROTOCOL|pickle\.DEFAULT_PROTOCOL|pickle\.PickleError|pickle\.PicklingError|pickle\.UnpicklingError|pickle\.Unpickler)', "Pickle module", "Good: using pickle module", Severity.INFO),
            (r'(?:marshal\.load|marshal\.dump|marshal\.loads|marshal\.dumps|marshal\.dump|marshal\.version)', "Marshal module", "Good: using marshal module", Severity.INFO),
            (r'(?:shelve\.open|shelve\.Shelf|shelve\.BsdDbShelf|shelve\.DbmShelf|shelve\.open|shelve\.copy)', "Shelve module", "Good: using shelve module", Severity.INFO),
            (r'(?:sqlite3\.connect|sqlite3\.Connection|sqlite3\.Cursor|sqlite3\.Row|sqlite3\.prepare|sqlite3\.execute|sqlite3\.executemany|sqlite3\.executescript|sqlite3\.fetchone|sqlite3\.fetchall|sqlite3\.fetchmany|sqlite3\.close|sqlite3\.commit|sqlite3\.rollback|sqlite3\.text_factory|sqlite3\.isolation_level|sqlite3\.autocommit|sqlite3\.register_adapter|sqlite3\.register_converter|sqlite3\.optimize|sqlite3\.complete_statement|sqlite3\.enable_callback_tracebacks|sqlite3\.enable_shared_cache|sqlite3\.connect)', "SQLite3 module", "Good: using sqlite3 module", Severity.INFO),
            (r'(?:pg|psycopg2|psycopg2\.connect|psycopg2\.extras|psycopg2\.extensions|psycopg2\.sql|psycopg2\.Range|psycopg2\.HstoreAdapter|psycopg2\.Json|psycopg2\.Binary|psycopg2\.TimestampTZ|psycopg2\.TimestampLocalTZ|psycopg2\.Date|psycopg2\.Time|psycopg2\.DateTime|psycopg2\.Interval|psycopg2\.UUID)', "PostgreSQL", "Good: using PostgreSQL", Severity.INFO),
            (r'(?:pymysql|pymysql\.connect|pymysql\.cursors|pymysql\.Connection|pymysql\.Cursor|pymysql\.DictCursor|pymysql\.SSCursor|pymysql\.DictMixin|pymysql\.ProgrammingError|pymysql\.OperationalError|pymysql\.IntegrityError|pymysql\.InternalError|pymysql\.NotSupportedError|pymysql\.MySQLError)', "MySQL", "Good: using MySQL", Severity.INFO),
            (r'(?:pymongo|pymongo\.MongoClient|pymongo\.ASCENDING|pymongo\.DESCENDING|pymongo\.GEOSPHERE|pymongo\.HASHED|pymongo\.TEXT|pymongo\.InsertOne|pymongo\.InsertMany|pymongo\.UpdateOne|pymongo\.UpdateMany|pymongo\.ReplaceOne|pymongo\.DeleteOne|pymongo\.DeleteMany|pymongo\.ReturnDocument|pymongo\.IndexModel|pymongo\.ASC|pymongo\.DESC|pymongo\.errors)', "MongoDB", "Good: using MongoDB", Severity.INFO),
            (r'(?:couchdb|couchdb\.Server|couchdb\.Database|couchdb\.Document|couchdb\.ResourceNotFound|couchdb\.ResourceConflict|couchdb\.Forbidden|couchdb\.Unauthorized|couchdb\.PreconditionFailed|couchdb\.RequestFailed|couchdb\.BadResponse|couchdb\.ServerError|couchdb\.HTTPError)', "CouchDB", "Good: using CouchDB", Severity.INFO),
            (r'(?:cassandra|cassandra\.Cluster|cassandra\.Session|cassandra\.ConsistencyLevel|cassandra\.SimpleStatement|cassandra\.PreparedStatement|cassandra\.BatchStatement|cassandra\.ExecutionProfile|cassandra\.policies|cassandra\.query|cassandra\.cluster|cassandra\.auth|cassandra\.io|cassandra\.marshalling|cassandra\.codec|cassandra\.datastax)', "Cassandra", "Good: using Cassandra", Severity.INFO),
            (r'(?:neo4j|neo4j\.GraphDatabase|neo4j\.Driver|neo4j\.Session|neo4j\.Transaction|neo4j\.Result|neo4j\.Record|neo4j\.Node|neo4j\.Relationship|neo4j\.Path|neo4j\.GraphError|neo4j\.ServiceUnavailable|neo4j\.SessionExpired|neo4j\.ConstraintError|neo4j\.AuthError|neo4j\.ConfigurationError)', "Neo4j", "Good: using Neo4j", Severity.INFO),
            (r'(?:elasticsearch|elasticsearch\.Elasticsearch|elasticsearch\.helpers|elasticsearch\.ConnectionError|elasticsearch\.SerializationError|elasticsearch\.TransportError|elasticsearch\.NotFound|elasticsearch\.Conflict|elasticsearch\.ConnectionTimeout|elasticsearch\.RequestError)', "Elasticsearch", "Good: using Elasticsearch", Severity.INFO),
            (r'(?:celery|Celery|shared_task|@task|@app\.task|@worker\.task|celery\.beat|celery\.result|celery\.backends|celery\.task_set|celery\.app|celery\.task)', "Celery", "Good: using Celery", Severity.INFO),
            (r'(?:dramatiq|dramatiq\.Actor|dramatiq\.actor|dramatiq\.ActorRegistry|dramatiq\.Middleware|dramatiq\.Results|dramatiq\.MemoryBackend|dramatiq\.RedisBackend|dramatiq\.RabbitmqBroker|dramatiq\.RedisBroker|dramatiq\.ActorProcess|dramatiq\.WorkerThread|dramatiq\.ConsumerThread|dramatiq\.Message|dramatiq\.MessageProxy|dramatiq\.Middleware|dramatiq\.Pipeline|dramatiq\.Group|dramatiq\.pipeline|dramatiq\.group|dramatiq\.chain)', "Dramatiq", "Good: using Dramatiq", Severity.INFO),
            (r'(?:rq|rq\.Queue|rq\.Worker|rq\.Job|rq\.Scheduler|rq\.SimpleWorker|rq\.Connection|rq\.ConnectionPool|rq\.Job\.create|rq\.Job\.enqueue|rq\.Job\.fetch|rq\.Job\.cancel|rq\.Job\.delete|rq\.Job\.enqueue_at|rq\.Job\.enqueue_in|rq\.Job\.enqueue_call|rq\.Job\.enqueue_call_async|rq\.Job\.Dependency)', "RQ", "Good: using RQ", Severity.INFO),
            (r'(?:huey|Huey|Huey\.task|Huey\.periodic_task|Huey\.on_startup|Huey\.on_shutdown|Huey\.queue_task|Huey\.result|Huey\.store_results|Huey\.flush_results|Huey\.storage|Huey\.SqliteHuey|Huey\.RedisHuey|Huey\.PostgresHuey)', "Huey", "Good: using Huey", Severity.INFO),
            (r'(?:schedule|schedule\.every|schedule\.clear|schedule\.cancel_job|schedule\.get_jobs|schedule\.run_pending|schedule\.next_run|schedule\.idle_seconds)', "Schedule", "Good: using Schedule", Severity.INFO),
            (r'(?:APScheduler|APScheduler\.BackgroundScheduler|APScheduler\.BlockingScheduler|APScheduler\.AsyncIOScheduler|APScheduler\.Job|APScheduler\.JobStore|APScheduler\.Trigger|APScheduler\.IntervalTrigger|APScheduler\.DateTrigger|APScheduler\.CronTrigger|APScheduler\.TimeoutError|APScheduler\.JobLookupError|APScheduler\.ConflictingIdError)', "APScheduler", "Good: using APScheduler", Severity.INFO),
            (r'(?:tqdm|tqdm\.tqdm|tqdm\.trange|tqdm\.auto|tqdm\.notebook|tqdm\.contrib|tqdm\.asyncio|tqdm\.logging|tqdm\.pandas|tqdm\.gui|tqdm\.tk|tqdm\.rich|tqdm\.dask|tqdm\.multiprocess|tqdm\.concurrent|tqdm\.wrapattr|tqdm\.tqdm)', "TQDM", "Good: using TQDM for progress bars", Severity.INFO),
            (r'(?:rich|rich\.Console|rich\.Table|rich\.Panel|rich\.Text|rich\.Markdown|rich\.Syntax|rich\.Tree|rich\.Prompt|rich\.confirm|rich\.progress|rich\.live|rich\.status|rich\.layout|rich\.columns|rich\.padding|rich\.rule|rich\.horizontal_rule|rich\.columns|rich\.group|rich\.stack|rich\.text|rich\.style|rich\.themes)', "Rich", "Good: using Rich for console output", Severity.INFO),
            (r'(?:colorama|colorama\.init|colorama\.Fore|colorama\.Back|colorama\.Style|colorama\.Cursor)', "Colorama", "Good: using Colorama", Severity.INFO),
            (r'(?:tabulate|tabulate\.tabulate|tabulate\.MINIMAL|tabulate\.PLAIN|tabulate\.SIMPLE|tabulate\.GRID|tabulate\.FANCY|tabulate\.PIPE|tabulate\.ORG|tabulate\.PLAIN_BOLD|tabulate\.MARKDOWN|tabulate\.GITHUB|tabulate\.PIEPTOE|tabulate\.PSQL|tabulate\.RST|tabulate\.MEADY|tabulate\.YOUTRACK|tabulate\.HTML|tabulate\.LATEX|tabulate\.LATEX_RAW|tabulate\.LATEX_BOOKTABS|tabulate\.TEXTILE|tabulate\.MEDIAWIKI|tabulate\.MEDIAWIKI_NOHEADER|tabulate\.ORGSimple|tabulate\.ORGtbl|tabulate\.JIRA|tabulate\.VESTIGE|tabulate\.PLOST|tabulate\.RON|tabulate\.GRID_FANCY|tabulate\.GRID_HEAVY|tabulate\.GRID_DOUBLE_DASH)', "Tabulate", "Good: using Tabulate", Severity.INFO),
            (r'(?:pygments|pygments\.highlight|pygments\.lex|pygments\.token|pygments\.lexers|pygments\.formatters|pygments\.styles|pygments\.filter|pygments\.HtmlFormatter|pygments\.TerminalFormatter|pygments\.Terminal256Formatter|pygments\.TerminalTrueColorFormatter|pygments\.NullFormatter|pygments\.RawTokenFormatter|pygments\.ImageFormatter|pygments\.GrokFormatter)', "Pygments", "Good: using Pygments", Severity.INFO),
            (r'(?:black|black\.format_str|black\.format_file_in_place|black\.target_versions|black\.FileMode|black\.TargetVersion|black\.parse_pyproject_toml|black\.format_cell_contents|black\.patched_config|black\.re_compile_maybe_verbose|black\.decode_bytes|black\.is_python_file)', "Black", "Good: using Black for formatting", Severity.INFO),
            (r'(?:isort|isort\.code|isort\.check_code|isort\.place_module|isort\.get_lines|isort\.output|isort\.main|isort\.Place|isort\.Known|isort\.sections|isort\.Profile)', "isort", "Good: using isort for import sorting", Severity.INFO),
            (r'(?:mypy|mypy\.api|check_mypy_annotations|HAS_TYPE_STUBS|stub_package_name)', "Mypy", "Good: using Mypy for type checking", Severity.INFO),
            (r'(?:flake8|flake8\.api|Flake8)', "Flake8", "Good: using Flake8", Severity.INFO),
            (r'(?:ruff|ruff\.check|ruff\.format)', "Ruff", "Good: using Ruff", Severity.INFO),
            (r'(?:bandit|bandit\.core|bandit\.formatters|bandit\.node_visitors|bandit\.issue)', "Bandit", "Good: using Bandit for security", Severity.INFO),
            (r'(?:safety|safety\.check|safety\.CLI)', "Safety", "Good: using Safety for dependencies", Severity.INFO),
            (r'(?:pip|pip\.main|pip\.commands|pip\.req|pip\.locations|pip\.exceptions|pip\.vcs|pip\.download|pip\.index|pip\.network|pip\.locations|pip\.utils|pip\.operations)', "Pip", "Good: using pip", Severity.INFO),
            (r'(?:setuptools|setup\.py|setup\.cfg|pyproject\.toml|pip\.wheel|pip\.egg_info)', "Setuptools", "Good: using setuptools", Severity.INFO),
            (r'(?:poetry|poetry\.core|poetry\.config|poetry\.exceptions|poetry\.factory|poetry\.installation|poetry\.packages|poetry\.plugins|poetry\.repositories|poetry\.scm|poetry\.semver|poetry\.vcs)', "Poetry", "Good: using Poetry", Severity.INFO),
            (r'(?:pipenv|Pipfile|Pipfile\.lock|pipenv\.project|pipenv\.environments|pipenv\.environments\.Set|pipenv\.environments\.Set\.get|pipenv\.environments\.Set\.bool)', "Pipenv", "Good: using Pipenv", Severity.INFO),
            (r'(?:conda|conda\.base|conda\.cli|conda\.common|conda\.core|conda\.env|conda\.exceptions|conda\.gateways|conda\.install|conda\.models|conda\.plugins|conda\.testing|conda\.utils)', "Conda", "Good: using Conda", Severity.INFO),
            (r'(?:poetry\.version|version_info|__version__|VERSION)', "Version management", "Good: managing versions", Severity.INFO),
            (r'(?:setup\.py|setup\.cfg|pyproject\.toml|poetry\.toml|poetry\.lock|requirements\.txt|requirements-dev\.txt|requirements-test\.txt|requirements-prod\.txt)', "Dependency management", "Good: managing dependencies", Severity.INFO),
        ]

        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith('#'):
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
