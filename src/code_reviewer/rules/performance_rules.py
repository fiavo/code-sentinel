"""
Comprehensive performance rules for code analysis.
Covers N+1 queries, memory leaks, inefficient algorithms, and more.
"""

import re
from typing import Optional

from ..core.models import CodeIssue, Severity, IssueCategory
from ..core.rules import BaseRule


class DatabasePerformanceRules(BaseRule):
    """Database query performance issues."""

    @property
    def name(self) -> str:
        return "db_performance"

    @property
    def description(self) -> str:
        return "Database performance issue detection"

    @property
    def category(self) -> IssueCategory:
        return IssueCategory.PERFORMANCE

    @property
    def severity(self) -> Severity:
        return Severity.WARNING

    def check(self, file_path: str, content: str) -> list[CodeIssue]:
        issues = []
        lines = content.splitlines()

        patterns = [
            # N+1 query patterns
            (r'for\s+\w+\s+in\s+\w+\.query.*\.all\s*\(\s*\)', "Potential N+1 query pattern",
             "Use joinedload(), selectinload(), or eager loading", Severity.WARNING),
            (r'for\s+\w+\s+in\s+\w+\.objects\.all\s*\(\s*\)', "Potential N+1 query pattern",
             "Use select_related() or prefetch_related()", Severity.WARNING),
            (r'for\s+\w+\s+in\s+\w+\.select\s*\(\s*\).*\.all\s*\(\s*\)', "N+1 query in loop",
             "Use aggregate queries or batch loading", Severity.WARNING),

            # Missing indexes
            (r'(?i)WHERE\s+\w+\s*=\s*\?', "Query without index hint",
             "Ensure proper indexes exist for WHERE clauses", Severity.INFO),
            (r'\.filter\s*\(\s*\w+\s*=', "Filter without select_related",
             "Use select_related() for foreign key lookups", Severity.INFO),
            (r'\.exclude\s*\(\s*\w+\s*=', "Exclude without select_related",
             "Use select_related() for foreign key lookups", Severity.INFO),

            # Missing pagination
            (r'\.all\s*\(\s*\)\s*$', "Query without pagination",
             "Add .limit() or .paginate() for large result sets", Severity.WARNING),
            (r'\.find\s*\(\s*\)\s*$', "Find without limit",
             "Add .limit() for large collections", Severity.WARNING),
            (r'SELECT\s+\*\s+FROM', "SELECT * without limit",
             "Select only needed columns and add LIMIT", Severity.WARNING),

            # Missing bulk operations
            (r'for\s+\w+\s+in.*:\s*\n\s*\w+\.save\s*\(\s*\)', "Individual saves in loop",
             "Use bulk_create() or bulk_update() for batch operations", Severity.WARNING),
            (r'for\s+\w+\s+in.*:\s*\n\s*\w+\.insert\s*\(', "Individual inserts in loop",
             "Use bulk insert operations", Severity.WARNING),
            (r'for\s+\w+\s+in.*:\s*\n\s*\w+\.update\s*\(', "Individual updates in loop",
             "Use bulk update operations", Severity.WARNING),
            (r'for\s+\w+\s+in.*:\s*\n\s*\w+\.delete\s*\(\s*\)', "Individual deletes in loop",
             "Use bulk delete operations", Severity.WARNING),

            # Missing connection pooling
            (r'(?:psycopg2|mysql|sqlite3)\.connect\s*\(', "Direct database connection",
             "Use connection pooling for better performance", Severity.INFO),
            (r'Database\s*\(\s*["\'](?:mysql|postgres|sqlite)', "Direct database connection",
             "Use connection pooling", Severity.INFO),

            # Missing query optimization
            (r'\.count\s*\(\s*\)\s*>\s*0', "Count check instead of exists()",
             "Use .exists() for existence checks", Severity.WARNING),
            (r'len\s*\(\s*\w+\.query.*\)\s*>\s*0', "len() check instead of exists()",
             "Use .exists() for existence checks", Severity.WARNING),
            (r'\.fetchall\s*\(\s*\)', "Fetch all records at once",
             "Use .fetchmany() or streaming for large datasets", Severity.WARNING),
            (r'cursor\.fetchall\s*\(\s*\)', "Fetch all records at once",
             "Use cursor.fetchmany() or streaming", Severity.WARNING),

            # Missing caching
            (r'(?:SELECT|select)\s+.*\s+FROM\s+\w+(?:\s+WHERE)?', "Database query without cache",
             "Consider adding result caching for repeated queries", Severity.INFO),
        ]

        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith('#') or stripped.startswith('--'):
                continue

            for pattern, message, suggestion, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    issues.append(self._create_issue(
                        file_path=file_path,
                        line=line_num,
                        message=message,
                        suggestion=suggestion,
                        severity=severity,
                        code_snippet=stripped,
                    ))

        return issues


class MemoryPerformanceRules(BaseRule):
    """Memory usage and leak detection."""

    @property
    def name(self) -> str:
        return "memory"

    @property
    def description(self) -> str:
        return "Memory usage and leak detection"

    @property
    def category(self) -> IssueCategory:
        return IssueCategory.PERFORMANCE

    @property
    def severity(self) -> Severity:
        return Severity.WARNING

    def check(self, file_path: str, content: str) -> list[CodeIssue]:
        issues = []
        lines = content.splitlines()

        patterns = [
            # Memory leaks
            (r'(?:addEvent[Ll]istener|on)\s*\([^)]*\)\s*(?:\}|;)', "Event listener without cleanup",
             "Remove event listeners when component unmounts", Severity.WARNING),
            (r'setInterval\s*\(', "setInterval without clearInterval",
             "Ensure clearInterval is called on cleanup", Severity.WARNING),
            (r'setTimeout\s*\(', "setTimeout without clearTimeout",
             "Ensure clearTimeout is called on cleanup", Severity.WARNING),
            (r'new\s+Worker\s*\(', "Worker without termination",
             "Call worker.terminate() when done", Severity.WARNING),
            (r'(?:global|window|globalThis)\.\w+\s*=\s*', "Global variable assignment",
             "Avoid global variables; use local scope or module exports", Severity.WARNING),

            # Large object creation
            (r'Array\s*\(\s*\d{6,}\s*\)', "Creating very large array",
             "Consider lazy loading or pagination", Severity.WARNING),
            (r'new\s+Array\s*\(\s*\d{6,}\s*\)', "Creating very large array",
             "Consider lazy loading or pagination", Severity.WARNING),
            (r'Buffer\.alloc\s*\(\s*\d{7,}\s*\)', "Allocating very large buffer",
             "Consider chunking or streaming", Severity.WARNING),
            (r'malloc\s*\(\s*\d{7,}\s*\)', "Allocating very large memory block",
             "Consider chunking or streaming", Severity.WARNING),

            # String concatenation in loops
            (r'for\s+\w+\s+in.*:\s*\n\s*\w+\s*\+=\s*["\']', "String concatenation in loop",
             "Use StringBuilder, list join, or array methods", Severity.WARNING),
            (r'for\s*\(.*\{[^}]*\+=\s*["\']', "String concatenation in loop (JS)",
             "Use array.join() or template literals", Severity.WARNING),
            (r'for\s+\w+\s+in.*:\s*\n\s*\w+\s*=\s*\w+\s*\+\s*["\']', "String concatenation in loop",
             "Use StringBuilder or list comprehension", Severity.WARNING),

            # Unnecessary copies
            (r'\.copy\s*\(\s*\)', "Unnecessary copy",
             "Use reference or view when possible", Severity.INFO),
            (r'\.clone\s*\(\s*\)', "Unnecessary clone",
             "Use reference when possible", Severity.INFO),
            (r'list\s*\(\s*\w+\s*\)', "Unnecessary list copy",
             "Use original iterable directly if possible", Severity.INFO),
            (r'slice\s*\(\s*\)', "Unnecessary array copy",
             "Use spread operator or original array if possible", Severity.INFO),

            # Missing lazy loading
            (r'import\s+\{.*\}\s+from\s+["\'][^"\']+["\']', "Eager import",
             "Consider lazy loading for large modules", Severity.INFO),
            (r'require\s*\(\s*["\'][^"\']+["\']\s*\)', "Synchronous require",
             "Consider async import for large modules", Severity.INFO),

            # inefficient loops
            (r'for\s+\w+\s+in\s+range\s*\(\s*len\s*\(', "Iterating with range(len())",
             "Use enumerate() or direct iteration", Severity.INFO),
            (r'for\s+\(.*;\s*\w+\s*<\s*\w+\.length', "C-style for loop on array",
             "Use for...of or array methods", Severity.INFO),
            (r'\.forEach\s*\(\s*function\s*\(', "forEach with anonymous function",
             "Use arrow function for better performance", Severity.INFO),

            # Missing break/return
            (r'for\s+\w+\s+in.*:\s*\n.*(?:if|elif).*:\s*\n\s*\w+\.append\s*\(', "Appending in loop without early exit",
             "Consider adding break/return for early exit", Severity.INFO),
        ]

        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith('#') or stripped.startswith('//'):
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


class AlgorithmPerformanceRules(BaseRule):
    """Algorithm efficiency and complexity issues."""

    @property
    def name(self) -> str:
        return "algorithm"

    @property
    def description(self) -> str:
        return "Algorithm efficiency detection"

    @property
    def category(self) -> IssueCategory:
        return IssueCategory.PERFORMANCE

    @property
    def severity(self) -> Severity:
        return Severity.WARNING

    def check(self, file_path: str, content: str) -> list[CodeIssue]:
        issues = []
        lines = content.splitlines()

        patterns = [
            # Nested loops
            (r'for\s+\w+\s+in\s+\w+.*:\s*\n(?:\s+.*\n)*?\s+for\s+\w+\s+in\s+\w+', "Nested loops detected",
             "Consider O(n²) complexity; optimize if possible", Severity.WARNING),
            (r'for\s*\(.*\{[^}]*for\s*\(', "Nested loops detected (JS)",
             "Consider O(n²) complexity; optimize if possible", Severity.WARNING),
            (r'for\s*\(.*\{[^}]*for\s*\(.*\{[^}]*for\s*\(', "Triple nested loops detected",
             "O(n³) complexity is very slow; refactor immediately", Severity.CRITICAL),

            # Inefficient search
            (r'for\s+\w+\s+in\s+\w+.*:\s*\n\s*(?:if|elif)\s+\w+\s*==', "Linear search in loop",
             "Use dictionary/set for O(1) lookup", Severity.WARNING),
            (r'\.indexOf\s*\(\s*\w+\s*\)', "Linear search with indexOf",
             "Use Map/Set for O(1) lookup", Severity.INFO),
            (r'\.includes\s*\(\s*\w+\s*\)', "Linear search with includes",
             "Use Set for O(1) lookup on large datasets", Severity.INFO),
            (r'\.find\s*\(\s*\w+\s+in', "Linear search with find",
             "Consider using index or dictionary", Severity.INFO),

            # Repeated computation
            (r'for\s+\w+\s+in.*:\s*\n.*len\s*\(', "len() called in loop",
             "Cache len() result outside loop", Severity.WARNING),
            (r'for\s+\w+\s+in.*:\s*\n.*\.count\s*\(', "count() called in loop",
             "Cache count() result or use Counter", Severity.WARNING),
            (r'for\s+\w+\s+in.*:\s*\n.*sorted\s*\(', "sorted() called in loop",
             "Sort once outside loop if possible", Severity.WARNING),

            # Inefficient data structure
            (r'list\s*\(\s*\)', "Using list instead of deque for queue operations",
             "Use collections.deque for O(1) append/pop", Severity.INFO),
            (r'\[\s*\]\s*\.append\s*\(\s*\w+\s*\)\s*\n.*\[\s*\]\s*\.pop\s*\(\s*0\s*\)', "List used as queue",
             "Use collections.deque for O(1) operations", Severity.WARNING),
            (r'\.sort\s*\(\s*\)\s*\n\s*\w+\s*=\s*\w+\s*\[', "Sorting then slicing",
             "Use heapq.nsmallest() or heapq.nlargest()", Severity.INFO),

            # Recursive without memoization
            (r'def\s+(\w+).*:\s*\n(?:\s+.*\n)*?\s+\1\s*\(', "Recursive function without memoization",
             "Add @lru_cache or implement memoization", Severity.WARNING),
            (r'function\s+(\w+).*\{[^}]*\1\s*\(', "Recursive function without memoization (JS)",
             "Add memoization for repeated calls", Severity.INFO),

            # Missing early exit
            (r'if\s+\w+\s+in\s+\w+.*:\s*\n\s*\w+\.append\s*\(', "Conditional append without early exit",
             "Use list comprehension or filter()", Severity.INFO),
        ]

        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith('#') or stripped.startswith('//'):
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


class NetworkPerformanceRules(BaseRule):
    """Network and I/O performance issues."""

    @property
    def name(self) -> str:
        return "network"

    @property
    def description(self) -> str:
        return "Network and I/O performance detection"

    @property
    def category(self) -> IssueCategory:
        return IssueCategory.PERFORMANCE

    @property
    def severity(self) -> Severity:
        return Severity.WARNING

    def check(self, file_path: str, content: str) -> list[CodeIssue]:
        issues = []
        lines = content.splitlines()

        patterns = [
            # Sequential requests
            (r'for\s+\w+\s+in.*:\s*\n\s*(?:requests|http|fetch|axios)', "Sequential HTTP requests in loop",
             "Use async/await with Promise.all() for parallel requests", Severity.WARNING),
            (r'for\s+\w+\s+in.*:\s*\n\s*(?:urllib|httpx)', "Sequential HTTP requests in loop",
             "Use asyncio.gather() for parallel requests", Severity.WARNING),

            # Missing connection reuse
            (r'requests\.(?:get|post|put|delete)\s*\(', "Request without session",
             "Use requests.Session() for connection reuse", Severity.INFO),
            (r'http\.client\.HTTPSConnection\s*\(', "Connection without pooling",
             "Use connection pooling", Severity.INFO),

            # Missing timeout
            (r'requests\.(?:get|post|put|delete)\s*\([^)]*\)', "HTTP request without timeout",
             "Add timeout parameter", Severity.WARNING),
            (r'fetch\s*\([^)]*\)', "fetch() without timeout",
             "Add AbortController for timeout", Severity.WARNING),
            (r'axios\.(?:get|post|put|delete)\s*\([^)]*\)', "axios request without timeout",
             "Add timeout configuration", Severity.WARNING),
            (r'urllib\.request\.urlopen\s*\([^)]*\)', "urlopen without timeout",
             "Add timeout parameter", Severity.WARNING),

            # Synchronous file I/O
            (r'(?:open|read|write)\s*\(', "Synchronous file I/O",
             "Consider async I/O for better performance", Severity.INFO),
            (r'fs\.readFileSync\s*\(', "Synchronous file read",
             "Use fs.readFile() or fs.promises.readFile()", Severity.WARNING),
            (r'fs\.writeFileSync\s*\(', "Synchronous file write",
             "Use fs.writeFile() or fs.promises.writeFile()", Severity.WARNING),

            # Missing compression
            (r'(?:get|post|put|delete)\s*\([^)]*\)', "HTTP request without Accept-Encoding",
             "Enable compression for better performance", Severity.INFO),

            # Large payload
            (r'res\.json\s*\(\s*\)', "Parsing large JSON response",
             "Consider streaming JSON parser for large payloads", Severity.INFO),
            (r'json\.loads\s*\(', "Parsing large JSON",
             "Consider ijson for streaming JSON parsing", Severity.INFO),
        ]

        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith('#') or stripped.startswith('//'):
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
