"""
Performance patterns for optimization detection.
"""

import re
from typing import Optional

from ..core.models import CodeIssue, Severity, IssueCategory
from ..core.rules import BaseRule


class PerformanceExtendedRules(BaseRule):
    """Extended performance pattern detection."""

    @property
    def name(self) -> str:
        return "performance_extended"

    @property
    def description(self) -> str:
        return "Extended performance pattern detection"

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
            # N+1 Query Patterns
            (r'for\s+\w+\s+in\s+\w+\.query.*\.all\s*\(\s*\)', "N+1 query in loop", "Use eager loading", Severity.WARNING),
            (r'for\s+\w+\s+in\s+\w+\.objects\.all\s*\(\s*\)', "N+1 query in loop", "Use select_related/prefetch_related", Severity.WARNING),
            (r'for\s+\w+\s+in\s+\w+\.select\s*\(\s*\).*\.all\s*\(\s*\)', "N+1 query in loop", "Use aggregate queries", Severity.WARNING),

            # Missing Pagination
            (r'\.all\s*\(\s*\)\s*$', "Query without pagination", "Add .limit() or .paginate()", Severity.WARNING),
            (r'\.find\s*\(\s*\)\s*$', "Find without limit", "Add .limit() for large collections", Severity.WARNING),
            (r'SELECT\s+\*\s+FROM', "SELECT * without limit", "Select needed columns and add LIMIT", Severity.WARNING),

            # Missing Bulk Operations
            (r'for\s+\w+\s+in.*:\s*\n\s*\w+\.save\s*\(\s*\)', "Individual saves in loop", "Use bulk_create() or bulk_update()", Severity.WARNING),
            (r'for\s+\w+\s+in.*:\s*\n\s*\w+\.insert\s*\(', "Individual inserts in loop", "Use bulk insert operations", Severity.WARNING),
            (r'for\s+\w+\s+in.*:\s*\n\s*\w+\.update\s*\(', "Individual updates in loop", "Use bulk update operations", Severity.WARNING),
            (r'for\s+\w+\s+in.*:\s*\n\s*\w+\.delete\s*\(\s*\)', "Individual deletes in loop", "Use bulk delete operations", Severity.WARNING),

            # Missing Connection Pooling
            (r'(?:psycopg2|mysql|sqlite3)\.connect\s*\(', "Direct database connection", "Use connection pooling", Severity.INFO),
            (r'Database\s*\(\s*["\'](?:mysql|postgres|sqlite)', "Direct database connection", "Use connection pooling", Severity.INFO),

            # Missing Query Optimization
            (r'\.count\s*\(\s*\)\s*>\s*0', "Count check instead of exists()", "Use .exists() for existence checks", Severity.WARNING),
            (r'len\s*\(\s*\w+\.query.*\)\s*>\s*0', "len() check instead of exists()", "Use .exists() for existence checks", Severity.WARNING),
            (r'\.fetchall\s*\(\s*\)', "Fetch all records", "Use .fetchmany() or streaming", Severity.WARNING),
            (r'cursor\.fetchall\s*\(\s*\)', "Fetch all records", "Use cursor.fetchmany() or streaming", Severity.WARNING),

            # Missing Caching
            (r'(?:SELECT|select)\s+.*\s+FROM\s+\w+(?:\s+WHERE)?', "Database query without cache", "Consider adding result caching", Severity.INFO),

            # Memory Leaks
            (r'(?:addEvent[Ll]istener|on)\s*\([^)]*\)\s*(?:\}|;)', "Event listener without cleanup", "Remove listeners on unmount", Severity.WARNING),
            (r'setInterval\s*\(', "setInterval without clearInterval", "Ensure clearInterval on cleanup", Severity.WARNING),
            (r'setTimeout\s*\(', "setTimeout without clearTimeout", "Ensure clearTimeout on cleanup", Severity.WARNING),
            (r'new\s+Worker\s*\(', "Worker without termination", "Call worker.terminate() when done", Severity.WARNING),
            (r'(?:global|window|globalThis)\.\w+\s*=\s*', "Global variable assignment", "Avoid global variables", Severity.WARNING),

            # Large Object Creation
            (r'Array\s*\(\s*\d{6,}\s*\)', "Creating very large array", "Consider lazy loading", Severity.WARNING),
            (r'new\s+Array\s*\(\s*\d{6,}\s*\)', "Creating very large array", "Consider lazy loading", Severity.WARNING),
            (r'Buffer\.alloc\s*\(\s*\d{7,}\s*\)', "Allocating very large buffer", "Consider chunking", Severity.WARNING),
            (r'malloc\s*\(\s*\d{7,}\s*\)', "Allocating very large memory", "Consider chunking", Severity.WARNING),

            # String Concatenation in Loops
            (r'for\s+\w+\s+in.*:\s*\n\s*\w+\s*\+=\s*["\']', "String concatenation in loop", "Use StringBuilder or list join", Severity.WARNING),
            (r'for\s*\(.*\{[^}]*\+=\s*["\']', "String concatenation in loop (JS)", "Use array.join() or template literals", Severity.WARNING),

            # Unnecessary Copies
            (r'\.copy\s*\(\s*\)', "Unnecessary copy", "Use reference when possible", Severity.INFO),
            (r'\.clone\s*\(\s*\)', "Unnecessary clone", "Use reference when possible", Severity.INFO),
            (r'list\s*\(\s*\w+\s*\)', "Unnecessary list copy", "Use original iterable if possible", Severity.INFO),
            (r'slice\s*\(\s*\)', "Unnecessary array copy", "Use spread operator if possible", Severity.INFO),

            # Missing Lazy Loading
            (r'import\s+\{.*\}\s+from\s+["\'][^"\']+["\']', "Eager import", "Consider lazy loading", Severity.INFO),
            (r'require\s*\(\s*["\'][^"\']+["\']\s*\)', "Synchronous require", "Consider async import", Severity.INFO),

            # Inefficient Loops
            (r'for\s+\w+\s+in\s+range\s*\(\s*len\s*\(', "Iterating with range(len())", "Use enumerate() or direct iteration", Severity.INFO),
            (r'for\s*\(.*;\s*\w+\s*<\s*\w+\.length', "C-style for loop on array", "Use for...of or array methods", Severity.INFO),
            (r'\.forEach\s*\(\s*function\s*\(', "forEach with anonymous function", "Use arrow function", Severity.INFO),

            # Missing Break/Return
            (r'for\s+\w+\s+in.*:\s*\n.*(?:if|elif).*:\s*\n\s*\w+\.append\s*\(', "Appending in loop without early exit", "Consider adding break/return", Severity.INFO),

            # Sequential HTTP Requests
            (r'for\s+\w+\s+in.*:\s*\n\s*(?:requests|http|fetch|axios)', "Sequential HTTP requests", "Use async/await with Promise.all()", Severity.WARNING),
            (r'for\s+\w+\s+in.*:\s*\n\s*(?:urllib|httpx)', "Sequential HTTP requests", "Use asyncio.gather()", Severity.WARNING),

            # Missing Connection Reuse
            (r'requests\.(?:get|post|put|delete)\s*\(', "Request without session", "Use requests.Session()", Severity.INFO),
            (r'http\.client\.HTTPSConnection\s*\(', "Connection without pooling", "Use connection pooling", Severity.INFO),

            # Missing Timeout
            (r'requests\.(?:get|post|put|delete)\s*\([^)]*\)', "HTTP request without timeout", "Add timeout parameter", Severity.WARNING),
            (r'fetch\s*\([^)]*\)', "fetch() without timeout", "Add AbortController for timeout", Severity.WARNING),
            (r'axios\.(?:get|post|put|delete)\s*\([^)]*\)', "axios request without timeout", "Add timeout configuration", Severity.WARNING),
            (r'urllib\.request\.urlopen\s*\([^)]*\)', "urlopen without timeout", "Add timeout parameter", Severity.WARNING),

            # Synchronous File I/O
            (r'(?:open|read|write)\s*\(', "Synchronous file I/O", "Consider async I/O", Severity.INFO),
            (r'fs\.readFileSync\s*\(', "Synchronous file read", "Use fs.readFile()", Severity.WARNING),
            (r'fs\.writeFileSync\s*\(', "Synchronous file write", "Use fs.writeFile()", Severity.WARNING),

            # Missing Compression
            (r'(?:get|post|put|delete)\s*\([^)]*\)', "HTTP request without compression", "Enable compression", Severity.INFO),

            # Large Payload
            (r'res\.json\s*\(\s*\)', "Parsing large JSON response", "Consider streaming parser", Severity.INFO),
            (r'json\.loads\s*\(', "Parsing large JSON", "Consider ijson for streaming", Severity.INFO),

            # Nested Loops
            (r'for\s+\w+\s+in\s+\w+.*:\s*\n(?:\s+.*\n)*?\s+for\s+\w+\s+in\s+\w+', "Nested loops detected", "Consider O(n^2) complexity", Severity.WARNING),
            (r'for\s*\(.*\{[^}]*for\s*\(', "Nested loops detected (JS)", "Consider O(n^2) complexity", Severity.WARNING),
            (r'for\s*\(.*\{[^}]*for\s*\(.*\{[^}]*for\s*\(', "Triple nested loops", "O(n^3) complexity", Severity.CRITICAL),

            # Inefficient Search
            (r'for\s+\w+\s+in\s+\w+.*:\s*\n\s*(?:if|elif)\s+\w+\s*==', "Linear search in loop", "Use dictionary/set for O(1) lookup", Severity.WARNING),
            (r'\.indexOf\s*\(\s*\w+\s*\)', "Linear search with indexOf", "Use Map/Set for O(1) lookup", Severity.INFO),
            (r'\.includes\s*\(\s*\w+\s*\)', "Linear search with includes", "Use Set for O(1) lookup", Severity.INFO),
            (r'\.find\s*\(\s*\w+\s+in', "Linear search with find", "Consider using index", Severity.INFO),

            # Repeated Computation
            (r'for\s+\w+\s+in.*:\s*\n.*len\s*\(', "len() called in loop", "Cache len() result", Severity.WARNING),
            (r'for\s+\w+\s+in.*:\s*\n.*\.count\s*\(', "count() called in loop", "Use Counter", Severity.WARNING),
            (r'for\s+\w+\s+in.*:\s*\n.*sorted\s*\(', "sorted() called in loop", "Sort once outside loop", Severity.WARNING),

            # Inefficient Data Structure
            (r'list\s*\(\s*\)', "Using list instead of deque for queue", "Use collections.deque", Severity.INFO),
            (r'\[\s*\]\s*\.append\s*\(\s*\w+\s*\)\s*\n.*\[\s*\]\s*\.pop\s*\(\s*0\s*\)', "List used as queue", "Use collections.deque", Severity.WARNING),
            (r'\.sort\s*\(\s*\)\s*\n\s*\w+\s*=\s*\w+\s*\[', "Sorting then slicing", "Use heapq.nsmallest()", Severity.INFO),

            # Recursive Without Memoization
            (r'def\s+(\w+).*:\s*\n(?:\s+.*\n)*?\s+\1\s*\(', "Recursive without memoization", "Add @lru_cache", Severity.WARNING),
            (r'function\s+(\w+).*\{[^}]*\1\s*\(', "Recursive without memoization (JS)", "Add memoization", Severity.INFO),

            # Missing Early Exit
            (r'if\s+\w+\s+in\s+\w+.*:\s*\n\s*\w+\.append\s*\(', "Conditional append without early exit", "Use list comprehension", Severity.INFO),

            # Repeated Property Access
            (r'self\.\w+\.\w+\s*\n.*self\.\w+\.\w+', "Repeated property access", "Cache property access in local variable", Severity.INFO),

            # Unnecessary Function Calls
            (r'(?:len|count|size)\s*\(\s*\w+\s*\)\s*>\s*0', "Length check instead of bool", "Use bool() or direct check", Severity.INFO),
            (r'(?:len|count|size)\s*\(\s*\w+\s*\)\s*==\s*0', "Length check instead of empty", "Use not or direct check", Severity.INFO),
            (r'(?:len|count|size)\s*\(\s*\w+\s*\)\s*!=\s*0', "Length check instead of non-empty", "Use bool() or direct check", Severity.INFO),

            # Missing Vectorization
            (r'for\s+\w+\s+in\s+range\s*\(\s*len\s*\(.*\)\s*\)', "Index-based loop", "Use vectorized operations if possible", Severity.INFO),
            (r'for\s+\w+\s+in\s+range\s*\(\s*\w+\.shape\s*\[\s*0\s*\]\s*\)', "Index-based loop on array", "Use vectorized operations", Severity.INFO),

            # Missing Parallelism
            (r'for\s+\w+\s+in\s+\w+.*:\s*\n\s*\w+\s*=\s*\w+\s*\(', "Sequential processing in loop", "Consider parallel processing", Severity.INFO),
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
