"""
Comprehensive performance patterns for all languages.
"""
import re
from ..core.models import CodeIssue, Severity, IssueCategory
from ..core.rules import BaseRule


class PerformanceComprehensiveRules(BaseRule):
    @property
    def name(self) -> str:
        return "performance_comprehensive"
    @property
    def description(self) -> str:
        return "Comprehensive performance patterns"
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
            # N+1 queries
            (r"for\s+\w+\s+in\s+\w+\.query.*\.all\(\)", "N+1 query", "Use eager loading", Severity.WARNING),
            (r"for\s+\w+\s+in\s+\w+\.objects\.all\(\)", "N+1 query", "Use select_related/prefetch_related", Severity.WARNING),
            # Missing pagination
            (r"\.all\(\)\s*$", "Query without pagination", "Add .limit() or .paginate()", Severity.WARNING),
            (r"SELECT\s+\*\s+FROM", "SELECT *", "Select needed columns and add LIMIT", Severity.WARNING),
            # Missing bulk operations
            (r"for\s+\w+\s+in.*:\s*\n\s*\w+\.save\(\)", "Individual saves in loop", "Use bulk_create() or bulk_update()", Severity.WARNING),
            (r"for\s+\w+\s+in.*:\s*\n\s*\w+\.insert\(", "Individual inserts in loop", "Use bulk insert operations", Severity.WARNING),
            # Missing caching
            (r"SELECT.*FROM.*WHERE", "Query without cache", "Consider adding result caching", Severity.INFO),
            # Memory leaks
            (r"addEventListener\(|removeEventListener\(|\.on\(|\.off\(", "Event listener", "Ensure cleanup on unmount", Severity.WARNING),
            (r"setInterval\(", "setInterval", "Ensure clearInterval on cleanup", Severity.WARNING),
            (r"setTimeout\(", "setTimeout", "Ensure clearTimeout on cleanup", Severity.WARNING),
            (r"new\s+Worker\(", "Worker", "Call worker.terminate() when done", Severity.WARNING),
            (r"(?:global|window|globalThis)\.\w+\s*=", "Global variable", "Avoid global variables", Severity.WARNING),
            # Large object creation
            (r"Array\(\s*\d{6,}\s*\)", "Large array", "Consider lazy loading", Severity.WARNING),
            (r"new\s+Array\(\s*\d{6,}\s*\)", "Large array", "Consider lazy loading", Severity.WARNING),
            # String concatenation in loops
            (r"for\s+\w+\s+in.*:\s*\n\s*\w+\s*\+=\s*['\"]", "String concatenation in loop", "Use StringBuilder or list join", Severity.WARNING),
            # Inefficient loops
            (r"for\s+\w+\s+in\s+range\s*\(\s*len\(", "Iterating with range(len())", "Use enumerate() or direct iteration", Severity.INFO),
            (r"\.forEach\(\s*function\(", "forEach with function", "Use arrow function", Severity.INFO),
            # Sequential HTTP requests
            (r"for\s+\w+\s+in.*:\s*\n\s*(?:requests|http|fetch|axios)", "Sequential HTTP requests", "Use async/await with Promise.all()", Severity.WARNING),
            # Missing connection reuse
            (r"requests\.(?:get|post|put|delete)\(", "Request without session", "Use requests.Session()", Severity.INFO),
            # Missing timeout
            (r"fetch\([^)]*\)", "fetch() without timeout", "Add AbortController for timeout", Severity.WARNING),
            (r"axios\.(?:get|post|put|delete)\([^)]*\)", "axios without timeout", "Add timeout configuration", Severity.WARNING),
            # Synchronous file I/O
            (r"fs\.readFileSync\(", "Synchronous file read", "Use fs.readFile()", Severity.WARNING),
            (r"fs\.writeFileSync\(", "Synchronous file write", "Use fs.writeFile()", Severity.WARNING),
            # Large payload
            (r"res\.json\(\)", "Parsing large JSON", "Consider streaming parser", Severity.INFO),
            # Nested loops
            (r"for\s+\w+\s+in\s+\w+.*:\s*\n(?:\s+.*\n)*?\s+for\s+\w+\s+in\s+\w+", "Nested loops", "Consider O(n^2) complexity", Severity.WARNING),
            (r"for\s*\(.*\{[^}]*for\s*\(", "Nested loops (JS)", "Consider O(n^2) complexity", Severity.WARNING),
            # Inefficient search
            (r"for\s+\w+\s+in\s+\w+.*:\s*\n\s*(?:if|elif)\s+\w+\s*==", "Linear search in loop", "Use dictionary/set for O(1) lookup", Severity.WARNING),
            (r"\.indexOf\(\s*\w+\s*\)", "Linear search with indexOf", "Use Map/Set for O(1) lookup", Severity.INFO),
            (r"\.includes\(\s*\w+\s*\)", "Linear search with includes", "Use Set for O(1) lookup", Severity.INFO),
            # Repeated computation
            (r"for\s+\w+\s+in.*:\s*\n.*len\(", "len() in loop", "Cache len() result", Severity.WARNING),
            (r"for\s+\w+\s+in.*:\s*\n.*\.count\(", "count() in loop", "Use Counter", Severity.WARNING),
            (r"for\s+\w+\s+in.*:\s*\n.*sorted\(", "sorted() in loop", "Sort once outside loop", Severity.WARNING),
            # Inefficient data structure
            (r"list\(\)\.append\(", "List used as queue", "Use collections.deque", Severity.WARNING),
            # Recursive without memoization
            (r"def\s+(\w+).*:\s*\n(?:\s+.*\n)*?\s+\1\(", "Recursive without memoization", "Add @lru_cache", Severity.WARNING),
            # Missing early exit
            (r"if\s+\w+\s+in\s+\w+.*:\s*\n\s*\w+\.append\(", "Conditional append", "Use list comprehension", Severity.INFO),
            # Repeated property access
            (r"self\.\w+\.\w+\s*\n.*self\.\w+\.\w+", "Repeated property access", "Cache in local variable", Severity.INFO),
            # Unnecessary function calls
            (r"(?:len|count|size)\(\s*\w+\s*\)\s*>\s*0", "Length check instead of bool", "Use bool()", Severity.INFO),
            (r"(?:len|count|size)\(\s*\w+\s*\)\s*==\s*0", "Length check instead of empty", "Use not", Severity.INFO),
            # Missing vectorization
            (r"for\s+\w+\s+in\s+range\s*\(\s*len\(.*\)\s*\)", "Index-based loop", "Use vectorized operations", Severity.INFO),
            # Missing parallelism
            (r"for\s+\w+\s+in\s+\w+.*:\s*\n\s*\w+\s*=\s*\w+\(", "Sequential processing", "Consider parallel processing", Severity.INFO),
            # Database queries
            (r"SELECT.*FROM.*WHERE.*AND.*AND", "Complex query", "Add proper indexes", Severity.INFO),
            (r"SELECT.*FROM.*JOIN.*JOIN", "Multiple joins", "Consider denormalization", Severity.INFO),
            (r"SELECT.*COUNT\(\*\)", "COUNT(*) query", "Use COUNT(1) or estimated counts", Severity.INFO),
            # Caching
            (r"redis\.get|memcached\.get|cache\.get", "Cache hit", "Good: using cache", Severity.INFO),
            (r"redis\.set|memcached\.set|cache\.set", "Cache set", "Good: setting cache", Severity.INFO),
            (r"cache\.delete|cache\.invalidate", "Cache invalidation", "Good: cache invalidation", Severity.INFO),
            # Connection pooling
            (r"connection.?pool|pool.?size|pool_size|max.?connections|max_connections", "Connection pooling", "Good: connection pooling", Severity.INFO),
            # Lazy loading
            (r"lazy|Lazy|lazy_load|lazy_load|on.?demand|on_demand", "Lazy loading", "Good: lazy loading", Severity.INFO),
            # Batch processing
            (r"batch|Batch|batch_size|batch_size|chunk|Chunk|chunk_size|chunk_size", "Batch processing", "Good: batch processing", Severity.INFO),
            # Streaming
            (r"stream|Stream|streaming|Streaming|chunked|Chunked", "Streaming", "Good: streaming data", Severity.INFO),
            # Compression
            (r"compress|Compress|gzip|GZIP|deflate|DEFLATE|brotli|BROTLI|zstd|ZSTD", "Compression", "Good: compression", Severity.INFO),
            # Pagination
            (r"page|Page|PAGE|limit|Limit|LIMIT|offset|Offset|OFFSET|cursor|Cursor|CURSOR", "Pagination", "Good: pagination", Severity.INFO),
            # Indexing
            (r"CREATE\s+INDEX|add_index|addIndex|index.*on", "Indexing", "Good: database indexing", Severity.INFO),
            # Denormalization
            (r"denormalize|Denormalize|denormalized|Denormalized|redundant|Redundant", "Denormalization", "Good: denormalization", Severity.INFO),
            # Read replicas
            (r"read.?replica|readReplica|read_replica|primary.?replica", "Read replicas", "Good: read replicas", Severity.INFO),
            # Sharding
            (r"shard|Shard|sharding|Sharding|partition|Partition|partitioning|Partitioning", "Sharding", "Good: sharding", Severity.INFO),
            # CDN
            (r"CDN|cdn|content.?delivery|ContentDelivery|edge|Edge|cache|Cache", "CDN", "Good: CDN usage", Severity.INFO),
            # Load balancing
            (r"load.?balancer|loadBalancer|load_balancer|round.?robin|roundRobin|weighted|Weighted|least.?connections|leastConnections", "Load balancing", "Good: load balancing", Severity.INFO),
            # Auto-scaling
            (r"auto.?scale|autoScale|auto_scaling|scale.?out|scaleOut|scale_out|scale.?in|scaleIn|scale_in", "Auto-scaling", "Good: auto-scaling", Severity.INFO),
            # Resource pooling
            (r"pool|Pool|resource.?pool|resourcePool|object.?pool|objectPool|buffer.?pool|bufferPool", "Resource pooling", "Good: resource pooling", Severity.INFO),
            # Connection pooling
            (r"connection.?pool|connectionPool|connection_pool|db.?pool|dbPool|pool.?size|poolSize|pool_size", "Connection pooling", "Good: connection pooling", Severity.INFO),
            # Thread pooling
            (r"thread.?pool|threadPool|thread_pool|worker.?pool|workerPool|worker_pool|executor|Executor", "Thread pooling", "Good: thread pooling", Severity.INFO),
            # Caching strategies
            (r"cache.?aside|cacheAside|cache_aside|read.?through|readThrough|read_through|write.?through|writeThrough|write_through|write.?behind|writeBehind|write_behind|write.?back|writeBack|write_back", "Caching strategy", "Good: caching strategies", Severity.INFO),
            # Memoization
            (r"memoize|Memoize|memoization|Memoization|cache|Cache|lru_cache|lruCache|@cache|@lru_cache", "Memoization", "Good: memoization", Severity.INFO),
            # Lazy evaluation
            (r"lazy|Lazy|lazy.?eval|lazyEval|lazy_eval|deferred|Deferred|on.?demand|onDemand|on_demand", "Lazy evaluation", "Good: lazy evaluation", Severity.INFO),
            # Short-circuit evaluation
            (r"&&|\|\||if.*\?.*:|if.*and.*return|if.*or.*return", "Short-circuit", "Good: short-circuit evaluation", Severity.INFO),
            # Tail call optimization
            (r"tail.?call|tailCall|tail_call|TCO|tail.?recursion|tailRecursion|tail_recursion", "Tail call optimization", "Good: tail call optimization", Severity.INFO),
            # Iterators
            (r"iterator|Iterator|generator|Generator|yield|yield.*return", "Iterator/generator", "Good: iterators/generators", Severity.INFO),
            # Lazy sequences
            (r"lazy|Lazy|lazy.?seq|lazySeq|lazy_seq|lazy.?list|lazyList|lazy_list", "Lazy sequence", "Good: lazy sequences", Severity.INFO),
            # Memoization
            (r"memoize|Memoize|memoization|Memoization|cache|Cache|lru_cache|lruCache|@cache|@lru_cache", "Memoization", "Good: memoization", Severity.INFO),
            # Profiling
            (r"profiler|Profiler|profile|Profile|benchmark|Benchmark|bench|Bench|perf|Perf", "Profiling", "Good: profiling", Severity.INFO),
            # Optimization
            (r"optimize|Optimize|optimize|performance|Performance|fast|Fast|efficient|Efficient|speed|Speed", "Optimization", "Good: optimization", Severity.INFO),
        ]
        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith('#') or stripped.startswith('//'):
                continue
            for pattern, message, severity in patterns:
                if re.search(pattern, line):
                    issues.append(self._create_issue(
                        file_path=file_path, line=line_num, message=message,
                        suggestion=message, severity=severity, code_snippet=stripped,
                    ))
        return issues
