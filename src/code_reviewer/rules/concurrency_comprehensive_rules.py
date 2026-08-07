"""
Comprehensive concurrency and async patterns for all languages.
"""
import re
from ..core.models import CodeIssue, Severity, IssueCategory
from ..core.rules import BaseRule


class ConcurrencyComprehensiveRules(BaseRule):
    @property
    def name(self) -> str:
        return "concurrency_comprehensive"
    @property
    def description(self) -> str:
        return "Comprehensive concurrency patterns"
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
            # Thread management
            (r"Thread|threading|Thread\.start|Thread\.join|Thread\.run", "Thread management", "Good: using threads", Severity.INFO),
            (r"pthread|pthread_create|pthread_join|pthread_mutex|pthread_cond", "POSIX threads", "Good: using POSIX threads", Severity.INFO),
            (r"goroutine|go\s+\w+|chan\s+\w+", "Goroutine/channel", "Good: using goroutines", Severity.INFO),
            (r"spawn|Task\.spawn|spawn_blocking|tokio::spawn", "Task spawning", "Good: spawning tasks", Severity.INFO),
            (r"std::thread|std::sync|std::async", "Rust threading", "Good: using Rust concurrency", Severity.INFO),
            (r"concurrent|Parallel|fork|join|async|await", "Concurrency", "Good: concurrency", Severity.INFO),
            # Locking
            (r"Lock|mutex|Mutex|synchronized|lock\.acquire|lock\.release", "Locking", "Good: using locks", Severity.INFO),
            (r"ReentrantLock|RLock|ReentrantReadWriteLock|StampedLock", "Reentrant lock", "Good: using reentrant locks", Severity.INFO),
            (r"Semaphore|BoundedSemaphore|Condition|Event|Barrier", "Synchronization", "Good: using synchronization", Severity.INFO),
            (r"AtomicInteger|AtomicLong|AtomicBoolean|AtomicReference|AtomicStampedReference", "Atomic operations", "Good: using atomic operations", Severity.INFO),
            (r"volatile|synchronized|transient", "Memory visibility", "Good: memory visibility", Severity.INFO),
            (r"MemoryBarrier|fence|atomic_thread_fence|atomic_signal_fence", "Memory fence", "Good: memory fences", Severity.INFO),
            # Async/await
            (r"async\s+fn|async\s+def|async\s+function|async\s+\w+", "Async function", "Good: using async", Severity.INFO),
            (r"await\s+\w+|\.await|\.then\(|\.catch\(|\.finally\(", "Await", "Good: using await", Severity.INFO),
            (r"Promise|Future|CompletableFuture|Task|asyncio\.Task", "Future/Promise", "Good: using futures", Severity.INFO),
            (r"tokio|async-std|smol|actix-rt", "Async runtime", "Good: using async runtime", Severity.INFO),
            (r"select!\(|select\s*\{|select\s*\(", "Select statement", "Good: using select", Severity.INFO),
            (r"mpsc|oneshot|broadcast|watch", "Channel type", "Good: using channels", Severity.INFO),
            # Parallelism
            (r"Parallel|parallel|fork|join|fork-join|work-stealing", "Parallelism", "Good: parallel processing", Severity.INFO),
            (r"ThreadPool|ExecutorService|ForkJoinPool|rayon|par_iter", "Thread pool", "Good: using thread pools", Severity.INFO),
            (r"map-reduce|MapReduce|map_reduce|fold|reduce", "MapReduce", "Good: map-reduce pattern", Severity.INFO),
            (r"data.?parallel|model.?parallel|pipeline.?parallel|tensor.?parallel", "Parallel strategy", "Good: parallel strategies", Severity.INFO),
            # Actor model
            (r"Actor|ActorRef|ActorSystem|Message|tell|ask|forward|pipeTo", "Actor model", "Good: using actor model", Severity.INFO),
            (r"Actor|ActorRef|ActorSystem|Message|tell|ask|forward|pipeTo", "Actor model", "Good: using actor model", Severity.INFO),
            # CSP
            (r"CSP|Communicating Sequential Processes|channel|go\s+\w+|chan", "CSP pattern", "Good: CSP pattern", Severity.INFO),
            # Event-driven
            (r"EventBus|EventEmitter|EventHandler|EventSource|EventLoop", "Event-driven", "Good: event-driven", Severity.INFO),
            (r"Observable|Observer|Subject|BehaviorSubject|ReplaySubject|AsyncSubject", "Observable pattern", "Good: using observables", Severity.INFO),
            (r"PubSub|Publish|Subscribe|Topic|Channel", "Pub/Sub", "Good: pub/sub pattern", Severity.INFO),
            # Reactive
            (r"Reactive|reactive|Observable|Flowable|Single|Maybe|Completable", "Reactive programming", "Good: reactive programming", Severity.INFO),
            (r"RxJava|RxJS|Reactor|RxKotlin|RxSwift|reactive-streams|Project.?Reactor", "Reactive library", "Good: using reactive library", Severity.INFO),
            (r"Backpressure|backpressure|back.?pressure|drop|buffer|latest", "Backpressure", "Good: backpressure handling", Severity.INFO),
            # Coroutines
            (r"Coroutine|coroutine|suspend|yield|generator|async.*generator", "Coroutine", "Good: using coroutines", Severity.INFO),
            (r"asyncio\.run|asyncio\.gather|asyncio\.create_task|asyncio\.ensure_future|asyncio\.wait|asyncio\.wait_for", "Python async", "Good: using Python async", Severity.INFO),
            (r"tokio::spawn|tokio::select|tokio::time|tokio::sync|tokio::fs|tokio::net", "Tokio async", "Good: using Tokio", Severity.INFO),
            (r"channel|mpsc|oneshot|broadcast|watch", "Channel", "Good: using channels", Severity.INFO),
            (r"RwLock|Mutex|Arc|Arc::new|Mutex::new|RwLock::new", "Shared state", "Good: shared state", Severity.INFO),
            (r"crossbeam|rayon|tokio|async-std|smol", "Concurrency crate", "Good: using concurrency crates", Severity.INFO),
            # Thread safety
            (r"Send|Sync|Arc|Mutex|RwLock|Pin|Unpin", "Thread safety", "Good: thread safety", Severity.INFO),
            (r"thread_local|thread_local!", "Thread-local storage", "Good: thread-local storage", Severity.INFO),
            (r"global|static\s+mut|static\s+", "Global state", "Avoid mutable globals", Severity.WARNING),
            (r"unsafe\s+fn|unsafe\s*\{", "Unsafe code", "Minimize unsafe code", Severity.WARNING),
            (r"data.?race|race.?condition|deadlock|livelock|starvation", "Concurrency bug", "Fix concurrency bugs", Severity.CRITICAL),
            (r"double.?check|double.?checked", "Double-checked locking", "Use proper synchronization", Severity.WARNING),
            (r"spin.?lock|SpinLock", "Spin lock", "Use OS-level locks", Severity.WARNING),
            (r"busy.?wait|busy.?loop", "Busy waiting", "Use proper synchronization", Severity.WARNING),
            (r"thread.?safe|thread.?unsafe|Send|Sync", "Thread safety", "Good: thread safety", Severity.INFO),
            (r"race.?condition|Race.?Condition", "Race condition", "Fix race conditions", Severity.CRITICAL),
            (r"deadlock|Deadlock", "Deadlock", "Fix deadlocks", Severity.CRITICAL),
            (r"livelock|Livelock", "Livelock", "Fix livelocks", Severity.CRITICAL),
            (r"starvation|Starvation", "Starvation", "Fix starvation", Severity.CRITICAL),
            (r"priority.?inversion|Priority.?Inversion", "Priority inversion", "Fix priority inversion", Severity.CRITICAL),
            (r"lock.?order|Lock.?Order", "Lock ordering", "Maintain lock ordering", Severity.WARNING),
            (r"trylock|try_lock|try_acquire", "Trylock", "Good: trylock pattern", Severity.INFO),
            (r"read.?write.?lock|RwLock|ReadWriteLock", "Read-write lock", "Good: read-write lock", Severity.INFO),
            (r"reader.?writer|ReaderWriter", "Reader-writer lock", "Good: reader-writer lock", Severity.INFO),
            (r"condition.?variable|ConditionVariable|condition_variable", "Condition variable", "Good: condition variable", Severity.INFO),
            (r"barrier|Barrier|CyclicBarrier|CountDownLatch|Phaser", "Barrier", "Good: barriers", Severity.INFO),
            (r"semaphore|Semaphore|CountingSemaphore|BinarySemaphore", "Semaphore", "Good: semaphores", Severity.INFO),
            (r"future|Future|Promise|Deferred|Task|CompletableFuture", "Future/Promise", "Good: futures", Severity.INFO),
            (r"async|await|yield|generator|coroutine", "Async/await", "Good: async/await", Severity.INFO),
            (r"channel|mpsc|oneshot|broadcast|watch|Channel", "Channel", "Good: channels", Severity.INFO),
            (r"producer|consumer|Producer|Consumer", "Producer-consumer", "Good: producer-consumer", Severity.INFO),
            (r"work.?queue|WorkQueue|task.?queue|TaskQueue", "Work queue", "Good: work queue", Severity.INFO),
            (r"thread.?pool|ThreadPool|worker.?pool|WorkerPool", "Thread pool", "Good: thread pool", Severity.INFO),
            (r"executor|Executor|ExecutorService|ScheduledExecutorService", "Executor", "Good: executor pattern", Severity.INFO),
            (r"dispatcher|Dispatcher|event.?loop|EventLoop", "Dispatcher/event loop", "Good: event loop", Severity.INFO),
            (r"async.?runtime|AsyncRuntime|tokio|async-std|smol", "Async runtime", "Good: async runtime", Severity.INFO),
            (r"green.?thread|GreenThread|goroutine|fiber|Fiber|green.?coroutine", "Green thread", "Good: green threads", Severity.INFO),
            (r"task.?spawning|spawn|TaskSpawn|spawn_blocking|spawn_local", "Task spawning", "Good: task spawning", Severity.INFO),
            (r"tokio::spawn|tokio::select|tokio::time|tokio::sync|tokio::fs|tokio::net|tokio::io", "Tokio", "Good: using Tokio", Severity.INFO),
            (r"rayon|par_iter|par_bridge|par_chunks|par_windows", "Rayon parallel", "Good: using Rayon", Severity.INFO),
            (r"crossbeam|channel|scope|queue|deque|atomic|epoch", "Crossbeam", "Good: using Crossbeam", Severity.INFO),
            (r"parking_lot|Mutex|RwLock|Condvar|Barrier|Semaphore|RwLock", "Parking lot", "Good: using parking_lot", Severity.INFO),
            (r"flume|channel|Sender|Receiver|bounded|unbounded", "Flume channel", "Good: using Flume", Severity.INFO),
            (r"async-channel|async-channel|Sender|Receiver|bounded|unbounded", "Async channel", "Good: async channels", Severity.INFO),
            (r"blocking|block_on|block_in_place|spawn_blocking", "Blocking", "Good: blocking operations", Severity.INFO),
            (r"async.?fn|async\s+fn|\.await|Future|Pin", "Async function", "Good: async functions", Severity.INFO),
        ]
        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith('#') or stripped.startswith('//'):
                continue
            for pattern, message, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    issues.append(self._create_issue(
                        file_path=file_path, line=line_num, message=message,
                        suggestion=message, severity=severity, code_snippet=stripped,
                    ))
        return issues
