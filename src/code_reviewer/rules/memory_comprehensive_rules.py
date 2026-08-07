"""
Comprehensive memory management patterns for all languages.
"""
import re
from ..core.models import CodeIssue, Severity, IssueCategory
from ..core.rules import BaseRule


class MemoryComprehensiveRules(BaseRule):
    @property
    def name(self) -> str:
        return "memory_comprehensive"
    @property
    def description(self) -> str:
        return "Comprehensive memory patterns"
    @property
    def category(self) -> IssueCategory:
        return IssueCategory.PERFORMANCE
    @property
    def severity(self) -> Severity:
        return Severity.INFO

    def check(self, file_path: str, content: str) -> list[CodeIssue]:
        issues = []
        lines = content.splitlines()
        patterns = [
            # Memory allocation
            (r"malloc|calloc|realloc|free|new|delete|new\[\]|delete\[\]", "C/C++ memory", "Good: memory management", Severity.INFO),
            (r"Arc::new|Rc::new|Box::new|Cell::new|RefCell::new|Cow::new", "Rust memory", "Good: Rust memory management", Severity.INFO),
            (r"Vec::new|HashMap::new|String::new|VecDeque::new", "Rust collections", "Good: Rust collections", Severity.INFO),
            (r"gc|GC|garbage.?collection|GarbageCollection", "Garbage collection", "Good: GC languages", Severity.INFO),
            (r"Arena|arena|region|Region|bump|Bump|slab|Slab", "Memory arena", "Good: memory arenas", Severity.INFO),
            (r"pool|Pool|object.?pool|ObjectPool|buffer.?pool|BufferPool", "Object pool", "Good: object pooling", Severity.INFO),
            (r"cache|Cache|L1|L2|L3|cache.?line|CacheLine", "Cache management", "Good: cache-aware code", Severity.INFO),
            (r"stack|Stack|heap|Heap|stack.?alloc|heap.?alloc", "Stack/heap", "Good: memory allocation", Severity.INFO),
            # Memory leaks
            (r"leak|Leak|LEAK|memory.?leak|MemoryLeak", "Memory leak", "Fix memory leaks", Severity.WARNING),
            (r"cyclic|cycle|circular|Circular|reference.?cycle|ReferenceCycle", "Reference cycle", "Fix reference cycles", Severity.WARNING),
            (r"weak.?ref|WeakRef|Weak|weak_ptr|WeakPointer", "Weak reference", "Good: weak references", Severity.INFO),
            (r"RAII|raii|Resource.?Acquisition", "RAII pattern", "Good: RAII", Severity.INFO),
            (r"smart.?ptr|SharedPtr|unique_ptr|weak_ptr|shared_ptr|Box|Rc|Arc", "Smart pointer", "Good: smart pointers", Severity.INFO),
            # Memory optimization
            (r"struct.?pack|struct.?padding|padding|alignment|alignas|alignof", "Struct packing", "Good: struct alignment", Severity.INFO),
            (r"compact|Compact|dense|Dense|bit.?pack|BitPack", "Memory compaction", "Good: memory compaction", Severity.INFO),
            (r"slab|Slab|arena|Arena|bump|Bump|region|Region", "Memory allocator", "Good: custom allocators", Severity.INFO),
            (r"jemalloc|tcmalloc|mimalloc|snmalloc|hoard", "Memory allocator library", "Good: using allocator library", Severity.INFO),
            (r"memory.?map|mmap|MapViewOfFile|MapViewOfFileEx", "Memory mapping", "Good: memory mapping", Severity.INFO),
            (r"copy.?on.?write|COW|CopyOnWrite|copy_on_write", "Copy-on-write", "Good: copy-on-write", Severity.INFO),
            # Buffer management
            (r"buffer|Buffer|ring.?buffer|RingBuffer|circular.?buffer|CircularBuffer", "Buffer", "Good: buffer management", Severity.INFO),
            (r"slice|Slice|view|View|borrow|Borrow", "Slicing", "Good: slicing", Severity.INFO),
            (r"string.?pool|StringPool|intern|Intern|symbol|Symbol", "String interning", "Good: string interning", Severity.INFO),
            (r"intern|Intern|string.?pool|StringPool|symbol.?table|SymbolTable", "String interning", "Good: string interning", Severity.INFO),
            # Garbage collection
            (r"gc|GC|garbage.?collector|GarbageCollector|mark.?sweep|MarkSweep|generational|Generational|concurrent.?gc|ConcurrentGC", "Garbage collection", "Good: GC", Severity.INFO),
            (r"reference.?counting|ReferenceCounting|refcount|RefCount|atomic.?refcount|AtomicRefCount", "Reference counting", "Good: reference counting", Severity.INFO),
            (r"weak.?reference|WeakReference|weak.?ptr|WeakPointer|weak|Weak", "Weak reference", "Good: weak references", Severity.INFO),
            # Memory pools
            (r"pool|Pool|object.?pool|ObjectPool|buffer.?pool|BufferPool|memory.?pool|MemoryPool|slab.?allocator|SlabAllocator|arena.?allocator|ArenaAllocator|bump.?allocator|BumpAllocator|region.?allocator|RegionAllocator", "Memory pool", "Good: memory pools", Severity.INFO),
            # Memory alignment
            (r"align|Align|ALIGN|alignof|alignas|__attribute__\(\(aligned", "Memory alignment", "Good: memory alignment", Severity.INFO),
            (r"cache.?line|CacheLine|cache.?friendly|CacheFriendly|data.?oriented|DataOriented", "Cache-friendly code", "Good: cache-friendly code", Severity.INFO),
            (r"contiguous|Contiguous|dense|Dense|compact|Compact", "Memory layout", "Good: memory layout", Severity.INFO),
            # Stack vs heap
            (r"stack|Stack|heap|Heap|stack.?alloc|heap.?alloc|stack.?overflow|StackOverflow|heap.?overflow|HeapOverflow", "Stack/heap", "Good: stack/heap awareness", Severity.INFO),
            (r"alloca|_alloca|VLAs|variable.?length.?array", "Stack allocation", "Use heap for large allocations", Severity.INFO),
            # Memory profiling
            (r"profiler|Profiler|valgrind|Valgrind|memcheck|Memcheck|heaptrack|Heaptrack|massif|Massif|dhat|DHAT", "Memory profiling", "Good: memory profiling", Severity.INFO),
            (r"leak.?sanitizer|LeakSanitizer|address.?sanitizer|AddressSanitizer|memory.?sanitizer|MemorySanitizer|thread.?sanitizer|ThreadSanitizer", "Sanitizer", "Good: using sanitizers", Severity.INFO),
            # Memory optimization
            (r"prefetch|__builtin_prefetch|_mm_prefetch|Prefetch|prefetcht0|prefetcht1|prefetcht2|prefetchnta", "Prefetching", "Good: prefetching", Severity.INFO),
            (r"intrinsics|SIMD|SSE|AVX|NEON|__m128|__m256|__m512|_mm_|_mm256_|_mm512_", "SIMD/intrinsics", "Good: using SIMD", Severity.INFO),
            (r"zero.?copy|ZeroCopy|zero_copy|sendfile|splice|vmsplice", "Zero-copy", "Good: zero-copy I/O", Severity.INFO),
            (r"scatter.?gather|ScatterGather|scatter_gather|iovec|WSABUF", "Scatter-gather", "Good: scatter-gather I/O", Severity.INFO),
            # Memory safety
            (r"bounds.?check|bounds_check|BoundsCheck|out.?of.?bounds|OutOfBounds|buffer.?overflow|BufferOverflow", "Bounds checking", "Good: bounds checking", Severity.INFO),
            (r"use.?after.?free|UseAfterFree|use_after_free|double.?free|DoubleFree|double_free|dangling.?pointer|DanglingPointer|dangling_pointer|wild.?pointer|WildPointer|wild_pointer|null.?pointer|NullPointer|null_pointer", "Memory safety", "Fix memory safety issues", Severity.CRITICAL),
            (r"memory.?leak|MemoryLeak|memory_leak|resource.?leak|ResourceLeak|resource_leak|handle.?leak|HandleLeak|handle_leak|fd.?leak|FDLeak|fd_leak", "Resource leak", "Fix resource leaks", Severity.WARNING),
            (r"stack.?overflow|StackOverflow|stack_overflow|stack.?exhaustion|StackExhaustion", "Stack overflow", "Fix stack overflow", Severity.CRITICAL),
            (r"heap.?overflow|HeapOverflow|heap_overflow|heap.?corruption|HeapCorruption|heap_corruption|buffer.?overflow|BufferOverflow|buffer_overflow|buffer.?overrun|BufferOverrun|buffer_overrun", "Heap corruption", "Fix heap corruption", Severity.CRITICAL),
            (r"uninitialized|Uninitialized|uninitialized_memory|UninitializedMemory|garbage.?data|GarbageData", "Uninitialized memory", "Initialize memory", Severity.WARNING),
            (r"alignment.?fault|AlignmentFault|alignment_fault|unaligned|Unaligned|unaligned_access|UnalignedAccess", "Alignment fault", "Fix alignment", Severity.WARNING),
            (r"page.?fault|PageFault|page_fault|soft.?page.?fault|SoftPageFault|hard.?page.?fault|HardPageFault", "Page fault", "Optimize memory access", Severity.INFO),
            # Memory mapping
            (r"mmap|munmap|mprotect|madvise|mincore|mlock|munlock|msync|mremap|MAP_SHARED|MAP_PRIVATE|MAP_ANONYMOUS|PROT_READ|PROT_WRITE|PROT_EXEC", "Memory mapping", "Good: memory mapping", Severity.INFO),
            (r"MapViewOfFile|UnmapViewOfFile|VirtualAlloc|VirtualFree|VirtualProtect|MapViewOfFileEx", "Windows memory", "Good: Windows memory management", Severity.INFO),
            (r"madvise|MADV_SEQUENTIAL|MADV_RANDOM|MADV_DONTNEED|MADV_WILLNEED|MADV_HUGEPAGE|MADV_NOHUGEPAGE", "Memory advice", "Good: memory advice", Severity.INFO),
            # Memory statistics
            (r"RSS|resident|VSZ|virtual|shared|heap|stack|VmRSS|VmSize|VmSwap|VmPeak", "Memory statistics", "Good: memory statistics", Severity.INFO),
            (r"/proc/meminfo|sysinfo|GlobalMemoryStatusEx|GetProcessMemoryInfo|mach_task_basic_info", "Memory info", "Good: memory info", Severity.INFO),
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
