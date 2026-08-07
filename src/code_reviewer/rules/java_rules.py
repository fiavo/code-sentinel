"""
Java-specific comprehensive rules.
"""
import re
from ..core.models import CodeIssue, Severity, IssueCategory
from ..core.rules import BaseRule


class JavaLanguageRules(BaseRule):
    @property
    def name(self) -> str:
        return "java_language"
    @property
    def description(self) -> str:
        return "Java-specific comprehensive patterns"
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
            # Java features
            (r"public\s+class\s+\w+", "Public class", "Good: public class", Severity.INFO),
            (r"private\s+class\s+\w+", "Private class", "Good: private class", Severity.INFO),
            (r"protected\s+class\s+\w+", "Protected class", "Good: protected class", Severity.INFO),
            (r"abstract\s+class\s+\w+", "Abstract class", "Good: abstract class", Severity.INFO),
            (r"final\s+class\s+\w+", "Final class", "Good: final class", Severity.INFO),
            (r"interface\s+\w+", "Interface definition", "Good: interface", Severity.INFO),
            (r"enum\s+\w+", "Enum definition", "Good: enum", Severity.INFO),
            (r"record\s+\w+", "Record definition", "Good: record", Severity.INFO),
            (r"sealed\s+class\s+\w+", "Sealed class", "Good: sealed class", Severity.INFO),
            (r"permits\s+\w+", "Permits clause", "Good: permits clause", Severity.INFO),
            # Java methods
            (r"public\s+\w+\s+\w+\(", "Public method", "Good: public method", Severity.INFO),
            (r"private\s+\w+\s+\w+\(", "Private method", "Good: private method", Severity.INFO),
            (r"protected\s+\w+\s+\w+\(", "Protected method", "Good: protected method", Severity.INFO),
            (r"static\s+\w+\s+\w+\(", "Static method", "Good: static method", Severity.INFO),
            (r"final\s+\w+\s+\w+\(", "Final method", "Good: final method", Severity.INFO),
            (r"abstract\s+\w+\s+\w+\(", "Abstract method", "Good: abstract method", Severity.INFO),
            (r"synchronized\s+\w+\s+\w+\(", "Synchronized method", "Good: synchronized method", Severity.INFO),
            (r"native\s+\w+\s+\w+\(", "Native method", "Good: native method", Severity.INFO),
            (r"default\s+\w+\s+\w+\(", "Default method", "Good: default method", Severity.INFO),
            # Java generics
            (r"<\w+>", "Generics", "Good: generics", Severity.INFO),
            (r"List<|Set<|Map<|Queue<|Deque<|Collection<|Optional<|Stream<|CompletableFuture<|CompletableFuture<", "Generic types", "Good: generic types", Severity.INFO),
            (r"Optional\.of\(|Optional\.empty\(|Optional\.ofNullable\(|\.orElse\(|\.orElseThrow\(|\.ifPresent\(|\.map\(|\.flatMap\(|\.filter\(|\.isPresent\(", "Optional usage", "Good: Optional usage", Severity.INFO),
            (r"stream\(\)|\.stream\(\)|\.parallelStream\(\)|\.collect\(|\.map\(|\.filter\(|\.flatMap\(|\.reduce\(|\.forEach\(|\.anyMatch\(|\.allMatch\(|\.noneMatch\(|\.findFirst\(|\.findAny\(|\.count\(|\.toList\(", "Stream API", "Good: Stream API", Severity.INFO),
            # Java exception handling
            (r"try\s*\{", "Try block", "Good: try block", Severity.INFO),
            (r"catch\s*\(\s*\w+", "Catch block", "Good: catch block", Severity.INFO),
            (r"finally\s*\{", "Finally block", "Good: finally block", Severity.INFO),
            (r"throw\s+new\s+\w+", "Throw exception", "Good: throw exception", Severity.INFO),
            (r"throws\s+\w+", "Throws declaration", "Good: throws declaration", Severity.INFO),
            (r"try-with-resources|AutoCloseable|Closeable|try\s*\(", "Try-with-resources", "Good: try-with-resources", Severity.INFO),
            # Java annotations
            (r"@\w+", "Annotation", "Good: annotation", Severity.INFO),
            (r"@Override|@Deprecated|@SuppressWarnings|@FunctionalInterface|@SafeVarargs", "Built-in annotation", "Good: built-in annotations", Severity.INFO),
            (r"@Autowired|@Component|@Service|@Repository|@Controller|@RestController|@Bean|@Configuration|@EnableAutoConfiguration|@SpringBootApplication", "Spring annotation", "Good: Spring annotations", Severity.INFO),
            (r"@Entity|@Table|@Column|@Id|@GeneratedValue|@OneToMany|@ManyToOne|@ManyToMany|@OneToOne|@JoinColumn|@Transient|@Embedded|@Embeddable", "JPA annotation", "Good: JPA annotations", Severity.INFO),
            # Java concurrency
            (r"Thread\.start\(\)|Thread\.join\(\)|Runnable|Callable|ExecutorService|CompletableFuture|synchronized|volatile|AtomicInteger|AtomicLong|AtomicBoolean|AtomicReference|CountDownLatch|CyclicBarrier|Semaphore|ReentrantLock|ReadWriteLock|StampedLock|ConcurrentHashMap|CopyOnWriteArrayList|BlockingQueue", "Concurrency", "Good: concurrency", Severity.INFO),
            # Java collections
            (r"ArrayList|LinkedList|HashMap|TreeMap|LinkedHashMap|HashSet|TreeSet|LinkedHashSet|Queue|Deque|PriorityQueue|ArrayDeque|Vector|Stack|Hashtable|Collections\.|Arrays\.", "Collection", "Good: collections", Severity.INFO),
            # Java I/O
            (r"InputStream|OutputStream|Reader|Writer|BufferedReader|BufferedWriter|FileReader|FileWriter|FileInputStream|FileOutputStream|ObjectInputStream|ObjectOutputStream|Scanner|PrintWriter", "I/O classes", "Good: I/O usage", Severity.INFO),
            (r"NIO|ByteBuffer|FileChannel|Selector|SocketChannel|ServerSocketChannel|Path\.|Files\.|Paths\.", "NIO usage", "Good: NIO usage", Severity.INFO),
            # Java tools
            (r"maven|Maven|gradle|Gradle|JUnit|junit|TestNG|Mockito|mockito|AssertJ|assertj|hamcrest|Hamcrest|PowerMock|powermock|WireMock|wiremock|RestAssured|restassured", "Java tools", "Good: Java tools", Severity.INFO),
            # Java patterns
            (r"Builder|builder|Factory|factory|Singleton|singleton|Observer|observer|Strategy|strategy|Decorator|decorator|Adapter|adapter|Proxy|proxy|Facade|facade|Command|command|Iterator|iterator|Visitor|visitor", "Design patterns", "Good: design patterns", Severity.INFO),
            # Modern Java
            (r"var\s+\w+\s*=", "Local variable type inference", "Good: var usage", Severity.INFO),
            (r"text\s+block|\"\"\"", "Text block", "Good: text blocks", Severity.INFO),
            (r"switch\s*\{", "Switch expression", "Good: switch expression", Severity.INFO),
            (r"case\s+\w+\s*->", "Arrow case", "Good: arrow case", Severity.INFO),
            (r"yield\s+\w+", "Yield in switch", "Good: yield", Severity.INFO),
            (r"record\s+\w+", "Record class", "Good: records", Severity.INFO),
            (r"sealed\s+class", "Sealed class", "Good: sealed classes", Severity.INFO),
            (r"pattern\s+matching|instanceof\s+\w+\s+\w+", "Pattern matching", "Good: pattern matching", Severity.INFO),
            (r"SequencedCollection|SequencedSet|SequencedMap", "Sequenced collections", "Good: Sequenced collections", Severity.INFO),
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
