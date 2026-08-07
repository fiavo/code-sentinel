"""
JavaScript/Node.js comprehensive rules.
"""
import re
from ..core.models import CodeIssue, Severity, IssueCategory
from ..core.rules import BaseRule


class JavaScriptLanguageRules(BaseRule):
    @property
    def name(self) -> str:
        return "javascript_language"
    @property
    def description(self) -> str:
        return "JavaScript-specific comprehensive patterns"
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
            # JS modern features
            (r"const\s+|let\s+", "Block scoping", "Good: block scoping", Severity.INFO),
            (r"=>\s*\{", "Arrow function", "Good: arrow function", Severity.INFO),
            (r"\.\.\.(\w+)", "Spread/rest operator", "Good: spread/rest", Severity.INFO),
            (r"`\$\{[^}]+\}`", "Template literal", "Good: template literals", Severity.INFO),
            (r"async\s+function|async\s+=>", "Async function", "Good: async function", Severity.INFO),
            (r"await\s+", "Await", "Good: await", Severity.INFO),
            (r"for\s*\(\s*(?:const|let)\s+\w+\s+of\s+", "for...of", "Good: for...of", Severity.INFO),
            (r"for\s*\(\s*(?:const|let)\s+\w+\s+in\s+", "for...in", "Good: for...in", Severity.INFO),
            (r"Object\.entries|Object\.keys|Object\.values|Object\.fromEntries", "Object methods", "Good: Object methods", Severity.INFO),
            (r"Array\.from|Array\.isArray|Array\.of|Array\.prototype", "Array methods", "Good: Array methods", Severity.INFO),
            (r"Promise\.all|Promise\.race|Promise\.allSettled|Promise\.any|Promise\.resolve|Promise\.reject", "Promise methods", "Good: Promise methods", Severity.INFO),
            (r"\.then\(|\.catch\(|\.finally\(", "Promise chaining", "Good: promise chaining", Severity.INFO),
            # JS anti-patterns
            (r"var\s+", "Var declaration", "Use const/let instead", Severity.WARNING),
            (r"==(?!=)", "Loose equality", "Use strict equality ===", Severity.WARNING),
            (r"!=(?!=)", "Loose inequality", "Use strict inequality !==", Severity.WARNING),
            (r"arguments\.callee", "arguments.callee", "Use named function", Severity.WARNING),
            (r"with\s*\(", "With statement", "Avoid with statement", Severity.WARNING),
            (r"eval\(", "eval usage", "Avoid eval", Severity.WARNING),
            (r"new\s+Function\(", "Function constructor", "Avoid Function constructor", Severity.WARNING),
            (r"setTimeout\(\s*['\"]", "String eval in setTimeout", "Use function instead", Severity.WARNING),
            (r"setInterval\(\s*['\"]", "String eval in setInterval", "Use function instead", Severity.WARNING),
            (r"\bvoid\s+0\b", "void 0", "Use undefined", Severity.INFO),
            (r"typeof\s+\w+\s*===?\s*['\"]undefined['\"]", "typeof undefined check", "Use === undefined", Severity.INFO),
            # JS frameworks
            (r"React\.|useState|useEffect|useContext|useReducer|useMemo|useCallback|useRef|useLayoutEffect|useImperativeHandle|useDebugValue|useDeferredValue|useTransition|useId|useSyncExternalStore|useInsertionEffect", "React hooks", "Good: React hooks", Severity.INFO),
            (r"createContext|createRef|forwardRef|memo|lazy|startTransition|Suspense|Fragment|Portal|StrictMode|Profiler", "React features", "Good: React features", Severity.INFO),
            (r"Component|PureComponent|createElement|createRoot|hydrateRoot|render", "React class/render", "Good: React rendering", Severity.INFO),
            (r"Vue\.|ref\(|reactive\(|computed\(|watch\(|watchEffect\(|onMounted|onUnmounted|onUpdated|onBeforeMount|onBeforeUnmount|provide\(|inject\(", "Vue 3 composition API", "Good: Vue 3", Severity.INFO),
            (r"defineComponent|defineProps|defineEmits|defineExpose|defineSlots|defineModel|withDefaults", "Vue macros", "Good: Vue macros", Severity.INFO),
            (r"ngOnInit|ngOnDestroy|ngOnChanges|ngAfterViewInit|ngDoCheck|ngAfterContentInit|ngAfterContentChecked|ngAfterViewChecked", "Angular lifecycle", "Good: Angular lifecycle", Severity.INFO),
            (r"@Component|@Injectable|@Directive|@Pipe|@NgModule|@Input|@Output|@ViewChild|@ContentChild", "Angular decorators", "Good: Angular decorators", Severity.INFO),
            (r"useSelector|useDispatch|useStore|connect\(", "Redux/State", "Good: state management", Severity.INFO),
            (r"createSlice|createAsyncThunk|configureStore|createStore|combineReducers|applyMiddleware", "Redux toolkit", "Good: Redux toolkit", Severity.INFO),
            (r"atom\(|selector\(|useRecoilState|useRecoilValue|useSetRecoilState", "Recoil state", "Good: Recoil", Severity.INFO),
            (r"zustand|create\(\(|useStore", "Zustand state", "Good: Zustand", Severity.INFO),
            (r"jotai|atom\(|useAtom|useSetAtom|useAtomValue", "Jotai state", "Good: Jotai", Severity.INFO),
            (r"signal\(|computed\(|effect\(|untracked\(|toSignal\(|toObservable\(", "Signals", "Good: signals", Severity.INFO),
            # Node.js
            (r"require\(", "CommonJS require", "Good: require", Severity.INFO),
            (r"module\.exports|exports\.", "CommonJS exports", "Good: exports", Severity.INFO),
            (r"import\s+\w+\s+from\s+['\"]", "ESM import", "Good: ESM import", Severity.INFO),
            (r"export\s+(?:default\s+)?(?:function|const|class|let|var|async)", "ESM export", "Good: ESM export", Severity.INFO),
            (r"process\.env\.\w+", "Environment variable", "Good: env variable", Severity.INFO),
            (r"process\.exit|process\.kill|process\.abort", "Process exit", "Good: process management", Severity.INFO),
            (r"fs\.readFile|fs\.writeFile|fs\.appendFile|fs\.unlink|fs\.mkdir|fs\.readdir|fs\.stat|fs\.access", "File system", "Good: fs operations", Severity.INFO),
            (r"fs\.promises|fsPromises|require\(['\"]fs/promises['\"]\)", "Promise-based fs", "Good: promise-based fs", Severity.INFO),
            (r"http\.createServer|https\.createServer|express\(\)|app\.listen", "HTTP server", "Good: HTTP server", Severity.INFO),
            (r"app\.get\(|app\.post\(|app\.put\(|app\.delete\(|app\.patch\(|app\.use\(", "Express routes", "Good: Express routes", Severity.INFO),
            (r"router\.get\(|router\.post\(|router\.put\(|router\.delete\(|router\.patch\(|router\.use\(", "Express router", "Good: Express router", Severity.INFO),
            (r"middleware|Middleware", "Middleware pattern", "Good: middleware", Severity.INFO),
            (r"try\s*\{", "Try block", "Good: error handling", Severity.INFO),
            (r"catch\s*\(\s*\w+\s*\)", "Catch block", "Good: error handling", Severity.INFO),
            (r"finally\s*\{", "Finally block", "Good: error handling", Severity.INFO),
            (r"Error\.cause|new\s+\w+Error|Error\.captureStackTrace|Error\.stackTraceLimit", "Error handling", "Good: error handling", Severity.INFO),
            # Testing
            (r"describe\(|it\(|test\(|expect\(|assert\.|chai\.|jest\.|vitest\.|mocha\.", "Testing", "Good: testing", Severity.INFO),
            (r"beforeAll|afterAll|beforeEach|afterEach|beforeAll|afterAll", "Test lifecycle", "Good: test lifecycle", Severity.INFO),
            (r"jest\.mock|jest\.spyOn|jest\.fn|vi\.mock|vi\.spyOn|vi\.fn", "Test mocking", "Good: test mocking", Severity.INFO),
            (r"toMatchSnapshot|toMatchInlineSnapshot|toThrow|rejects|resolves", "Test matchers", "Good: test matchers", Severity.INFO),
            # TypeScript integration
            (r":\s*(?:string|number|boolean|null|undefined|any|unknown|never|void|object|symbol|bigint)", "TypeScript type", "Good: TypeScript types", Severity.INFO),
            (r"interface\s+\w+|type\s+\w+\s*=|enum\s+\w+|namespace\s+\w+|module\s+\w+", "TypeScript constructs", "Good: TypeScript constructs", Severity.INFO),
            (r"<\w+>", "TypeScript generics", "Good: TypeScript generics", Severity.INFO),
            (r"as\s+\w+|satisfies\s+\w+", "Type assertions", "Good: type assertions", Severity.INFO),
            (r"keyof|typeof|infer|readonly|partial|required|pick|omit|record|exclude|extract|nonNullable|parameters|returnType|instanceType|constructorParameters|awaited", "TypeScript utility types", "Good: utility types", Severity.INFO),
            # Package management
            (r"npm\s+install|npm\s+i|yarn\s+add|pnpm\s+add|bun\s+add", "Package install", "Good: package install", Severity.INFO),
            (r"package\.json", "Package.json", "Good: package.json", Severity.INFO),
            (r"node_modules|\.npm|\.yarn|\.pnpm|\.bun", "Package cache", "Good: package cache", Severity.INFO),
            (r"npx\s+|yarn\s+dlx\s+|pnpm\s+dlx\s+|bunx\s+", "Package execute", "Good: package execute", Severity.INFO),
            (r"npm\s+run|yarn\s+run|pnpm\s+run|bun\s+run", "Package script", "Good: package script", Severity.INFO),
            # Build tools
            (r"webpack|vite|rollup|esbuild|parcel|snowpack|turbopack|swc|babel|tsc|typescript|tsup|unbuild|farm", "Build tool", "Good: build tools", Severity.INFO),
            (r"tsconfig|vite\.config|webpack\.config|rollup\.config|babel\.config|jest\.config|vitest\.config|next\.config|nuxt\.config", "Config file", "Good: config files", Severity.INFO),
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
