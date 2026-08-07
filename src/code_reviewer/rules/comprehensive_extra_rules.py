"""
Comprehensive extra rules for code analysis.
Contains patterns for database, frontend, DevOps, cloud, and more.
"""

import re
from typing import Optional

from ..core.models import CodeIssue, Severity, IssueCategory
from ..core.rules import BaseRule


class DatabaseExtraRules(BaseRule):
    """Extra database patterns."""

    @property
    def name(self) -> str:
        return "database_extra"

    @property
    def description(self) -> str:
        return "Extra database patterns"

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
            # ORM patterns
            (r'(?:ORM|model\.save|model\.delete|model\.update|model\.create|model\.find|model\.filter|model\.query|model\.all|model\.get|model\.first|model\.count|model\.exists|model\.aggregate|model\.bulk_create|model\.bulk_update|model\.prefetch|model\.select_related|model\.annotate|model\.values|model\.values_list|model\.only|model\.defer|model\.select_for_update|model\.create_many|model\.update_many|model\.delete_many|model\.upsert|model\.bulk_upsert)', "ORM operations", "Good: using ORM", Severity.INFO),
            # SQL patterns
            (r'(?:SELECT|INSERT|UPDATE|DELETE|CREATE|ALTER|DROP|TRUNCATE|INDEX|VIEW|PROCEDURE|FUNCTION|TRIGGER|EVENT|GRANT|REVOKE)', "SQL statement", "Good: writing SQL", Severity.INFO),
            (r'(?:JOIN|LEFT JOIN|RIGHT JOIN|INNER JOIN|OUTER JOIN|CROSS JOIN|FULL JOIN)', "SQL join", "Good: using SQL joins", Severity.INFO),
            (r'(?:WHERE|AND|OR|NOT|IN|BETWEEN|LIKE|IS NULL|IS NOT NULL|EXISTS|ANY|ALL|SOME)', "SQL condition", "Good: using SQL conditions", Severity.INFO),
            (r'(?:GROUP BY|ORDER BY|HAVING|LIMIT|OFFSET|UNION|INTERSECT|EXCEPT|DISTINCT|ALL|TOP|FETCH|ROWS|ONLY|NEXT|FIRST|PERCENT|WITH TIES)', "SQL clause", "Good: using SQL clauses", Severity.INFO),
            (r'(?:COUNT|SUM|AVG|MIN|MAX|COALESCE|NULLIF|IFNULL|IF|CASE|WHEN|THEN|ELSE|END|CAST|CONVERT|ROUND|FLOOR|CEIL|ABS|MOD|POWER|SQRT|LOG|EXP|LN|SIGN|RAND|NOW|CURDATE|CURTIME|DATE|TIME|DATETIME|YEAR|MONTH|DAY|HOUR|MINUTE|SECOND|DATEDIFF|DATE_ADD|DATE_SUB|DATE_FORMAT|STR_TO_DATE|EXTRACT|UNIX_TIMESTAMP|FROM_UNIXTIME|TIME_TO_SEC|SEC_TO_TIME|TIME_FORMAT|TIMEDIFF|ADDTIME|SUBTIME|MAKETIME|TIME|DATE|TIMESTAMP|INTERVAL|FORMAT|REPLACE|CONCAT|CONCAT_WS|SUBSTRING|SUBSTR|LEFT|RIGHT|UPPER|LOWER|TRIM|LTRIM|RTRIM|LENGTH|CHAR_LENGTH|LOCATE|INSTR|REVERSE|REPEAT|SPACE|LPAD|RPAD|ELT|FIELD|FIND_IN_SET|ASCII|CHAR|CONV|BIN|OCT|HEX|LCASE|UCASE|INITCAP|SOUNDEX|SPEATS|REGEXP|RLIKE)', "SQL function", "Good: using SQL functions", Severity.INFO),
            (r'(?:BEGIN|COMMIT|ROLLBACK|SAVEPOINT|RELEASE|START|SET)', "Transaction control", "Good: using transactions", Severity.INFO),
            (r'(?:AUTO_INCREMENT|SERIAL|IDENTITY|SEQUENCE|DEFAULT|NOT NULL|NULL|PRIMARY KEY|FOREIGN KEY|UNIQUE|CHECK|INDEX|CONSTRAINT|REFERENCES|ON DELETE|ON UPDATE|CASCADE|SET NULL|SET DEFAULT|RESTRICT|NO ACTION)', "Schema definition", "Good: defining schema", Severity.INFO),
            (r'(?:VARCHAR|CHAR|TEXT|BLOB|CLOB|NCHAR|NVARCHAR|BINARY|VARBINARY|BOOLEAN|BIT|TINYINT|SMALLINT|INT|INTEGER|BIGINT|FLOAT|DOUBLE|DECIMAL|NUMERIC|DATE|TIME|DATETIME|TIMESTAMP|INTERVAL|JSON|JSONB|XML|UUID|ARRAY|ENUM|SET|GEOMETRY|POINT|LINESTRING|POLYGON|MULTIPOINT|MULTILINESTRING|MULTIPOLYGON|GEOMETRYCOLLECTION)', "Data type", "Good: using data types", Severity.INFO),
            (r'(?:DATABASE|SCHEMA|TABLE|VIEW|INDEX|PROCEDURE|FUNCTION|TRIGGER|EVENT|GRANT|REVOKE)', "Database object", "Good: using database objects", Severity.INFO),
            (r'(?:EXPLAIN|ANALYZE|DESCRIBE|SHOW|USE|SET|RESET|PREPARE|EXECUTE|DEALLOCATE|LOCK|UNLOCK|FLUSH|PURGE|OPTIMIZE|REPAIR|CHECK|ANALYZE|VACUUM|REINDEX|CLONE|IMPORT|EXPORT)', "Database administration", "Good: using database commands", Severity.INFO),
            # Connection pool
            (r'(?:connection.*pool|pool.*size|max.*connections|idle.*timeout|connection.*timeout|reconnect|retry|failover|load.*balance|read.*replica|write.*primary|sharding|partitioning|replication|backup|restore|point.*time.*recovery|wal|archive|log.*shipping)', "Connection management", "Good: managing database connections", Severity.INFO),
            # Migration
            (r'(?:migration|alembic|flyway|liquibase|django\.db\.migrations|prisma\.migrate|typeorm|knex|sequelize|drizzle|pgm)', "Database migration", "Good: using migrations", Severity.INFO),
            # NoSQL patterns
            (r'(?:MongoDB|Cassandra|DynamoDB|CouchDB|Redis|Memcached|Elasticsearch|Neo4j|RethinkDB|ArangoDB|RavenDB|Firebase|Firestore|Firestore|Supabase|PlanetScale|TiDB|CockroachDB|YugabyteDB|Vitess|ProxySQL|MaxScale|HAProxy)', "NoSQL/NewSQL database", "Good: using modern databases", Severity.INFO),
            # Caching
            (r'(?:cache|redis|memcached|APC|OPcache|Varnish|Nginx|CDN|edge.*cache|browser.*cache|service.*worker|workbox|sw-precache)', "Caching strategy", "Good: using caching", Severity.INFO),
            # Monitoring
            (r'(?:monitor|metrics|prometheus|grafana|datadog|new.relic|app.dynamics|dynatrace|splunk|ELK|kibana|jaeger|zipkin|opentelemetry|openmetrics|statsd|graphite|collectd|telegraf|fluentd|fluentbit|logstash|filebeat|metricbeat|heartbeat|packetbeat|apm)', "Monitoring/Observability", "Good: monitoring system", Severity.INFO),
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


class FrontendExtraRules(BaseRule):
    """Extra frontend patterns."""

    @property
    def name(self) -> str:
        return "frontend_extra"

    @property
    def description(self) -> str:
        return "Extra frontend patterns"

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
            # React patterns
            (r'(?:useState|useEffect|useContext|useReducer|useMemo|useCallback|useRef|useImperativeHandle|useLayoutEffect|useDebugValue|useDeferredValue|useTransition|useId|useSyncExternalStore|useInsertionEffect)', "React hook", "Good: using React hooks", Severity.INFO),
            (r'(?:React\.createElement|React\.memo|React\.lazy|React\.Suspense|React\.Fragment|React\.createContext|React\.forwardRef|React\.createRef|React\.cloneElement|React\.isValidElement|React\.Children|React\.startTransition)', "React API", "Good: using React API", Severity.INFO),
            (r'(?:Component|PureComponent|FC|FunctionComponent|PropsWithChildren|ReactNode|ReactElement|RefObject|MutableRefObject|Dispatch|SetStateAction|Reducer|ReducerState|EffectCallback|DependencyList|RefCallback|LegacyRef)', "React type", "Good: using React types", Severity.INFO),
            # Vue patterns
            (r'(?:ref|reactive|computed|watch|watchEffect|onMounted|onUnmounted|onUpdated|onBeforeMount|onBeforeUnmount|onErrorCaptured|onActivated|onDeactivated|provide|inject|defineComponent|defineProps|defineEmits|defineExpose|defineModel|nextTick|toRef|toRefs|unref|isRef|customRef|triggerRef|shallowRef|shallowReactive|toRaw|markRaw|effectScope|getCurrentScope|onScopeDispose)', "Vue composition API", "Good: using Vue composition API", Severity.INFO),
            (r'(?:Vue\.createApp|Vue\.defineComponent|Vue\.defineAsyncComponent|Vue\.defineCustomElement|Vue\.defineEmits|Vue\.defineExpose|Vue\.defineProps|Vue\.defineSlots|Vue\.defineCustomWatcher|Vue\.defineModel|Vue\.defineOptions)', "Vue API", "Good: using Vue API", Severity.INFO),
            # Angular patterns
            (r'(?:@Component|@Injectable|@NgModule|@Directive|@Pipe|@Input|@Output|@HostBinding|@HostListener|@ContentChild|@ContentChildren|@ViewChild|@ViewChildren|@TemplateRef|@ViewContainerRef|@ElementRef|@QueryList|@ChangeDetectionStrategy|@ChangeDetectorRef|@NgZone|@ApplicationRef|@PlatformRef|@Injector|@Inject|@Optional|@Self|@SkipSelf|@Host)', "Angular decorator", "Good: using Angular decorators", Severity.INFO),
            # Svelte patterns
            (r'(?:onMount|onDestroy|beforeUpdate|afterUpdate|createEventDispatcher|tick|setContext|getContext|onSsr|beforeNavigate|afterNavigate|goto|page|navigating|updated|preloadData|prerender)', "Svelte lifecycle", "Good: using Svelte lifecycle", Severity.INFO),
            # State management
            (r'(?:Redux|createStore|combineReducers|applyMiddleware|compose|dispatch|getState|subscribe|Provider|connect|useSelector|useDispatch|useStore|createSlice|createAsyncThunk|configureStore|createListenerMiddleware|combineSlices|createAction|createReducer)', "Redux", "Good: using Redux", Severity.INFO),
            (r'(?:Zustand|create|useStore|devtools|persist|immer|subscribeWithSelector|combine)', "Zustand", "Good: using Zustand", Severity.INFO),
            (r'(?:Jotai|atom|useAtom|useSetAtom|useAtomValue|createStore|getDefaultStore|atomWithStorage|atomWithObservable|atomWithQuery|atomWithMutation|atomWithInfiniteQuery|loadable|selectAtom|atomFamily|atomWithDefault|atomWithReset|RESET)', "Jotai", "Good: using Jotai", Severity.INFO),
            (r'(?:Recoil|atom|selector|useRecoilState|useRecoilValue|useSetRecoilState|useRecoilCallback|useRecoilTransactionObserver|useRecoilRefresher_UNSTABLE|useRecoilStoreID|useRecoilValueLoadable|useRecoilStateLoadable|useRecoilCallbackTransaction)', "Recoil", "Good: using Recoil", Severity.INFO),
            (r'(?:MobX|makeObservable|makeAutoObservable|observable|computed|action|runInAction|reaction|autorun|when|configure|enforceActions|reaction|when|autorun)', "MobX", "Good: using MobX", Severity.INFO),
            (r'(?:Pinia|defineStore|storeToRefs|usePinia|createPinia|setActivePinia)', "Pinia", "Good: using Pinia", Severity.INFO),
            (r'(?:Vuex|createStore|createLogger|useStore|mapState|mapGetters|mapActions|mapMutations)', "Vuex", "Good: using Vuex", Severity.INFO),
            # UI frameworks
            (r'(?:Tailwind|className|classNames|clsx|cva|twMerge|twJoin|cn)', "Tailwind CSS", "Good: using Tailwind", Severity.INFO),
            (r'(?:Chakra|useDisclosure|useToast|useColorMode|useMediaQuery|useBreakpoint|extendTheme|createMultiStyleConfig)', "Chakra UI", "Good: using Chakra UI", Severity.INFO),
            (r'(?:MUI|makeStyles|withStyles|styled|useTheme|createTheme|ThemeProvider|styledEngine)', "MUI", "Good: using MUI", Severity.INFO),
            (r'(?:Ant|useForm|useFormInstance|Form\.Item|Button\.type|message\.success|notification\.open|Modal\.confirm|Drawer\.open|Select\.mode|Table\.columns|Upload\.beforeUpload)', "Ant Design", "Good: using Ant Design", Severity.INFO),
            # Testing
            (r'(?:describe|it|test|expect|beforeEach|afterEach|beforeAll|afterAll|mock|jest|vitest|cypress|playwright|testing-library|render|screen|fireEvent|waitFor|findByText|findByRole)', "Testing framework", "Good: using testing framework", Severity.INFO),
            (r'(?:@testing-library/react|@testing-library/jest-dom|@testing-library/user-event)', "Testing library", "Good: using Testing Library", Severity.INFO),
            # Build tools
            (r'(?:webpack|rollup|vite|esbuild|parcel|turbopack|swc|babel|typescript|tsconfig|jsconfig)', "Build tool", "Good: using build tool", Severity.INFO),
            (r'(?:eslint|prettier|stylelint|postcss|autoprefixer|tailwindcss|sass|less|stylus)', "Dev tools", "Good: using dev tools", Severity.INFO),
            # Performance
            (r'(?:React\.memo|useMemo|useCallback|lazy|Suspense|Transition|startTransition|DeferredValue|useDeferredValue|useTransition)', "React performance", "Good: optimizing React performance", Severity.INFO),
            (r'(?:IntersectionObserver|MutationObserver|ResizeObserver|PerformanceObserver|requestAnimationFrame|requestIdleCallback|cancelAnimationFrame|cancelIdleCallback)', "Performance API", "Good: using performance APIs", Severity.INFO),
            # PWA
            (r'(?:service.worker|workbox|sw-precache|sw-toolbox|manifest\.json|manifest\.webmanifest|Cache|CacheStorage|IndexedDB|localStorage|sessionStorage)', "PWA", "Good: using PWA features", Severity.INFO),
            # WebSocket
            (r'(?:WebSocket|ws://|wss://|Socket\.IO|socket\.io|pusher|ably|centrifuge)', "Real-time", "Good: using real-time communication", Severity.INFO),
            # GraphQL
            (r'(?:Apollo|useQuery|useMutation|useSubscription|useLazyQuery|useApolloClient|gql|graphql|ApolloClient|ApolloProvider|InMemoryCache|HttpLink|WebSocketLink|SplitLink)', "Apollo GraphQL", "Good: using Apollo", Severity.INFO),
            (r'(?:urql|useQuery|useMutation|useSubscription|createClient|dedupExchange|fetchExchange|cacheExchange|ssrExchange|subscriptionExchange)', "urql GraphQL", "Good: using urql", Severity.INFO),
            (r'(?:Relay|useFragment|useLazyLoadQuery|usePaginationFragment|useRefetchableFragment|useSubscription|usePreloadedQuery|fetchQuery|commitMutation|loadQuery|loadLazyQuery|requestSubscription)', "Relay GraphQL", "Good: using Relay", Severity.INFO),
            # i18n
            (r'(?:i18next|react-i18next|useTranslation|t\(|Trans|useI18next|changeLanguage|addResourceBundle)', "i18n", "Good: using i18n", Severity.INFO),
            (r'(?:vue-i18n|useI18n|createI18n|$t\(|$tc\(|$te\(|$tm\()', "Vue i18n", "Good: using Vue i18n", Severity.INFO),
            (r'(?:ngx-translate|TranslateModule|TranslateService|translate\.instant|translate\.stream|translate\.get)', "Angular i18n", "Good: using Angular i18n", Severity.INFO),
            # Accessibility
            (r'(?:aria-|role=|tabIndex|focus|blur|keydown|keyup|keypress|ScreenReader|VisuallyHidden|SkipLink|FocusTrap)', "Accessibility", "Good: ensuring accessibility", Severity.INFO),
            # Animation
            (r'(?:framer-motion|motion\.|useAnimation|useSpring|useTransform|useMotionValue|AnimatePresence|LayoutGroup|Reorder|LazyMotion|domAnimation|Animate)', "Framer Motion", "Good: using Framer Motion", Severity.INFO),
            (r'(?:react-spring|useSpring|useSprings|useTrail|useTransition|animated|interpolate|config|Spring)', "React Spring", "Good: using React Spring", Severity.INFO),
            (r'(?:GSAP|gsap\.|ScrollTrigger|ScrollToPlugin|Draggable|MotionPath|TextPlugin|Flip|ScrollSmoother)', "GSAP", "Good: using GSAP", Severity.INFO),
            # Routing
            (r'(?:react-router|useRoutes|useNavigate|useParams|useLocation|useSearchParams|NavLink|Link|Route|Routes|BrowserRouter|HashRouter|MemoryRouter|Router|Outlet|Navigate)', "React Router", "Good: using React Router", Severity.INFO),
            (r'(?:vue-router|useRouter|useRoute|createRouter|createWebHistory|createWebHashHistory|RouterLink|RouterView|NavigationGuard|beforeEach|afterEach|beforeResolve|beforeRouteEnter|beforeRouteUpdate|beforeRouteLeave)', "Vue Router", "Good: using Vue Router", Severity.INFO),
            (r'(?:@angular/router|RouterModule|RouterOutlet|RouterLink|RouterLinkActive|ActivatedRoute|NavigationEnd|NavigationStart|NavigationCancel|NavigationError|Routes|Route|CanActivate|CanDeactivate|Resolve|Guard)', "Angular Router", "Good: using Angular Router", Severity.INFO),
            (r'(?:next/router|next/navigation|useRouter|usePathname|useSearchParams|useParams|Link|NavLink|Router|Pages Router|App Router)', "Next.js Router", "Good: using Next.js Router", Severity.INFO),
            (r'(?:nuxt|useRouter|useRoute|navigateTo|abortNavigation|defineNuxtRouteMiddleware|definePageMeta|NuxtLink|NuxtPage|NuxtLayout|NuxtLoadingIndicator|NuxtErrorBoundary)', "Nuxt Router", "Good: using Nuxt Router", Severity.INFO),
            # Forms
            (r'(?:react-hook-form|useForm|useFormContext|useFieldArray|useWatch|Controller|FormProvider|useController|useFormState|FormState)', "React Hook Form", "Good: using React Hook Form", Severity.INFO),
            (r'(?:formik|useFormik|Formik|Field|ErrorMessage|Form|FastField|connect|withFormik|FormikConsumer|FormikContext|useField|FieldArray)', "Formik", "Good: using Formik", Severity.INFO),
            (r'(?:vuelidate|useVuelidate|required|email|minValue|maxValue|between|integer|decimal| minLength|maxLength|alpha|alphaNum|numeric|url)', "Vuelidate", "Good: using Vuelidate", Severity.INFO),
            (r'(?:vee-validate|useForm|useField|Field|ErrorMessage|Form|defineRule|configure|FormKit|formkit|createClient)', "VeeValidate", "Good: using VeeValidate", Severity.INFO),
            # Validation
            (r'(?:zod|z\.\w+|z\.string|z\.number|z\.boolean|z\.array|z\.object|z\.union|z\.enum|z\.literal|z\.nullable|z\.optional|z\.default|z\.transform|z\.refine|z\.superRefine|z\.pipe)', "Zod", "Good: using Zod for validation", Severity.INFO),
            (r'(?:yup|Yup|yup\.string|yup\.number|yup\.boolean|yup\.array|yup\.object|yup\.date|yup\.mixed|yup\.tuple|yup\.reach|yup\.setLocale|yup\.addMethod)', "Yup", "Good: using Yup for validation", Severity.INFO),
            (r'(?:joi|Joi|Joi\.string|Joi\.number|Joi\.boolean|Joi\.array|Joi\.object|Joi\.date|Joi\.alternatives|Joi\.any|Joi\.validate|Joi\.compile)', "Joi", "Good: using Joi for validation", Severity.INFO),
            (r'(?:superstruct|struct|object|string|number|boolean|array|union|optional|nullable|literal|pattern|length|min|max|refine|create|validate|is)', "Superstruct", "Good: using Superstruct", Severity.INFO),
            # HTTP clients
            (r'(?:axios|useFetch|ofetch|ky|got|node-fetch|cross-fetch|undici|wretch|superagent)', "HTTP client", "Good: using HTTP client", Severity.INFO),
            # Auth
            (r'(?:next-auth|NextAuth|useSession|signIn|signOut|getSession|getServerSession|getToken|withAuth|SessionProvider|useSWR|useSWRMutation)', "NextAuth", "Good: using NextAuth", Severity.INFO),
            (r'(?:clerk|useAuth|useUser|useSession|useSignIn|useSignUp|useClerk|SignedIn|SignedOut|SignInButton|SignUpButton|UserButton|OrganizationSwitcher|ClerkProvider)', "Clerk", "Good: using Clerk", Severity.INFO),
            (r'(?:supabase|createClient|useSession|useUser|signIn|signUp|signOut|onAuthStateChange|auth\.signIn|auth\.signUp|auth\.signOut|auth\.getUser|auth\.getSession|auth\.updateUser|auth\.admin)', "Supabase Auth", "Good: using Supabase Auth", Severity.INFO),
            # Charts
            (r'(?:recharts|nivo|visx|victory|chart\.js|d3|echarts|plotly|highcharts|amcharts)', "Charting library", "Good: using charting library", Severity.INFO),
            # State machines
            (r'(?:xstate|createMachine|interpret|assign|send|Actor|StateMachine|ActorRef|sendBack|raise|choose|pure|log|forwardTo|cancel)', "XState", "Good: using XState", Severity.INFO),
            (r'(?:robot|createMachine|interpret|action|guard|invoke|state|transition|event|context|action|service|effect)', "Robot", "Good: using Robot", Severity.INFO),
            # Utilities
            (r'(?:lodash|underscore|ramda|rambda|date-fns|dayjs|moment|luxon|ms|pretty-ms|human-id|nanoid|uuid|cuid|ulid|short-uuid|uuid-v4|isomorphic-ws|isomorphic-fetch|node-fetch|cross-fetch|abort-controller)', "Utility library", "Good: using utility library", Severity.INFO),
            # DevOps
            (r'(?:Vercel|Netlify|Cloudflare|Firebase|Supabase|Railway|Render|Fly\.io|DigitalOcean|Linode|AWS|Azure|GCP)', "Cloud platform", "Good: using cloud platform", Severity.INFO),
            (r'(?:Docker|docker-compose|Dockerfile|\.dockerignore|container|image|volume|network|build|run|push|pull|tag|inspect|logs|exec|cp|kill|stop|start|restart|rm|rmi|system|builder|manifest|swarm|service|node|config|secret)', "Docker", "Good: using Docker", Severity.INFO),
            (r'(?:Kubernetes|kubectl|k8s|Deployment|Service|Pod|Ingress|ConfigMap|Secret|StatefulSet|DaemonSet|CronJob|Job|Namespace|RBAC|Role|ClusterRole|Binding|ServiceAccount|PersistentVolume|PersistentVolumeClaim|StorageClass|Ingress|NetworkPolicy|PodSecurityPolicy)', "Kubernetes", "Good: using Kubernetes", Severity.INFO),
            (r'(?:Terraform|terraform|provider|resource|data|variable|output|module|backend|locals|provisioner|connection|provisioner|lifecycle|depends_on|count|for_each|conditional|splat|dynamic|block|element|file|templatefile|path|locals|terraform\.tfstate)', "Terraform", "Good: using Terraform", Severity.INFO),
            (r'(?:Ansible|ansible|playbook|role|task|handler|template|copy|file|lineinfile|blockinfile|service|package|yum|apt|pip|npm|git|command|shell|user|group|cron|sysctl|sysvinit|systemd|wait_for|uri|debug|assert|set_fact|register|when|with_items|loop|until|retries|delay|ignore_errors|become|become_user|become_method|tags|vars|defaults|files|templates|handlers|meta|tasks|pre_tasks|post_tasks)', "Ansible", "Good: using Ansible", Severity.INFO),
            (r'(?:GitHub Actions|github\.action|actions/checkout|actions/setup-node|actions/setup-python|actions/cache|actions/upload-artifact|actions/download-artifact|actions/labeler|actions/stale|actions/github-script|peaceiris/actions-gh-pages|codecov)', "GitHub Actions", "Good: using GitHub Actions", Severity.INFO),
            (r'(?:GitLab CI|gitlab-ci|stages|jobs|script|before_script|after_script|services|cache|artifacts|only|except|when|rules|environment|coverage|interruptible|retry|timeout|tags|image|allow_failure|needs|dependencies|trigger|include|extends)', "GitLab CI", "Good: using GitLab CI", Severity.INFO),
            (r'(?:Jenkins|Jenkinsfile|pipeline|agent|stages|stage|steps|post|always|success|failure|cleanup|environment|parameters|options|triggers|tools|input|parallel|script|sh|bat|echo|dir|withEnv|withCredentials|withAWS|node|docker)', "Jenkins", "Good: using Jenkins", Severity.INFO),
            (r'(?:CircleCI|circleci|version|jobs|steps|checkout|run|store_test_results|store_artifacts|deploy|filters|requires|context|orbs|commands|executors|workflows|matrix|parallelism|resource_class|docker|machine|macos|windows)', "CircleCI", "Good: using CircleCI", Severity.INFO),
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


class CloudDevOpsRules(BaseRule):
    """Cloud and DevOps patterns."""

    @property
    def name(self) -> str:
        return "cloud_devops"

    @property
    def description(self) -> str:
        return "Cloud and DevOps patterns"

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
            # AWS patterns
            (r'(?:aws|boto3|botocore|s3|ec2|lambda|dynamodb|sqs|sns|ses|ses|route53|cloudfront|cloudwatch|iam|kms|secrets\.manager|ssm|ssm\.parameter|ecs|eks|fargate|amplify|appsync|cognito|step\.functions|eventbridge|kinesis|firehose|glue|athena|redshift|rds|aurora|neptune|timestream|qldb|managed\.blockchain|elasticache|elasticsearch\.service|opensearch|msk|mq|docdb|memorydb)', "AWS service", "Good: using AWS", Severity.INFO),
            # GCP patterns
            (r'(?:gcp|gcloud|firebase|firestore|cloud\.functions|cloud\.run|cloud\.build|cloud\.storage|cloud\.sql|cloud\.pubsub|cloud\.bigquery|cloud\.dataflow|cloud\.dataproc|cloud\.composer|cloud\.spanner|cloud\.firestore|cloud\.memorystore|cloud\.dns|cloud\.cdn|cloud\.armor|cloud\.load|cloud\.armor|cloud\.monitoring|cloud\.logging|cloud\.trace|cloud\.profiler|cloud\.debugger|cloud\.scheduler|cloud\.tasks|cloud\.vision|cloud\.speech|cloud\.translate|cloud\.natural|cloud\.ml|ai\.platform|vertex\.ai|bigquery|datastore|datastore\.admin)', "GCP service", "Good: using GCP", Severity.INFO),
            # Azure patterns
            (r'(?:azure|azure\.functions|azure\.storage|azure\.sql|azure\.cosmos|azure\.redis|azure\.service|azure\.event|azure\.signalr|azure\.search|azure\.cognitive|azure\.form|azure\.document|azure\.video|azure\.speech|azure\.translation|azure\.bot|azure\.devops|azure\.pipelines|azure\.repos|azure\.artifacts|azure\.boards|azure\.test|azure\.monitor|azure\.log|azure\.application|azure\.keyvault|azure\.identity|azure\.credentials|azure\.management|azure\.resource|azure\.deploy|azure\.arm|azure\.bicep|azure\.terraform|azure\.ansible)', "Azure service", "Good: using Azure", Severity.INFO),
            # Serverless patterns
            (r'(?:serverless|sls|lambda|function\.handler|function\.context|function\.event|function\.callback|serverless\.yml|serverless\.ts|serverless\.js)', "Serverless", "Good: using serverless", Severity.INFO),
            (r'(?:netlify\.functions|netlify\.edge|netlify\.background|netlify\.blobs|netlify\.identity)', "Netlify", "Good: using Netlify", Severity.INFO),
            (r'(?:vercel\.functions|vercel\.edge|vercel\.blob|vercel\.kv|vercel\.postgres|vercel\.postgres\.edge|vercel\.redis|vercel\.cron|vercel\.analytics|vercel\.speed|vercel\.sentry)', "Vercel", "Good: using Vercel", Severity.INFO),
            (r'(?:cloudflare\.workers|cloudflare\.kv|cloudflare\.d1|cloudflare\.r2|cloudflare\.durable|cloudflare\.pages|cloudflare\.images|cloudflare\.stream|cloudflare\.analytics|cloudflare\.zaraz|cloudflare\.turnstile|cloudflare\.waf|cloudflare\.cdn|cloudflare\.dns|cloudflare\.email|cloudflare\.spectrum|cloudflare\.load|cloudflare\.ssl|cloudflare\.zero|cloudflare\.tunnel|cloudflare\.warp)', "Cloudflare", "Good: using Cloudflare", Severity.INFO),
            # Container orchestration
            (r'(?:kubernetes|kubectl|helm|kustomize|skaffold|tilt|devspace|docker|docker-compose|podman|containerd|cri-o|runc|buildah|buildkit)', "Container orchestration", "Good: using container tools", Severity.INFO),
            # CI/CD
            (r'(?:Jenkins|GitLab|GitHub|CircleCI|Travis|Azure|Pipelines|ArgoCD|Flux|Tekton|Drone|Woodpecker|Buildkite|TeamCity|Bamboo|Buddy|Codeship|Bitbucket|Harness|Spinnaker|Octopus|Deploy)', "CI/CD", "Good: using CI/CD", Severity.INFO),
            # Monitoring
            (r'(?:Prometheus|Grafana|Datadog|New Relic|Dynatrace|Splunk|ELK|Jaeger|Zipkin|OpenTelemetry|OpenMetrics|StatsD|Graphite|CollectD|Telegraf|Fluentd|FluentBit|Logstash|Filebeat|Metricbeat|Heartbeat|Packetbeat|APM)', "Monitoring/Observability", "Good: using monitoring tools", Severity.INFO),
            # Security
            (r'(?:Vault|HashiCorp|Consul|Nomad|Waypoint|Boundary|Sentinel|Atlantis|Packer|Vagrant|Terraform|Terragrunt|Terratest|Checkov|tfsec|tflint|Snyk|SonarQube|OWASP|ZAP|Burp|Nmap|Metasploit|Cobalt|Nessus|Qualys|Rapid7)', "Security tool", "Good: using security tools", Severity.INFO),
            # Infrastructure
            (r'(?:Terraform|Terragrunt|Pulumi|Ansible|Chef|Puppet|SaltStack|CloudFormation|ARM|Bicep|CDK|SST|Crossplane)', "Infrastructure as Code", "Good: using IaC", Severity.INFO),
            # Service mesh
            (r'(?:Istio|Envoy|Linkerd|Consul|Cilium|Kong|Tyk|Traefik|NGINX|HAProxy|HAProxy|Varnish|Envoy|Istio|Linkerd|Consul|Kuma|Open Service|Mesh|Gloo|Ambassador|Emissary|Kong|Tyk|APISIX|Grafana|Tempo|Mimir|Loki|Pyroscope)', "Service mesh/API Gateway", "Good: using service mesh", Severity.INFO),
            # Message queues
            (r'(?:RabbitMQ|Kafka|NATS|Redis|Pulsar|ZeroMQ|ActiveMQ|IBM MQ|Amazon SQS|Amazon SNS|Google Pub/Sub|Azure Service Bus|Azure Queue)', "Message queue", "Good: using message queues", Severity.INFO),
            # Caching
            (r'(?:Redis|Memcached|Hazelcast|Ehcache|Caffeine|Guava|Aerospike|Dragonfly|KeyDB|Valkey)', "Caching system", "Good: using caching", Severity.INFO),
            # Search
            (r'(?:Elasticsearch|OpenSearch|Solr|Meilisearch|Typesense|Algolia|Splunk|Grafana Loki)', "Search engine", "Good: using search engine", Severity.INFO),
            # Analytics
            (r'(?:Google Analytics|Mixpanel|Amplitude|Segment|Heap|Hotjar|FullStory|LogRocket|PostHog|Plausible|Umami|Matomo)', "Analytics", "Good: using analytics", Severity.INFO),
            # Payment
            (r'(?:Stripe|PayPal|Braintree|Square|Adyen|Authorize\.net|Checkout|PaymentIntent|PaymentMethod|Customer|Subscription|Invoice|Webhook|Charge|Refund|Dispute|Payout|Connect|Identity|Radar|Tax|Terminal|Sigma|Climate|Issuing|Treasury|Financial Connections|Payment Links|Payment Request|SetupIntent)', "Payment processing", "Good: using payment processing", Severity.INFO),
            # Email
            (r'(?:SendGrid|Mailgun|Postmark|SES|SparkPost|Mailchimp|Brevo|Mailtrap|EmailOctopus|Moosend|MailerLite|ConvertKit)', "Email service", "Good: using email service", Severity.INFO),
            # CMS
            (r'(?:Contentful|Sanity|Strapi|Directus|Payload|Keystone|Ghost|WordPress|Drupal|Joomla|Netlify CMS|Decap|Storyblok|Contentstack|Kontent|Prismic|Butter)', "CMS", "Good: using CMS", Severity.INFO),
            # Storage
            (r'(?:S3|Cloud Storage|Azure Blob|MinIO|R2|DigitalOcean Spaces|Wasabi|B2|Backblaze|Google Drive|Dropbox|OneDrive)', "Cloud storage", "Good: using cloud storage", Severity.INFO),
            # Authentication
            (r'(?:Auth0|Firebase Auth|Supabase Auth|Cognito|Keycloak|Okta|Ping Identity|OneLogin|JumpCloud|Azure AD|AWS SSO|Duo|YubiKey|TOTP|OAuth|OIDC|SAML|JWT|session|cookie|token)', "Authentication", "Good: using authentication", Severity.INFO),
            # Feature flags
            (r'(?:LaunchDarkly|Split|Flagsmith|Unleash|Flipt|ConfigCat|Eppo|GrowthBook|Statsig|Harness|FeatureFlag|feature.*flag|toggle|experiment|A/B)', "Feature flags", "Good: using feature flags", Severity.INFO),
            # Error tracking
            (r'(?:Sentry|Bugsnag|Rollbar|Airbrake|LogRocket|Honeybadger|Errorception|TrackJS|ErrorStackr|Sentry)', "Error tracking", "Good: using error tracking", Severity.INFO),
            # Performance monitoring
            (r'(?:New Relic|Datadog|Dynatrace|AppDynamics|Elastic APM|Jaeger|Zipkin|OpenTelemetry|Prometheus|Grafana|Grafana Tempo)', "APM", "Good: using APM", Severity.INFO),
            # Documentation
            (r'(?:Swagger|OpenAPI|Postman|Insomnia|Hoppscotch|HTTPie|Thunder Client|REST Client|Bruno|Kong|Tyk|Stoplight)', "API documentation", "Good: documenting APIs", Severity.INFO),
            # Version control
            (r'(?:git|GitHub|GitLab|Bitbucket|Azure DevOps|Perforce|SVN|Mercurial|Subversion)', "Version control", "Good: using version control", Severity.INFO),
            # Package managers
            (r'(?:npm|yarn|pnpm|bun|pip|poetry|conda|cargo|go|mod|composer|gem|bundler|pub|mix|hex|nuget|maven|gradle|sbt|cocoapods|carthage|spm|homebrew|apt|yum|dnf|pacman|chocolatey|winget|scoop)', "Package manager", "Good: using package manager", Severity.INFO),
            # Runtime environments
            (r'(?:Node\.js|Deno|Bun|Python|Ruby|PHP|Java|Go|Rust|C\+\+|C#|Swift|Kotlin|Scala|Clojure|Elixir|Erlang|Haskell|OCaml|F#|Julia|R|MATLAB|SAS|SPSS|Stata|Lua|Perl|Tcl|Ada|Fortran|COBOL|Assembly)', "Runtime environment", "Good: using runtime environment", Severity.INFO),
            # Databases
            (r'(?:PostgreSQL|MySQL|MariaDB|SQLite|Oracle|SQL Server|DB2|MongoDB|Cassandra|DynamoDB|CouchDB|Redis|Memcached|Elasticsearch|Neo4j|RethinkDB|ArangoDB|RavenDB|Firebase|Firestore|Supabase|PlanetScale|TiDB|CockroachDB|YugabyteDB|Vitess|ProxySQL|MaxScale|ClickHouse|Druid|InfluxDB|TimescaleDB|QuestDB|DuckDB|Parquet|Iceberg|Delta Lake|Hudi)', "Database system", "Good: using databases", Severity.INFO),
        ]

        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith('#') or stripped.startswith('//'):
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
