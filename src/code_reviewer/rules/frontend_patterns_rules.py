"""
Frontend patterns for web development.
"""

import re
from typing import Optional

from ..core.models import CodeIssue, Severity, IssueCategory
from ..core.rules import BaseRule


class FrontendPatternsRules(BaseRule):
    """Frontend pattern detection."""

    @property
    def name(self) -> str:
        return "frontend_patterns"

    @property
    def description(self) -> str:
        return "Frontend pattern detection"

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
            (r"(?:useState|useEffect|useContext|useReducer|useMemo|useCallback|useRef|useImperativeHandle|useLayoutEffect|useDebugValue|useDeferredValue|useTransition|useId|useSyncExternalStore|useInsertionEffect)", "React hook", "Good: using React hooks", Severity.INFO),
            (r"(?:React\.createElement|React\.memo|React\.lazy|React\.Suspense|React\.Fragment|React\.createContext|React\.forwardRef|React\.createRef|React\.cloneElement|React\.isValidElement|React\.Children|React\.startTransition)", "React API", "Good: using React API", Severity.INFO),
            (r"(?:Component|PureComponent|FC|FunctionComponent|PropsWithChildren|ReactNode|ReactElement|RefObject|MutableRefObject|Dispatch|SetStateAction|Reducer|ReducerState|EffectCallback|DependencyList|RefCallback|LegacyRef)", "React type", "Good: using React types", Severity.INFO),

            # Vue patterns
            (r"(?:ref|reactive|computed|watch|watchEffect|onMounted|onUnmounted|onUpdated|onBeforeMount|onBeforeUnmount|onErrorCaptured|onActivated|onDeactivated|provide|inject|defineComponent|defineProps|defineEmits|defineExpose|defineModel|nextTick|toRef|toRefs|unref|isRef|customRef|triggerRef|shallowRef|shallowReactive|toRaw|markRaw|effectScope|getCurrentScope|onScopeDispose)", "Vue composition API", "Good: using Vue composition API", Severity.INFO),
            (r"(?:Vue\.createApp|Vue\.defineComponent|Vue\.defineAsyncComponent|Vue\.defineCustomElement|Vue\.defineEmits|Vue\.defineExpose|Vue\.defineProps|Vue\.defineSlots|Vue\.defineCustomWatcher|Vue\.defineModel|Vue\.defineOptions)", "Vue API", "Good: using Vue API", Severity.INFO),

            # Angular patterns
            (r"(?:@Component|@Injectable|@NgModule|@Directive|@Pipe|@Input|@Output|@HostBinding|@HostListener|@ContentChild|@ContentChildren|@ViewChild|@ViewChildren|@TemplateRef|@ViewContainerRef|@ElementRef|@QueryList|@ChangeDetectionStrategy|@ChangeDetectorRef|@NgZone|@ApplicationRef|@PlatformRef|@Injector|@Inject|@Optional|@Self|@SkipSelf|@Host)", "Angular decorator", "Good: using Angular decorators", Severity.INFO),

            # Svelte patterns
            (r"(?:onMount|onDestroy|beforeUpdate|afterUpdate|createEventDispatcher|tick|setContext|getContext|onSsr|beforeNavigate|afterNavigate|goto|page|navigating|updated|preloadData|prerender)", "Svelte lifecycle", "Good: using Svelte lifecycle", Severity.INFO),

            # State management
            (r"(?:Redux|createStore|combineReducers|applyMiddleware|compose|dispatch|getState|subscribe|Provider|connect|useSelector|useDispatch|useStore|createSlice|createAsyncThunk|configureStore|createListenerMiddleware|combineSlices|createAction|createReducer)", "Redux", "Good: using Redux", Severity.INFO),
            (r"(?:Zustand|create|useStore|devtools|persist|immer|subscribeWithSelector|combine)", "Zustand", "Good: using Zustand", Severity.INFO),
            (r"(?:Jotai|atom|useAtom|useSetAtom|useAtomValue|createStore|getDefaultStore|atomWithStorage|atomWithObservable|atomWithQuery|atomWithMutation|atomWithInfiniteQuery|loadable|selectAtom|atomFamily|atomWithDefault|atomWithReset|RESET)", "Jotai", "Good: using Jotai", Severity.INFO),
            (r"(?:Recoil|atom|selector|useRecoilState|useRecoilValue|useSetRecoilState|useRecoilCallback|useRecoilTransactionObserver|useRecoilRefresher_UNSTABLE|useRecoilStoreID|useRecoilValueLoadable|useRecoilStateLoadable|useRecoilCallbackTransaction)", "Recoil", "Good: using Recoil", Severity.INFO),
            (r"(?:MobX|makeObservable|makeAutoObservable|observable|computed|action|runInAction|reaction|autorun|when|configure|enforceActions|reaction|when|autorun)", "MobX", "Good: using MobX", Severity.INFO),
            (r"(?:Pinia|defineStore|storeToRefs|usePinia|createPinia|setActivePinia)", "Pinia", "Good: using Pinia", Severity.INFO),
            (r"(?:Vuex|createStore|createLogger|useStore|mapState|mapGetters|mapActions|mapMutations)", "Vuex", "Good: using Vuex", Severity.INFO),

            # UI frameworks
            (r"(?:Tailwind|className|classNames|clsx|cva|twMerge|twJoin|cn)", "Tailwind CSS", "Good: using Tailwind", Severity.INFO),
            (r"(?:Chakra|useDisclosure|useToast|useColorMode|useMediaQuery|useBreakpoint|extendTheme|createMultiStyleConfig)", "Chakra UI", "Good: using Chakra UI", Severity.INFO),
            (r"(?:MUI|makeStyles|withStyles|styled|useTheme|createTheme|ThemeProvider|styledEngine)", "MUI", "Good: using MUI", Severity.INFO),
            (r"(?:Ant|useForm|useFormInstance|Form\.Item|Button\.type|message\.success|notification\.open|Modal\.confirm|Drawer\.open|Select\.mode|Table\.columns|Upload\.beforeUpload)", "Ant Design", "Good: using Ant Design", Severity.INFO),

            # Testing
            (r"(?:describe|it|test|expect|beforeEach|afterEach|beforeAll|afterAll|mock|jest|vitest|cypress|playwright|testing-library|render|screen|fireEvent|waitFor|findByText|findByRole)", "Testing framework", "Good: using testing framework", Severity.INFO),
            (r"(?:@testing-library/react|@testing-library/jest-dom|@testing-library/user-event)", "Testing library", "Good: using Testing Library", Severity.INFO),

            # Build tools
            (r"(?:webpack|rollup|vite|esbuild|parcel|turbopack|swc|babel|typescript|tsconfig|jsconfig)", "Build tool", "Good: using build tool", Severity.INFO),
            (r"(?:eslint|prettier|stylelint|postcss|autoprefixer|tailwindcss|sass|less|stylus)", "Dev tools", "Good: using dev tools", Severity.INFO),

            # Performance
            (r"(?:React\.memo|useMemo|useCallback|lazy|Suspense|Transition|startTransition|DeferredValue|useDeferredValue|useTransition)", "React performance", "Good: optimizing React performance", Severity.INFO),
            (r"(?:IntersectionObserver|MutationObserver|ResizeObserver|PerformanceObserver|requestAnimationFrame|requestIdleCallback|cancelAnimationFrame|cancelIdleCallback)", "Performance API", "Good: using performance APIs", Severity.INFO),

            # PWA
            (r"(?:service.worker|workbox|sw-precache|sw-toolbox|manifest\.json|manifest\.webmanifest|Cache|CacheStorage|IndexedDB|localStorage|sessionStorage)", "PWA", "Good: using PWA features", Severity.INFO),

            # WebSocket
            (r"(?:WebSocket|ws://|wss://|Socket\.IO|socket\.io|pusher|ably|centrifuge)", "Real-time", "Good: using real-time communication", Severity.INFO),

            # GraphQL
            (r"(?:Apollo|useQuery|useMutation|useSubscription|useLazyQuery|useApolloClient|gql|graphql|ApolloClient|ApolloProvider|InMemoryCache|HttpLink|WebSocketLink|SplitLink)", "Apollo GraphQL", "Good: using Apollo", Severity.INFO),
            (r"(?:urql|useQuery|useMutation|useSubscription|createClient|dedupExchange|fetchExchange|cacheExchange|ssrExchange|subscriptionExchange)", "urql GraphQL", "Good: using urql", Severity.INFO),
            (r"(?:Relay|useFragment|useLazyLoadQuery|usePaginationFragment|useRefetchableFragment|useSubscription|usePreloadedQuery|fetchQuery|commitMutation|loadQuery|loadLazyQuery|requestSubscription)", "Relay GraphQL", "Good: using Relay", Severity.INFO),

            # i18n
            (r"(?:i18next|react-i18next|useTranslation|t\(|Trans|useI18next|changeLanguage|addResourceBundle)", "i18n", "Good: using i18n", Severity.INFO),
            (r"(?:vue-i18n|useI18n|createI18n|\$t\(|\$tc\(|\$te\(|\$tm\()", "Vue i18n", "Good: using Vue i18n", Severity.INFO),
            (r"(?:ngx-translate|TranslateModule|TranslateService|translate\.instant|translate\.stream|translate\.get)", "Angular i18n", "Good: using Angular i18n", Severity.INFO),

            # Accessibility
            (r"(?:aria-|role=|tabIndex|focus|blur|keydown|keyup|keypress|ScreenReader|VisuallyHidden|SkipLink|FocusTrap)", "Accessibility", "Good: ensuring accessibility", Severity.INFO),

            # Animation
            (r"(?:framer-motion|motion\.||useAnimation|useSpring|useTransform|useMotionValue|AnimatePresence|LayoutGroup|Reorder|LazyMotion|domAnimation|Animate)", "Framer Motion", "Good: using Framer Motion", Severity.INFO),
            (r"(?:react-spring|useSpring|useSprings|useTrail|useTransition|animated|interpolate|config|Spring)", "React Spring", "Good: using React Spring", Severity.INFO),
            (r"(?:GSAP|gsap\.||ScrollTrigger|ScrollToPlugin|Draggable|MotionPath|TextPlugin|Flip|ScrollSmoother)", "GSAP", "Good: using GSAP", Severity.INFO),

            # Routing
            (r"(?:react-router|useRoutes|useNavigate|useParams|useLocation|useSearchParams|NavLink|Link|Route|Routes|BrowserRouter|HashRouter|MemoryRouter|Router|Outlet|Navigate)", "React Router", "Good: using React Router", Severity.INFO),
            (r"(?:vue-router|useRouter|useRoute|createRouter|createWebHistory|createWebHashHistory|RouterLink|RouterView|NavigationGuard|beforeEach|afterEach|beforeResolve|beforeRouteEnter|beforeRouteUpdate|beforeRouteLeave)", "Vue Router", "Good: using Vue Router", Severity.INFO),
            (r"(?:@angular/router|RouterModule|RouterOutlet|RouterLink|RouterLinkActive|ActivatedRoute|NavigationEnd|NavigationStart|NavigationCancel|NavigationError|Routes|Route|CanActivate|CanDeactivate|Resolve|Guard)", "Angular Router", "Good: using Angular Router", Severity.INFO),
            (r"(?:next/router|next/navigation|useRouter|usePathname|useSearchParams|useParams|Link|NavLink|Router|Pages Router|App Router)", "Next.js Router", "Good: using Next.js Router", Severity.INFO),
            (r"(?:nuxt|useRouter|useRoute|navigateTo|abortNavigation|defineNuxtRouteMiddleware|definePageMeta|NuxtLink|NuxtPage|NuxtLayout|NuxtLoadingIndicator|NuxtErrorBoundary)", "Nuxt Router", "Good: using Nuxt Router", Severity.INFO),

            # Forms
            (r"(?:react-hook-form|useForm|useFormContext|useFieldArray|useWatch|Controller|FormProvider|useController|useFormState|FormState)", "React Hook Form", "Good: using React Hook Form", Severity.INFO),
            (r"(?:formik|useFormik|Formik|Field|ErrorMessage|Form|FastField|connect|withFormik|FormikConsumer|FormikContext|useField|FieldArray)", "Formik", "Good: using Formik", Severity.INFO),
            (r"(?:vuelidate|useVuelidate|required|email|minValue|maxValue|between|integer|decimal| minLength|maxLength|alpha|alphaNum|numeric|url)", "Vuelidate", "Good: using Vuelidate", Severity.INFO),
            (r"(?:vee-validate|useForm|useField|Field|ErrorMessage|Form|defineRule|configure|FormKit|formkit|createClient)", "VeeValidate", "Good: using VeeValidate", Severity.INFO),

            # Validation
            (r"(?:zod|z\.\w+|z\.string|z\.number|z\.boolean|z\.array|z\.object|z\.union|z\.enum|z\.literal|z\.nullable|z\.optional|z\.default|z\.transform|z\.refine|z\.superRefine|z\.pipe)", "Zod", "Good: using Zod for validation", Severity.INFO),
            (r"(?:yup|Yup|yup\.string|yup\.number|yup\.boolean|yup\.array|yup\.object|yup\.date|yup\.mixed|yup\.tuple|yup\.reach|yup\.setLocale|yup\.addMethod)", "Yup", "Good: using Yup for validation", Severity.INFO),
            (r"(?:joi|Joi|Joi\.string|Joi\.number|Joi\.boolean|Joi\.array|Joi\.object|Joi\.date|Joi\.alternatives|Joi\.any|Joi\.validate|Joi\.compile)", "Joi", "Good: using Joi for validation", Severity.INFO),
            (r"(?:superstruct|struct|object|string|number|boolean|array|union|optional|nullable|literal|pattern|length|min|max|refine|create|validate|is)", "Superstruct", "Good: using Superstruct", Severity.INFO),

            # HTTP clients
            (r"(?:axios|useFetch|ofetch|ky|got|node-fetch|cross-fetch|undici|wretch|superagent)", "HTTP client", "Good: using HTTP client", Severity.INFO),

            # Auth
            (r"(?:next-auth|NextAuth|useSession|signIn|signOut|getSession|getServerSession|getToken|withAuth|SessionProvider|useSWR|useSWRMutation)", "NextAuth", "Good: using NextAuth", Severity.INFO),
            (r"(?:clerk|useAuth|useUser|useSession|useSignIn|useSignUp|useClerk|SignedIn|SignedOut|SignInButton|SignUpButton|UserButton|OrganizationSwitcher|ClerkProvider)", "Clerk", "Good: using Clerk", Severity.INFO),
            (r"(?:supabase|createClient|useSession|useUser|signIn|signUp|signOut|onAuthStateChange|auth\.signIn|auth\.signUp|auth\.signOut|auth\.getUser|auth\.getSession|auth\.updateUser|auth\.admin)", "Supabase Auth", "Good: using Supabase Auth", Severity.INFO),

            # Charts
            (r"(?:recharts|nivo|visx|victory|chart\.js|d3|echarts|plotly|highcharts|amcharts)", "Charting library", "Good: using charting library", Severity.INFO),

            # State machines
            (r"(?:xstate|createMachine|interpret|assign|send|Actor|StateMachine|ActorRef|sendBack|raise|choose|pure|log|forwardTo|cancel)", "XState", "Good: using XState", Severity.INFO),
            (r"(?:robot|createMachine|interpret|action|guard|invoke|state|transition|event|context|action|service|effect)", "Robot", "Good: using Robot", Severity.INFO),

            # Utilities
            (r"(?:lodash|underscore|ramda|rambda|date-fns|dayjs|moment|luxon|ms|pretty-ms|human-id|nanoid|uuid|cuid|ulid|short-uuid|uuid-v4|isomorphic-ws|isomorphic-fetch|node-fetch|cross-fetch|abort-controller)", "Utility library", "Good: using utility library", Severity.INFO),

            # DevOps
            (r"(?:Vercel|Netlify|Cloudflare|Firebase|Supabase|Railway|Render|Fly\.io|DigitalOcean|Linode|AWS|Azure|GCP)", "Cloud platform", "Good: using cloud platform", Severity.INFO),
            (r"(?:Docker|docker-compose|Dockerfile|\.dockerignore|container|image|volume|network|build|run|push|pull|tag|inspect|logs|exec|cp|kill|stop|start|restart|rm|rmi|system|builder|manifest|swarm|service|node|config|secret)", "Docker", "Good: using Docker", Severity.INFO),
            (r"(?:Kubernetes|kubectl|k8s|Deployment|Service|Pod|Ingress|ConfigMap|Secret|StatefulSet|DaemonSet|CronJob|Job|Namespace|RBAC|Role|ClusterRole|Binding|ServiceAccount|PersistentVolume|PersistentVolumeClaim|StorageClass|Ingress|NetworkPolicy|PodSecurityPolicy)", "Kubernetes", "Good: using Kubernetes", Severity.INFO),
            (r"(?:Terraform|terraform|provider|resource|data|variable|output|module|backend|locals|provisioner|connection|provisioner|lifecycle|depends_on|count|for_each|conditional|splat|dynamic|block|element|file|templatefile|path|locals|terraform\.tfstate)", "Terraform", "Good: using Terraform", Severity.INFO),
            (r"(?:Ansible|ansible|playbook|role|task|handler|template|copy|file|lineinfile|blockinfile|service|package|yum|apt|pip|npm|git|command|shell|user|group|cron|sysctl|sysvinit|systemd|wait_for|uri|debug|assert|set_fact|register|when|with_items|loop|until|retries|delay|ignore_errors|become|become_user|become_method|tags|vars|defaults|files|templates|handlers|meta|tasks|pre_tasks|post_tasks)", "Ansible", "Good: using Ansible", Severity.INFO),
            (r"(?:GitHub Actions|github\.action|actions/checkout|actions/setup-node|actions/setup-python|actions/cache|actions/upload-artifact|actions/download-artifact|actions/labeler|actions/stale|actions/github-script|peaceiris/actions-gh-pages|codecov)", "GitHub Actions", "Good: using GitHub Actions", Severity.INFO),
            (r"(?:GitLab CI|gitlab-ci|stages|jobs|script|before_script|after_script|services|cache|artifacts|only|except|when|rules|environment|coverage|interruptible|retry|timeout|tags|image|allow_failure|needs|dependencies|trigger|include|extends)", "GitLab CI", "Good: using GitLab CI", Severity.INFO),
            (r"(?:Jenkins|Jenkinsfile|pipeline|agent|stages|stage|steps|post|always|success|failure|cleanup|environment|parameters|options|triggers|tools|input|parallel|script|sh|bat|echo|dir|withEnv|withCredentials|withAWS|node|docker)", "Jenkins", "Good: using Jenkins", Severity.INFO),
            (r"(?:CircleCI|circleci|version|jobs|steps|checkout|run|store_test_results|store_artifacts|deploy|filters|requires|context|orbs|commands|executors|workflows|matrix|parallelism|resource_class|docker|machine|macos|windows)", "CircleCI", "Good: using CircleCI", Severity.INFO),
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
