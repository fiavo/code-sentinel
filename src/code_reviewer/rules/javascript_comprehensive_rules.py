"""
Comprehensive JavaScript-specific rules.
"""

import re
from typing import Optional

from ..core.models import CodeIssue, Severity, IssueCategory
from ..core.rules import BaseRule


class JavaScriptComprehensiveRules(BaseRule):
    """JavaScript-specific comprehensive rules."""

    @property
    def name(self) -> str:
        return "javascript_comprehensive"

    @property
    def description(self) -> str:
        return "JavaScript-specific comprehensive rules"

    @property
    def category(self) -> IssueCategory:
        return IssueCategory.BEST_PRACTICE

    @property
    def severity(self) -> Severity:
        return Severity.INFO

    def check(self, file_path: str, content: str) -> list[CodeIssue]:
        if not file_path.endswith(('.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs')):
            return []

        issues = []
        lines = content.splitlines()

        patterns = [
            # JavaScript-specific patterns
            (r"(?:import|export|require|module\.exports)", "Module system", "Good: using modules", Severity.INFO),
            (r"(?:const|let|var|function|class|extends|super|new|this|self|typeof|instanceof|in|of|void|delete|yield|await|async|static|get|set)", "JavaScript keyword", "Good: using JS keywords", Severity.INFO),
            (r"(?:undefined|null|true|false|NaN|Infinity|\-Infinity)", "JavaScript value", "Good: using JS values", Severity.INFO),
            (r"(?:console\.log|console\.warn|console\.error|console\.info|console\.debug|console\.table|console\.time|console\.timeEnd|console\.count|console\.group|console\.groupEnd|console\.trace|console\.clear|console\.dir|console\.dirxml|console\.assert|console\.profile|console\.profileEnd|console\.timeStamp|console\.memory)", "Console method", "Good: using console", Severity.INFO),
            (r"(?:window\.document|document\.getElementById|document\.querySelector|document\.querySelectorAll|document\.createElement|document\.createTextNode|document\.createDocumentFragment|document\.addEventListener|document\.removeEventListener|document\.dispatchEvent|document\.createEvent|document\.createRange|document\.createTreeWalker|document\.createNodeIterator|document\.createComment|document\.createProcessingInstruction|document\.createAttribute|document\.createAttributeNS)", "DOM API", "Good: using DOM API", Severity.INFO),
            (r"(?:window\.location|window\.navigator|window\.history|window\.screen|window\.innerWidth|window\.innerHeight|window\.outerWidth|window\.outerHeight|window\.scrollX|window\.scrollY|window\.pageXOffset|window\.pageYOffset|window\.localStorage|window\.sessionStorage|window\.performance|window\.crypto|window\.fetch|window\.XMLHttpRequest|window\.WebSocket|window\.Worker|window\.ServiceWorker|window\.SharedWorker)", "Window API", "Good: using Window API", Severity.INFO),
            (r"(?:Array\.from|Array\.isArray|Array\.of|Array\.prototype|Array\.keys|Array\.values|Array\.entries|Array\.includes|Array\.find|Array\.findIndex|Array\.fill|Array\.copyWithin|Array\.flat|Array\.flatMap|Array\.sort|Array\.reverse|Array\.push|Array\.pop|Array\.shift|Array\.unshift|Array\.splice|Array\.concat|Array\.slice|Array\.join|Array\.toString|Array\.toLocaleString|Array\.reduce|Array\.reduceRight|Array\.filter|Array\.map|Array\.forEach|Array\.some|Array\.every)", "Array method", "Good: using Array methods", Severity.INFO),
            (r"(?:Object\.keys|Object\.values|Object\.entries|Object\.assign|Object\.create|Object\.defineProperty|Object\.defineProperties|Object\.freeze|Object\.seal|Object\.preventExtensions|Object\.is|Object\.getPrototypeOf|Object\.setPrototypeOf|Object\.getOwnPropertyDescriptor|Object\.getOwnPropertyDescriptors|Object\.getOwnPropertyNames|Object\.getOwnPropertySymbols|Object\.hasOwn|Object\.fromEntries)", "Object method", "Good: using Object methods", Severity.INFO),
            (r"(?:Promise\.all|Promise\.allSettled|Promise\.any|Promise\.race|Promise\.resolve|Promise\.reject|Promise\.try)", "Promise static", "Good: using Promise statics", Severity.INFO),
            (r"(?:Symbol\.for|Symbol\.keyFor|Symbol\.iterator|Symbol\.asyncIterator|Symbol\.hasInstance|Symbol\.isConcatSpreadable|Symbol\.species|Symbol\.toPrimitive|Symbol\.toStringTag|Symbol\.match|Symbol\.replace|Symbol\.search|Symbol\.split)", "Symbol", "Good: using Symbols", Severity.INFO),
            (r"(?:WeakMap|WeakSet|WeakRef|FinalizationRegistry|FinalizationRegistry\.register|FinalizationRegistry\.unregister)", "Weak references", "Good: using weak references", Severity.INFO),
            (r"(?:Proxy|Reflect\.get|Reflect\.set|Reflect\.has|Reflect\.deleteProperty|Reflect\.ownKeys|Reflect\.getOwnPropertyDescriptor|Reflect\.defineProperty|Reflect\.getPrototypeOf|Reflect\.setPrototypeOf|Reflect\.apply|Reflect\.construct|Reflect\.preventExtensions|Reflect\.isExtensible)", "Proxy/Reflect", "Good: using Proxy/Reflect", Severity.INFO),
            (r"(?:Map\.prototype|Set\.prototype|WeakMap\.prototype|WeakSet\.prototype|Map\.size|Set\.size|Map\.has|Set\.has|Map\.get|Set\.add|Map\.set|Set\.delete|Map\.delete|Map\.clear|Set\.clear|Map\.keys|Set\.keys|Map\.values|Set\.values|Map\.entries|Set\.entries|Map\.forEach|Set\.forEach)", "Collection method", "Good: using collections", Severity.INFO),
            (r"(?:RegExp\.prototype|RegExp\.test|RegExp\.exec|RegExp\.compile|RegExp\.flags|RegExp\.source|RegExp\.global|RegExp\.ignoreCase|RegExp\.multiline|RegExp\.sticky|RegExp\.unicode|RegExp\.dotAll)", "RegExp method", "Good: using RegExp", Severity.INFO),
            (r"(?:String\.prototype|String\.fromCharCode|String\.fromCodePoint|String\.raw|String\.prototype\.match|String\.prototype\.matchAll|String\.prototype\.replace|String\.prototype\.replaceAll|String\.prototype\.search|String\.prototype\.split|String\.prototype\.trim|String\.prototype\.trimStart|String\.prototype\.trimEnd|String\.prototype\.padStart|String\.prototype\.padEnd|String\.prototype\.repeat|String\.prototype\.startsWith|String\.prototype\.endsWith|String\.prototype\.includes|String\.prototype\.indexOf|String\.prototype\.lastIndexOf|String\.prototype\.slice|String\.prototype\.substring|String\.prototype\.substr|String\.prototype\.charAt|String\.prototype\.charCodeAt|String\.prototype\.codePointAt|String\.prototype\.normalize|String\.prototype\.normalize)", "String method", "Good: using String methods", Severity.INFO),
            (r"(?:Number\.isNaN|Number\.isFinite|Number\.isInteger|Number\.isSafeInteger|Number\.parseFloat|Number\.parseInt|Number\.MAX_VALUE|Number\.MIN_VALUE|Number\.MAX_SAFE_INTEGER|Number\.MIN_SAFE_INTEGER|Number\.EPSILON|Number\.NEGATIVE_INFINITY|Number\.POSITIVE_INFINITY|Number\.NaN)", "Number method", "Good: using Number methods", Severity.INFO),
            (r"(?:Math\.random|Math\.floor|Math\.ceil|Math\.round|Math\.trunc|Math\.sign|Math\.abs|Math\.sqrt|Math\.cbrt|Math\.pow|Math\.log|Math\.log2|Math\.log10|Math\.exp|Math\.max|Math\.min|Math\.sin|Math\.cos|Math\.tan|Math\.asin|Math\.acos|Math\.atan|Math\.atan2|Math\.sinh|Math\.cosh|Math\.tanh|Math\.asinh|Math\.acosh|Math\.atanh|Math\.hypot|Math\.imul|Math\.clz32|Math\.fround|Math\.E|Math\.LN10|Math\.LN2|Math\.LOG10E|Math\.LOG2E|Math\.PI|Math\.SQRT1_2|Math\.SQRT2)", "Math method", "Good: using Math methods", Severity.INFO),
            (r"(?:Date\.now|Date\.parse|Date\.UTC|Date\.prototype\.getTime|Date\.prototype\.getFullYear|Date\.prototype\.getMonth|Date\.prototype\.getDate|Date\.prototype\.getDay|Date\.prototype\.getHours|Date\.prototype\.getMinutes|Date\.prototype\.getSeconds|Date\.prototype\.getMilliseconds|Date\.prototype\.getTimezoneOffset|Date\.prototype\.getUTCFullYear|Date\.prototype\.getUTCMonth|Date\.prototype\.getUTCDate|Date\.prototype\.getUTCDay|Date\.prototype\.getUTCHours|Date\.prototype\.getUTCMinutes|Date\.prototype\.getUTCSeconds|Date\.prototype\.getUTCMilliseconds|Date\.prototype\.setTime|Date\.prototype\.setFullYear|Date\.prototype\.setMonth|Date\.prototype\.setDate|Date\.prototype\.setHours|Date\.prototype\.setMinutes|Date\.prototype\.setSeconds|Date\.prototype\.setMilliseconds|Date\.prototype\.setUTCFullYear|Date\.prototype\.setUTCMonth|Date\.prototype\.setUTCDate|Date\.prototype\.setUTCHours|Date\.prototype\.setUTCMinutes|Date\.prototype\.setUTCSeconds|Date\.prototype\.setUTCMilliseconds|Date\.prototype\.toISOString|Date\.prototype\.toDateString|Date\.prototype\.toTimeString|Date\.prototype\.toLocaleDateString|Date\.prototype\.toLocaleTimeString|Date\.prototype\.toLocaleString|Date\.prototype\.toString|Date\.prototype\.toUTCString|Date\.prototype\.valueOf|Date\.prototype\.getYear|Date\.prototype\.setYear)", "Date method", "Good: using Date methods", Severity.INFO),
            (r"(?:JSON\.parse|JSON\.stringify|JSON\.reviver|JSON\.replacer)", "JSON method", "Good: using JSON methods", Severity.INFO),
            (r"(?:console\.log|console\.warn|console\.error|console\.info|console\.debug|console\.table|console\.time|console\.timeEnd|console\.count|console\.group|console\.groupEnd|console\.trace|console\.clear|console\.dir|console\.dirxml|console\.assert|console\.profile|console\.profileEnd|console\.timeStamp|console\.memory)", "Console method", "Good: using console", Severity.INFO),
            (r"(?:fetch|XMLHttpRequest|axios|got|node-fetch|cross-fetch|undici|superagent|ky|ofetch)", "HTTP client", "Good: using HTTP client", Severity.INFO),
            (r"(?:setTimeout|setInterval|setImmediate|requestAnimationFrame|cancelAnimationFrame|requestIdleCallback|cancelIdleCallback)", "Timer", "Good: using timers", Severity.INFO),
            (r"(?:addEventListener|removeEventListener|dispatchEvent|EventTarget|Event|CustomEvent|MouseEvent|KeyboardEvent|TouchEvent|FocusEvent|WheelEvent|DragEvent|ClipboardEvent|AnimationEvent|TransitionEvent|InputEvent|CompositionEvent|MutationObserver|IntersectionObserver|ResizeObserver|PerformanceObserver|ReportingObserver)", "Event system", "Good: using events", Severity.INFO),
            (r"(?:WebSocket|Worker|SharedWorker|ServiceWorker|MessageChannel|MessagePort|BroadcastChannel|Notification|Geolocation|MediaDevices|MediaStream|RTCPeerConnection|RTCDataChannel|WebAssembly|WebGPU|WebBluetooth|WebUSB|WebSerial|WebHID|WebNFC|WebShare|WebLocks|WebCodecs|WebTransport|WebSockets|Web Workers)", "Web API", "Good: using Web APIs", Severity.INFO),
            (r"(?:module\.exports|exports\.|require\()", "CommonJS", "Good: using CommonJS", Severity.INFO),
            (r"(?:import\s*\{|import\s+\w|export\s+default|export\s+\{|export\s+\*)", "ES Modules", "Good: using ES Modules", Severity.INFO),
            (r"(?:async\s+function|await\s+|\.then\(|\.catch\(|\.finally\(|Promise\s*\()", "Async/Await", "Good: using async/await", Severity.INFO),
            (r"(?:try|catch|finally|throw|new\s+Error|Error\(|TypeError|RangeError|ReferenceError|SyntaxError|URIError|EvalError|AggregateError|InternalError)", "Error handling", "Good: handling errors", Severity.INFO),
            (r"(?:class\s+\w+|extends\s+\w+|super\(|super\.|constructor\()", "Class syntax", "Good: using class syntax", Severity.INFO),
            (r"(?:\=>\s*\{|\=>\s*[^{]|function\s*\(|function\s+\w+|\*\w+|async\s+function)", "Function syntax", "Good: using function syntax", Severity.INFO),
            (r"(?:\.map\(|\.filter\(|\.reduce\(|\.forEach\(|\.find\(|\.findIndex\(|\.some\(|\.every\(|\.includes\(|\.indexOf\(|\.lastIndexOf\(|\.flatMap\(|\.flat\()", "Array method", "Good: using array methods", Severity.INFO),
            (r"(?:\?\.|\?\?|\.\.\.|\*\*|~\s*|<<\s*|>>\s*|>>>\s*|&&\s*|\|\||\?\?\=|\.\.\=)", "Modern operator", "Good: using modern operators", Severity.INFO),
            (r"(?:\`[\s\S]*?\`|\$\{[\s\S]*?\})", "Template literal", "Good: using template literals", Severity.INFO),
            (r"(?:for\s*\(.*\bof\b|for\s*\(.*\bin\b|for\s*\(.*\bawait\b)", "Modern loop", "Good: using modern loops", Severity.INFO),
            (r"(?:const\s+\w+\s*=\s*\[|const\s+\w+\s*=\s*\{|const\s+\w+\s*=\s*\`)", "Modern variable", "Good: using modern variables", Severity.INFO),
            (r"(?:\w+\s*=\s*\.\.\.|\w+\s*=\s*\[\.\.\.|\w+\s*=\s*\{\.\.\.)", "Spread syntax", "Good: using spread syntax", Severity.INFO),
            (r"(?:\.\.\w+\)|\.\.\.\[|\.\.\.{)", "Rest syntax", "Good: using rest syntax", Severity.INFO),
            (r"(?:if\s*\(|else\s+if|else\s*\{|switch\s*\(|case\s+|default\s*:)", "Control flow", "Good: using control flow", Severity.INFO),
            (r"(?:for\s*\(|while\s*\(|do\s+\{|break|continue)", "Loop", "Good: using loops", Severity.INFO),
            (r"(?:try\s*\{|catch\s*\(|finally\s*\{)", "Try-catch", "Good: using try-catch", Severity.INFO),
            (r"(?:return\s+|yield\s+|await\s+|async\s+)", "Return/yield/await", "Good: using return/yield/await", Severity.INFO),
            (r"(?:function\s*\*|yield\*|async\s+function\s*\*)", "Generator", "Good: using generators", Severity.INFO),
            (r"(?:Proxy|Reflect|Symbol|WeakMap|WeakSet|WeakRef|FinalizationRegistry)", "Advanced feature", "Good: using advanced features", Severity.INFO),
            (r"(?:Map|Set|WeakMap|WeakSet)", "Collection", "Good: using collections", Severity.INFO),
            (r"(?:Promise|async|await)", "Promise", "Good: using promises", Severity.INFO),
            (r"(?:class|extends|super|constructor)", "Class", "Good: using classes", Severity.INFO),
            (r"(?:import|export|require|module)", "Module", "Good: using modules", Severity.INFO),
            (r"(?:let|const|var)", "Variable declaration", "Good: declaring variables", Severity.INFO),
            (r"(?:function|=>|arrow)", "Function", "Good: using functions", Severity.INFO),
            (r"(?:if|else|switch|case|default)", "Conditional", "Good: using conditionals", Severity.INFO),
            (r"(?:for|while|do|break|continue)", "Loop", "Good: using loops", Severity.INFO),
            (r"(?:try|catch|finally|throw)", "Error handling", "Good: handling errors", Severity.INFO),
            (r"(?:async|await|yield|return)", "Async/flow", "Good: using async/flow", Severity.INFO),
            (r"(?:new|delete|void|typeof|instanceof)", "Operator", "Good: using operators", Severity.INFO),
            (r"(?:===|!==|==|!=|<=|>=|<|>|&&|\|\||!)", "Comparison/logical", "Good: using operators", Severity.INFO),
            (r"(?:\+|\-|\*|\/|%|\*\*)", "Arithmetic", "Good: using arithmetic", Severity.INFO),
            (r"(?:\?\.|\?\?|\.\.\.|\*\*)", "Modern operator", "Good: using modern operators", Severity.INFO),
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
