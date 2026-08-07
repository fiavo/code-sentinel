"""
TypeScript-specific comprehensive rules.
"""
import re
from ..core.models import CodeIssue, Severity, IssueCategory
from ..core.rules import BaseRule


class TypeScriptCompactRules(BaseRule):
    @property
    def name(self) -> str:
        return "typescript_compact"
    @property
    def description(self) -> str:
        return "TypeScript-specific comprehensive patterns"
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
            # TypeScript types
            (r":\s*(?:string|number|boolean|null|undefined|any|unknown|never|void|object|symbol|bigint)\b", "Primitive type", "Good: primitive type", Severity.INFO),
            (r"interface\s+\w+", "Interface", "Good: interface", Severity.INFO),
            (r"type\s+\w+\s*=", "Type alias", "Good: type alias", Severity.INFO),
            (r"enum\s+\w+", "Enum", "Good: enum", Severity.INFO),
            (r"namespace\s+\w+", "Namespace", "Good: namespace", Severity.INFO),
            (r"<\w+>", "Generics", "Good: generics", Severity.INFO),
            (r"as\s+\w+", "Type assertion", "Good: type assertion", Severity.INFO),
            (r"satisfies\s+\w+", "Satisfies", "Good: satisfies", Severity.INFO),
            (r"keyof\s+\w+", "Keyof", "Good: keyof", Severity.INFO),
            (r"typeof\s+\w+", "Typeof", "Good: typeof", Severity.INFO),
            (r"infer\s+\w+", "Infer", "Good: infer", Severity.INFO),
            (r"readonly\s+", "Readonly", "Good: readonly", Severity.INFO),
            (r"Partial<|Required<|Pick<|Omit<|Record<|Exclude<|Extract<|NonNullable<|ReturnType<|InstanceType<|Parameters<|ConstructorParameters<|Awaited<", "Utility types", "Good: utility types", Severity.INFO),
            (r"Optional\??:", "Optional property", "Good: optional property", Severity.INFO),
            (r"readonly\s+\w+\[?\]?", "Readonly array", "Good: readonly array", Severity.INFO),
            # TypeScript classes
            (r"class\s+\w+", "Class", "Good: class", Severity.INFO),
            (r"abstract\s+class\s+\w+", "Abstract class", "Good: abstract class", Severity.INFO),
            (r"implements\s+\w+", "Implements", "Good: implements", Severity.INFO),
            (r"extends\s+\w+", "Extends", "Good: extends", Severity.INFO),
            (r"constructor\(", "Constructor", "Good: constructor", Severity.INFO),
            (r"private\s+\w+|protected\s+\w+|public\s+\w+|readonly\s+\w+|static\s+\w+", "Access modifier", "Good: access modifiers", Severity.INFO),
            (r"declare\s+", "Declare", "Good: declare", Severity.INFO),
            # TypeScript functions
            (r"function\s+\w+\s*\(", "Function", "Good: function", Severity.INFO),
            (r"async\s+function\s+\w+\s*\(", "Async function", "Good: async function", Severity.INFO),
            (r"=>\s*\{|=>\s*\w+", "Arrow function", "Good: arrow function", Severity.INFO),
            (r"\w+\s*\([^)]*\):\s*\w+", "Return type annotation", "Good: return type", Severity.INFO),
            (r"\w+\s*\(\w+\s*:\s*\w+", "Parameter type annotation", "Good: parameter type", Severity.INFO),
            # TypeScript imports/exports
            (r"import\s+type\s+", "Type import", "Good: type imports", Severity.INFO),
            (r"export\s+type\s+", "Type export", "Good: type exports", Severity.INFO),
            (r"export\s+default\s+", "Default export", "Good: default export", Severity.INFO),
            (r"export\s+(?:const|function|class|interface|type|enum|namespace)", "Named export", "Good: named export", Severity.INFO),
            # TypeScript modules
            (r"declare\s+module\s+", "Module declaration", "Good: module declaration", Severity.INFO),
            (r"declare\s+global", "Global declaration", "Good: global declaration", Severity.INFO),
            (r"declare\s+namespace\s+\w+", "Namespace declaration", "Good: namespace declaration", Severity.INFO),
            # TypeScript decorators
            (r"@\w+\(\)|@\w+", "Decorator", "Good: decorator", Severity.INFO),
            # TypeScript conditional types
            (r"\w+\s+extends\s+\w+\s+\?\s*\w+\s*:\s*\w+", "Conditional type", "Good: conditional type", Severity.INFO),
            (r"infer\s+\w+", "Infer type", "Good: infer type", Severity.INFO),
            # TypeScript mapped types
            (r"\[K\s+in\s+keyof\s+\w+\]", "Mapped type", "Good: mapped type", Severity.INFO),
            (r"\[K\s+in\s+\w+\]", "Mapped type", "Good: mapped type", Severity.INFO),
            # TypeScript template literal types
            (r"`\$\{[^}]+\}`", "Template literal type", "Good: template literal types", Severity.INFO),
            # TypeScript assertions
            (r"as\s+const", "As const", "Good: as const", Severity.INFO),
            (r"satisfies\s+", "Satisfies", "Good: satisfies", Severity.INFO),
            (r"!", "Non-null assertion", "Minimize non-null assertions", Severity.WARNING),
            (r"\.as\s*\(", "Angle bracket assertion", "Good: angle bracket assertion", Severity.INFO),
            # TypeScript enums
            (r"enum\s+\w+\s*\{", "Enum", "Good: enum", Severity.INFO),
            (r"const\s+enum\s+\w+", "Const enum", "Good: const enum", Severity.INFO),
            # TypeScript utility patterns
            (r"<T\b|<T,|<T\s+extends", "Type parameter", "Good: type parameter", Severity.INFO),
            (r"extends\s+\w+\s+\?\s*\w+\s*:\s*\w+", "Conditional type", "Good: conditional type", Severity.INFO),
            (r"keyof\s+", "Keyof operator", "Good: keyof operator", Severity.INFO),
            (r"typeof\s+", "Typeof operator", "Good: typeof operator", Severity.INFO),
            (r"infer\s+", "Infer keyword", "Good: infer keyword", Severity.INFO),
            (r"\[.*\]\s+extends\s+\[", "Variadic tuple", "Good: variadic tuples", Severity.INFO),
            (r"Parameters<|ReturnType<|InstanceType<|ConstructorParameters<", "Reflection utility", "Good: reflection utilities", Severity.INFO),
            # TypeScript testing
            (r"describe\(|it\(|test\(|expect\(|assert\.", "Testing", "Good: testing", Severity.INFO),
            (r"jest\.|vitest\.", "Testing framework", "Good: testing framework", Severity.INFO),
            # TypeScript patterns
            (r"Promise<|Promise\.all|Promise\.race|Promise\.allSettled|Promise\.any", "Promise", "Good: promises", Severity.INFO),
            (r"async\s+fn|\.await\b", "Async/await", "Good: async/await", Severity.INFO),
            (r"<\w+\s*=\s*unknown>", "Default type parameter", "Good: default type", Severity.INFO),
            (r"string\s*\||number\s*\||boolean\s*\||null\s*\||undefined\s*\|", "Union type", "Good: union type", Severity.INFO),
            (r"&\s*\{", "Intersection type", "Good: intersection type", Severity.INFO),
            (r"Pick<|Omit<|Record<|Partial<|Required<|Readonly<|Exclude<|Extract<|NonNullable<|ReturnType<|InstanceType<|Parameters<|ConstructorParameters<|Awaited<", "Utility type", "Good: utility type", Severity.INFO),
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
