"""
TypeScript-specific rules for code analysis.
Comprehensive rules for TypeScript error detection, type safety, and best practices.
"""

import re
from typing import Optional

from ..core.models import CodeIssue, Severity, IssueCategory
from ..core.rules import BaseRule


class TypeScriptRules(BaseRule):
    """TypeScript-specific error detection."""

    @property
    def name(self) -> str:
        return "typescript"

    @property
    def description(self) -> str:
        return "TypeScript error detection"

    @property
    def category(self) -> IssueCategory:
        return IssueCategory.STYLE

    @property
    def severity(self) -> Severity:
        return Severity.WARNING

    def check(self, file_path: str, content: str) -> list[CodeIssue]:
        # Skip if not TypeScript code
        ts_indicators = ['interface ', 'type ', 'enum ', 'declare ', ': string', ': number', ': boolean', ': any', ': void', 'readonly ', 'as ', 'satisfies ', 'keyof ', 'infer ', 'Extract<', 'Exclude<', 'Partial<', 'Required<', 'Pick<', 'Omit<', 'Record<', 'Promise<', 'Array<']
        is_ts = any(ind in content for ind in ts_indicators)
        if not is_ts:
            return []

        issues = []
        lines = content.splitlines()

        patterns = [
            # Type safety
            (r':\s*any\b', "Use of 'any' type", "Use specific types or 'unknown' instead", Severity.WARNING),
            (r'as\s+any\b', "Type assertion to 'any'", "Avoid 'any'; use specific types", Severity.WARNING),
            (r'@ts-ignore\b', "TypeScript directive @ts-ignore", "Fix the underlying type error instead", Severity.WARNING),
            (r'@ts-expect-error\b', "TypeScript directive @ts-expect-error", "Fix the underlying type error", Severity.INFO),
            (r'@ts-nocheck\b', "TypeScript directive @ts-nocheck", "Avoid disabling type checking globally", Severity.WARNING),
            (r'as\s+unknown\b', "Type assertion to 'unknown'", "Use proper type narrowing instead", Severity.INFO),
            (r'<any>', "Generic type 'any'", "Use specific types", Severity.WARNING),
            (r'Promise<any>', "Promise with 'any'", "Use Promise<unknown> or specific type", Severity.WARNING),
            (r'Array<any>', "Array with 'any'", "Use specific array type", Severity.WARNING),

            # Null safety
            (r'!\.', "Non-null assertion operator", "Use optional chaining (?.) or null checks", Severity.WARNING),
            (r'!\[', "Non-null assertion on index", "Add null check before indexing", Severity.WARNING),
            (r'as\s+\w+\s*\|', "Type assertion with union", "Use type narrowing or discriminated unions", Severity.INFO),
            (r'\w+\s*!\s*[^(]', "Non-null assertion", "Prefer null checks or optional chaining", Severity.INFO),
            (r'\?\.\w+', "Optional chaining", "Good: using optional chaining", Severity.INFO),
            (r'\?\?', "Nullish coalescing", "Good: using nullish coalescing", Severity.INFO),

            # Function issues
            (r'(?:function|const)\s+\w+\s*=\s*(?:async\s+)?(?:function|\()', "Function type annotation",
             "Add explicit return type", Severity.INFO),
            (r'(?:function|const)\s+\w+[^:]*\)\s*{', "Function without return type",
             "Add explicit return type for better type safety", Severity.INFO),
            (r'(?:async\s+function|async\s+\()', "Async function",
             "Ensure proper error handling for async functions", Severity.INFO),
            (r'\.\.\.\w+', "Rest parameters",
             "Good: using rest parameters", Severity.INFO),

            # Promise issues
            (r'new\s+Promise\s*\(\s*(?:async\s+)?\(', "Promise constructor",
             "Consider using async/await instead", Severity.INFO),
            (r'Promise\.(?:all|race|allSettled|any)\s*\(', "Promise combinators",
             "Good: using Promise combinators", Severity.INFO),
            (r'\.then\s*\(\s*(?:async\s+)?\(', "Promise .then()",
             "Consider using async/await", Severity.INFO),
            (r'\.catch\s*\(\s*\)', "Empty .catch() handler",
             "Add error handling logic", Severity.WARNING),
            (r'await\s+\w+\.json\s*\(\s*\)', "await response.json()",
             "Add error handling for JSON parsing", Severity.INFO),

            # Type narrowing
            (r'typeof\s+\w+\s*===', "typeof comparison",
             "Good: using typeof for type narrowing", Severity.INFO),
            (r'(?:instanceof|is\s+\w+)', "instanceof/is type guard",
             "Good: using type guards", Severity.INFO),
            (r'(?:in|keyof)', "in/keyof usage",
             "Good: using type-level operations", Severity.INFO),

            # Enum issues
            (r'enum\s+\w+', "Enum declaration",
             "Consider using const enum or union types", Severity.INFO),
            (r'(?:const|let)\s+\w+\s*=\s*\{[^}]+\}\s+as\s+const', "Const assertion",
             "Good: using const assertion for immutable objects", Severity.INFO),

            # Generic issues
            (r'(?:function|interface|type)\s+\w+\s*<\w+>', "Generic type parameter",
             "Good: using generics", Severity.INFO),
            (r'<T\s+extends\s+', "Constrained generic",
             "Good: using generic constraints", Severity.INFO),
            (r'Partial<', "Partial type",
             "Good: using built-in utility type", Severity.INFO),
            (r'Required<', "Required type",
             "Good: using built-in utility type", Severity.INFO),
            (r'Pick<', "Pick type",
             "Good: using built-in utility type", Severity.INFO),
            (r'Omit<', "Omit type",
             "Good: using built-in utility type", Severity.INFO),
            (r'Record<', "Record type",
             "Good: using built-in utility type", Severity.INFO),

            # Type import/export
            (r'(?:export|import)\s+type\s+', "Type import/export",
             "Good: using type-only imports/exports", Severity.INFO),
            (r'(?:export|import)\s+\{\s*type\s+', "Type import/export",
             "Good: using type-only imports/exports", Severity.INFO),

            # Decorator issues
            (r'@\w+\s*(?:\([^)]*\))?\s*\n\s*(?:class|function|method|property)', "Decorator usage",
             "Good: using decorators", Severity.INFO),

            # Module issues
            (r'export\s+(?:default|const|function|class|interface|type|enum)', "Module export",
             "Good: using module exports", Severity.INFO),
            (r'import\s+.*from\s+["\'][^"\']+["\']', "Module import",
             "Good: using module imports", Severity.INFO),
            (r'(?:import|export)\s+(?:type|value)\s+\{', "Type/value import/export",
             "Good: separating type and value imports", Severity.INFO),

            # Satisfies operator
            (r'satisfies\s+\w+', "Satisfies operator",
             "Good: using satisfies for type checking", Severity.INFO),

            # Assertion functions
            (r'function\s+\w+\s*\([^)]*\)\s*:\s*\w+\s+is\s+', "Assertion function",
             "Good: using assertion functions", Severity.INFO),

            # Conditional types
            (r'type\s+\w+\s*=\s*\w+\s+extends\s+', "Conditional type",
             "Good: using conditional types", Severity.INFO),

            # Mapped types
            (r'\{[^}]*\[K\s+in\s+', "Mapped type",
             "Good: using mapped types", Severity.INFO),

            # Template literal types
            (r'`[^`]*\$\{', "Template literal",
             "Good: using template literals", Severity.INFO),
            (r'type\s+\w+\s*=\s*`[^`]+`', "Template literal type",
             "Good: using template literal types", Severity.INFO),

            # Strict mode
            (r'strict\s*:\s*true', "TypeScript strict mode",
             "Good: enabling strict mode", Severity.INFO),
            (r'strictNullChecks\s*:\s*true', "strictNullChecks",
             "Good: enabling strict null checks", Severity.INFO),
            (r'strictFunctionTypes\s*:\s*true', "strictFunctionTypes",
             "Good: enabling strict function types", Severity.INFO),

            # Type-only imports
            (r'import\s+type\s+', "Type-only import",
             "Good: using type-only imports", Severity.INFO),
            (r'export\s+type\s+', "Type-only export",
             "Good: using type-only exports", Severity.INFO),

            # Utility types
            (r'Readonly<', "Readonly type",
             "Good: using Readonly utility type", Severity.INFO),
            (r'Pick<', "Pick type",
             "Good: using Pick utility type", Severity.INFO),
            (r'Omit<', "Omit type",
             "Good: using Omit utility type", Severity.INFO),
            (r'Record<', "Record type",
             "Good: using Record utility type", Severity.INFO),
            (r'Extract<', "Extract type",
             "Good: using Extract utility type", Severity.INFO),
            (r'Exclude<', "Exclude type",
             "Good: using Exclude utility type", Severity.INFO),
            (r'NonNullable<', "NonNullable type",
             "Good: using NonNullable utility type", Severity.INFO),
            (r'ReturnType<', "ReturnType type",
             "Good: using ReturnType utility type", Severity.INFO),
            (r'Parameters<', "Parameters type",
             "Good: using Parameters utility type", Severity.INFO),
            (r'ConstructorParameters<', "ConstructorParameters type",
             "Good: using ConstructorParameters utility type", Severity.INFO),
        ]

        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith('//') or stripped.startswith('*'):
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
