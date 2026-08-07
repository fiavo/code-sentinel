"""
Comprehensive code style patterns for all languages.
"""
import re
from ..core.models import CodeIssue, Severity, IssueCategory
from ..core.rules import BaseRule


class StyleComprehensiveRules(BaseRule):
    @property
    def name(self) -> str:
        return "style_comprehensive"
    @property
    def description(self) -> str:
        return "Comprehensive code style patterns"
    @property
    def category(self) -> IssueCategory:
        return IssueCategory.STYLE
    @property
    def severity(self) -> Severity:
        return Severity.INFO

    def check(self, file_path: str, content: str) -> list[CodeIssue]:
        issues = []
        lines = content.splitlines()
        patterns = [
            # Formatting
            (r"^\s{4,}(?! )", "Over-indented", "Use consistent indentation", Severity.INFO),
            (r"\t", "Tab character", "Use spaces for indentation", Severity.INFO),
            (r" +$", "Trailing whitespace", "Remove trailing whitespace", Severity.INFO),
            (r"\s+\)\s*$", "Space before closing paren", "Remove space before )", Severity.INFO),
            (r"\(\s+", "Space after opening paren", "Consider removing space after (", Severity.INFO),
            (r"def\s+\w+\s*\(", "Function definition", "Good: function definition", Severity.INFO),
            (r"class\s+\w+\s*[:\(]", "Class definition", "Good: class definition", Severity.INFO),
            (r"import\s+\w+", "Import statement", "Good: import statement", Severity.INFO),
            (r"from\s+\w+\s+import", "From import", "Good: from import", Severity.INFO),
            (r"return\s+\w+", "Return statement", "Good: return statement", Severity.INFO),
            (r"if\s+\w+\s*:", "If statement", "Good: if statement", Severity.INFO),
            (r"elif\s+\w+\s*:", "Elif statement", "Good: elif statement", Severity.INFO),
            (r"else\s*:", "Else statement", "Good: else statement", Severity.INFO),
            (r"for\s+\w+\s+in\s+\w+\s*:", "For loop", "Good: for loop", Severity.INFO),
            (r"while\s+\w+\s*:", "While loop", "Good: while loop", Severity.INFO),
            (r"try\s*:", "Try block", "Good: try block", Severity.INFO),
            (r"except\s+\w+", "Except clause", "Good: except clause", Severity.INFO),
            (r"finally\s*:", "Finally block", "Good: finally block", Severity.INFO),
            (r"with\s+\w+\s+as\s+\w+\s*:", "With statement", "Good: with statement", Severity.INFO),
            (r"raise\s+\w+", "Raise statement", "Good: raise statement", Severity.INFO),
            (r"assert\s+\w+", "Assert statement", "Good: assert statement", Severity.INFO),
            (r"pass\s*$", "Pass statement", "Consider adding implementation", Severity.INFO),
            (r"break\s*$", "Break statement", "Good: break statement", Severity.INFO),
            (r"continue\s*$", "Continue statement", "Good: continue statement", Severity.INFO),
            (r"global\s+\w+", "Global statement", "Avoid global variables", Severity.INFO),
            (r"nonlocal\s+\w+", "Nonlocal statement", "Good: nonlocal statement", Severity.INFO),
            (r"del\s+\w+", "Del statement", "Good: del statement", Severity.INFO),
            (r"yield\s+\w+", "Yield statement", "Good: yield statement", Severity.INFO),
            (r"yield\s+from\s+\w+", "Yield from", "Good: yield from", Severity.INFO),
            (r"await\s+\w+", "Await statement", "Good: await statement", Severity.INFO),
            (r"async\s+def\s+\w+", "Async def", "Good: async def", Severity.INFO),
            (r"lambda\s+\w+\s*:", "Lambda", "Good: lambda", Severity.INFO),
            (r"@\w+", "Decorator", "Good: decorator", Severity.INFO),
            (r"@\w+\(\)", "Decorator with parens", "Good: decorator with parens", Severity.INFO),
            (r"@\w+\(\w+=\w+\)", "Decorator with args", "Good: decorator with args", Severity.INFO),
            # Comments
            (r"#\s+\w+", "Comment", "Good: comment", Severity.INFO),
            (r"//\s+\w+", "Comment", "Good: comment", Severity.INFO),
            (r"/\*\s+\w+", "Block comment", "Good: block comment", Severity.INFO),
            (r"\*/\s*$", "Block comment end", "Good: block comment end", Severity.INFO),
            (r"///\s+\w+", "Doc comment", "Good: doc comment", Severity.INFO),
            (r"//!\s+\w+", "Module doc", "Good: module doc", Severity.INFO),
            (r"#!\[", "Attribute", "Good: attribute", Severity.INFO),
            (r"#!\[allow", "Allow attribute", "Good: allow attribute", Severity.INFO),
            (r"#!\[deny", "Deny attribute", "Good: deny attribute", Severity.INFO),
            (r"#!\[warn", "Warn attribute", "Good: warn attribute", Severity.INFO),
            (r"#!\[forbid", "Forbid attribute", "Good: forbid attribute", Severity.INFO),
            (r"#!\[cfg\(", "Cfg attribute", "Good: cfg attribute", Severity.INFO),
            (r"#!\[derive\(", "Derive attribute", "Good: derive attribute", Severity.INFO),
            (r"#!\[doc\(", "Doc attribute", "Good: doc attribute", Severity.INFO),
            (r"#!\[must_use\]", "Must use attribute", "Good: must_use attribute", Severity.INFO),
            (r"#!\[inline\(", "Inline attribute", "Good: inline attribute", Severity.INFO),
            (r"#!\[cold\]", "Cold attribute", "Good: cold attribute", Severity.INFO),
            (r"#!\[repr\(", "Repr attribute", "Good: repr attribute", Severity.INFO),
            # Docstrings
            (r"\"\"\"", "Docstring", "Good: docstring", Severity.INFO),
            (r"'''\s*$", "Docstring", "Good: docstring", Severity.INFO),
            (r"#\s*TODO\s*:", "TODO comment", "Address the TODO", Severity.INFO),
            (r"#\s*FIXME\s*:", "FIXME comment", "Fix the issue", Severity.INFO),
            (r"#\s*HACK\s*:", "HACK comment", "Refactor the hack", Severity.INFO),
            (r"#\s*XXX\s*:", "XXX comment", "Address the XXX", Severity.INFO),
            (r"#\s*NOTE\s*:", "NOTE comment", "Good: note comment", Severity.INFO),
            (r"#\s*REVIEW\s*:", "REVIEW comment", "Review the code", Severity.INFO),
            (r"#\s*BUG\s*:", "BUG comment", "Fix the bug", Severity.INFO),
            (r"#\s*WORKAROUND\s*:", "WORKAROUND comment", "Find proper solution", Severity.INFO),
            # Line length
            (r"^.{80,}$", "Long line (>80 chars)", "Consider breaking line", Severity.INFO),
            (r"^.{100,}$", "Very long line (>100 chars)", "Break line", Severity.INFO),
            (r"^.{120,}$", "Extremely long line (>120 chars)", "Break line", Severity.INFO),
            # Blank lines
            (r"^\s*$", "Blank line", "Good: blank line", Severity.INFO),
            # Semicolons
            (r";\s*$", "Trailing semicolon", "Remove trailing semicolon", Severity.INFO),
            # Braces
            (r"\{\s*$", "Opening brace", "Good: opening brace", Severity.INFO),
            (r"^\s*\}\s*$", "Closing brace", "Good: closing brace", Severity.INFO),
            # Operators
            (r"=\s*=", "Assignment vs equality", "Use == for comparison", Severity.INFO),
            (r"!=\s*=", "Inequality vs assignment", "Use != for inequality", Severity.INFO),
            (r"<=\s*>", "Spaceship operator", "Good: spaceship operator", Severity.INFO),
            # String quotes
            (r"'[^']*'", "Single quotes", "Good: single quotes", Severity.INFO),
            (r'"[^"]*"', "Double quotes", "Good: double quotes", Severity.INFO),
            (r"'''[\s\S]*?'''", "Triple single quotes", "Good: triple single quotes", Severity.INFO),
            (r'"""[\s\S]*?"""', "Triple double quotes", "Good: triple double quotes", Severity.INFO),
            (r"`[^`]*`", "Backtick quotes", "Good: backtick quotes", Severity.INFO),
            # Naming conventions
            (r"class\s+[A-Z]\w+", "Class (PascalCase)", "Good: PascalCase for classes", Severity.INFO),
            (r"def\s+[a-z_]\w*\(", "Function (snake_case)", "Good: snake_case for functions", Severity.INFO),
            (r"[A-Z_][A-Z_0-9]+\s*=", "Constant (UPPER_SNAKE)", "Good: UPPER_SNAKE for constants", Severity.INFO),
            (r"[a-z_][a-z_0-9]+\s*=", "Variable (snake_case)", "Good: snake_case for variables", Severity.INFO),
            (r"[a-z][a-zA-Z0-9]+\s*=", "Variable (camelCase)", "Good: camelCase for variables", Severity.INFO),
            (r"[A-Z][a-zA-Z0-9]+\s*=", "Variable (PascalCase)", "Good: PascalCase for variables", Severity.INFO),
            (r"[a-z][a-z0-9-]+\s*=", "Variable (kebab-case)", "Good: kebab-case for variables", Severity.INFO),
            (r"[a-z][a-z0-9_]+\s*=", "Variable (snake_case)", "Good: snake_case for variables", Severity.INFO),
            # Code organization
            (r"^class\s+\w+", "Class definition", "Good: class definition", Severity.INFO),
            (r"^def\s+\w+", "Function definition", "Good: function definition", Severity.INFO),
            (r"^import\s+\w+", "Import statement", "Good: import statement", Severity.INFO),
            (r"^from\s+\w+\s+import", "From import", "Good: from import", Severity.INFO),
            (r"^return\s+\w+", "Return statement", "Good: return statement", Severity.INFO),
            (r"^if\s+\w+\s*:", "If statement", "Good: if statement", Severity.INFO),
            (r"^elif\s+\w+\s*:", "Elif statement", "Good: elif statement", Severity.INFO),
            (r"^else\s*:", "Else statement", "Good: else statement", Severity.INFO),
            (r"^for\s+\w+\s+in\s+\w+\s*:", "For loop", "Good: for loop", Severity.INFO),
            (r"^while\s+\w+\s*:", "While loop", "Good: while loop", Severity.INFO),
            (r"^try\s*:", "Try block", "Good: try block", Severity.INFO),
            (r"^except\s+\w+", "Except clause", "Good: except clause", Severity.INFO),
            (r"^finally\s*:", "Finally block", "Good: finally block", Severity.INFO),
            (r"^with\s+\w+\s+as\s+\w+\s*:", "With statement", "Good: with statement", Severity.INFO),
            (r"^raise\s+\w+", "Raise statement", "Good: raise statement", Severity.INFO),
            (r"^assert\s+\w+", "Assert statement", "Good: assert statement", Severity.INFO),
            (r"^pass\s*$", "Pass statement", "Consider adding implementation", Severity.INFO),
            (r"^break\s*$", "Break statement", "Good: break statement", Severity.INFO),
            (r"^continue\s*$", "Continue statement", "Good: continue statement", Severity.INFO),
            (r"^global\s+\w+", "Global statement", "Avoid global variables", Severity.INFO),
            (r"^nonlocal\s+\w+", "Nonlocal statement", "Good: nonlocal statement", Severity.INFO),
            (r"^del\s+\w+", "Del statement", "Good: del statement", Severity.INFO),
            (r"^yield\s+\w+", "Yield statement", "Good: yield statement", Severity.INFO),
            (r"^yield\s+from\s+\w+", "Yield from", "Good: yield from", Severity.INFO),
            (r"^await\s+\w+", "Await statement", "Good: await statement", Severity.INFO),
            (r"^async\s+def\s+\w+", "Async def", "Good: async def", Severity.INFO),
            (r"^lambda\s+\w+\s*:", "Lambda", "Good: lambda", Severity.INFO),
            (r"^@\w+", "Decorator", "Good: decorator", Severity.INFO),
            (r"^@\w+\(\)", "Decorator with parens", "Good: decorator with parens", Severity.INFO),
            (r"^@\w+\(\w+=\w+\)", "Decorator with args", "Good: decorator with args", Severity.INFO),
            # Code organization
            (r"#\s+\w+", "Comment", "Good: comment", Severity.INFO),
            (r"//\s+\w+", "Comment", "Good: comment", Severity.INFO),
            (r"/\*\s+\w+", "Block comment", "Good: block comment", Severity.INFO),
            (r"\*/\s*$", "Block comment end", "Good: block comment end", Severity.INFO),
            (r"///\s+\w+", "Doc comment", "Good: doc comment", Severity.INFO),
            (r"//!\s+\w+", "Module doc", "Good: module doc", Severity.INFO),
            (r"#!\[", "Attribute", "Good: attribute", Severity.INFO),
            (r"#!\[allow", "Allow attribute", "Good: allow attribute", Severity.INFO),
            (r"#!\[deny", "Deny attribute", "Good: deny attribute", Severity.INFO),
            (r"#!\[warn", "Warn attribute", "Good: warn attribute", Severity.INFO),
            (r"#!\[forbid", "Forbid attribute", "Good: forbid attribute", Severity.INFO),
            (r"#!\[cfg\(", "Cfg attribute", "Good: cfg attribute", Severity.INFO),
            (r"#!\[derive\(", "Derive attribute", "Good: derive attribute", Severity.INFO),
            (r"#!\[doc\(", "Doc attribute", "Good: doc attribute", Severity.INFO),
            (r"#!\[must_use\]", "Must use attribute", "Good: must_use attribute", Severity.INFO),
            (r"#!\[inline\(", "Inline attribute", "Good: inline attribute", Severity.INFO),
            (r"#!\[cold\]", "Cold attribute", "Good: cold attribute", Severity.INFO),
            (r"#!\[repr\(", "Repr attribute", "Good: repr attribute", Severity.INFO),
            # Docstrings
            (r"\"\"\"", "Docstring", "Good: docstring", Severity.INFO),
            (r"'''\s*$", "Docstring", "Good: docstring", Severity.INFO),
            (r"#\s*TODO\s*:", "TODO comment", "Address the TODO", Severity.INFO),
            (r"#\s*FIXME\s*:", "FIXME comment", "Fix the issue", Severity.INFO),
            (r"#\s*HACK\s*:", "HACK comment", "Refactor the hack", Severity.INFO),
            (r"#\s*XXX\s*:", "XXX comment", "Address the XXX", Severity.INFO),
            (r"#\s*NOTE\s*:", "NOTE comment", "Good: note comment", Severity.INFO),
            (r"#\s*REVIEW\s*:", "REVIEW comment", "Review the code", Severity.INFO),
            (r"#\s*BUG\s*:", "BUG comment", "Fix the bug", Severity.INFO),
            (r"#\s*WORKAROUND\s*:", "WORKAROUND comment", "Find proper solution", Severity.INFO),
            # Line length
            (r"^.{80,}$", "Long line (>80 chars)", "Consider breaking line", Severity.INFO),
            (r"^.{100,}$", "Very long line (>100 chars)", "Break line", Severity.INFO),
            (r"^.{120,}$", "Extremely long line (>120 chars)", "Break line", Severity.INFO),
            # Blank lines
            (r"^\s*$", "Blank line", "Good: blank line", Severity.INFO),
            # Semicolons
            (r";\s*$", "Trailing semicolon", "Remove trailing semicolon", Severity.INFO),
            # Braces
            (r"\{\s*$", "Opening brace", "Good: opening brace", Severity.INFO),
            (r"^\s*\}\s*$", "Closing brace", "Good: closing brace", Severity.INFO),
            # Operators
            (r"=\s*=", "Assignment vs equality", "Use == for comparison", Severity.INFO),
            (r"!=\s*=", "Inequality vs assignment", "Use != for inequality", Severity.INFO),
            (r"<=\s*>", "Spaceship operator", "Good: spaceship operator", Severity.INFO),
            # String quotes
            (r"'[^']*'", "Single quotes", "Good: single quotes", Severity.INFO),
            (r'"[^"]*"', "Double quotes", "Good: double quotes", Severity.INFO),
            (r"'''[\s\S]*?'''", "Triple single quotes", "Good: triple single quotes", Severity.INFO),
            (r'"""[\s\S]*?"""', "Triple double quotes", "Good: triple double quotes", Severity.INFO),
            (r"`[^`]*`", "Backtick quotes", "Good: backtick quotes", Severity.INFO),
            # Naming conventions
            (r"class\s+[A-Z]\w+", "Class (PascalCase)", "Good: PascalCase for classes", Severity.INFO),
            (r"def\s+[a-z_]\w*\(", "Function (snake_case)", "Good: snake_case for functions", Severity.INFO),
            (r"[A-Z_][A-Z_0-9]+\s*=", "Constant (UPPER_SNAKE)", "Good: UPPER_SNAKE for constants", Severity.INFO),
            (r"[a-z_][a-z_0-9]+\s*=", "Variable (snake_case)", "Good: snake_case for variables", Severity.INFO),
            (r"[a-z][a-zA-Z0-9]+\s*=", "Variable (camelCase)", "Good: camelCase for variables", Severity.INFO),
            (r"[A-Z][a-zA-Z0-9]+\s*=", "Variable (PascalCase)", "Good: PascalCase for variables", Severity.INFO),
            (r"[a-z][a-z0-9-]+\s*=", "Variable (kebab-case)", "Good: kebab-case for variables", Severity.INFO),
            (r"[a-z][a-z0-9_]+\s*=", "Variable (snake_case)", "Good: snake_case for variables", Severity.INFO),
            # Code organization
            (r"^class\s+\w+", "Class definition", "Good: class definition", Severity.INFO),
            (r"^def\s+\w+", "Function definition", "Good: function definition", Severity.INFO),
            (r"^import\s+\w+", "Import statement", "Good: import statement", Severity.INFO),
            (r"^from\s+\w+\s+import", "From import", "Good: from import", Severity.INFO),
            (r"^return\s+\w+", "Return statement", "Good: return statement", Severity.INFO),
            (r"^if\s+\w+\s*:", "If statement", "Good: if statement", Severity.INFO),
            (r"^elif\s+\w+\s*:", "Elif statement", "Good: elif statement", Severity.INFO),
            (r"^else\s*:", "Else statement", "Good: else statement", Severity.INFO),
            (r"^for\s+\w+\s+in\s+\w+\s*:", "For loop", "Good: for loop", Severity.INFO),
            (r"^while\s+\w+\s*:", "While loop", "Good: while loop", Severity.INFO),
            (r"^try\s*:", "Try block", "Good: try block", Severity.INFO),
            (r"^except\s+\w+", "Except clause", "Good: except clause", Severity.INFO),
            (r"^finally\s*:", "Finally block", "Good: finally block", Severity.INFO),
            (r"^with\s+\w+\s+as\s+\w+\s*:", "With statement", "Good: with statement", Severity.INFO),
            (r"^raise\s+\w+", "Raise statement", "Good: raise statement", Severity.INFO),
            (r"^assert\s+\w+", "Assert statement", "Good: assert statement", Severity.INFO),
            (r"^pass\s*$", "Pass statement", "Consider adding implementation", Severity.INFO),
            (r"^break\s*$", "Break statement", "Good: break statement", Severity.INFO),
            (r"^continue\s*$", "Continue statement", "Good: continue statement", Severity.INFO),
            (r"^global\s+\w+", "Global statement", "Avoid global variables", Severity.INFO),
            (r"^nonlocal\s+\w+", "Nonlocal statement", "Good: nonlocal statement", Severity.INFO),
            (r"^del\s+\w+", "Del statement", "Good: del statement", Severity.INFO),
            (r"^yield\s+\w+", "Yield statement", "Good: yield statement", Severity.INFO),
            (r"^yield\s+from\s+\w+", "Yield from", "Good: yield from", Severity.INFO),
            (r"^await\s+\w+", "Await statement", "Good: await statement", Severity.INFO),
            (r"^async\s+def\s+\w+", "Async def", "Good: async def", Severity.INFO),
            (r"^lambda\s+\w+\s*:", "Lambda", "Good: lambda", Severity.INFO),
            (r"^@\w+", "Decorator", "Good: decorator", Severity.INFO),
            (r"^@\w+\(\)", "Decorator with parens", "Good: decorator with parens", Severity.INFO),
            (r"^@\w+\(\w+=\w+\)", "Decorator with args", "Good: decorator with args", Severity.INFO),
        ]
        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith('#') or stripped.startswith('//') or stripped.startswith('/*'):
                continue
            for pattern, message, severity in patterns:
                if re.search(pattern, line):
                    issues.append(self._create_issue(
                        file_path=file_path, line=line_num, message=message,
                        suggestion=message, severity=severity, code_snippet=stripped,
                    ))
        return issues
