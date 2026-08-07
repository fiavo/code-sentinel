"""
Comprehensive naming and style patterns for all languages.
"""
import re
from ..core.models import CodeIssue, Severity, IssueCategory
from ..core.rules import BaseRule


class NamingComprehensiveRules(BaseRule):
    @property
    def name(self) -> str:
        return "naming_comprehensive"
    @property
    def description(self) -> str:
        return "Comprehensive naming patterns"
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
            # Python naming
            (r"class\s+[A-Z]\w+", "Class naming (PascalCase)", "Good: PascalCase for classes", Severity.INFO),
            (r"def\s+[a-z_]\w*\(", "Function naming (snake_case)", "Good: snake_case for functions", Severity.INFO),
            (r"def\s+_[a-z_]\w*\(", "Private function (snake_case)", "Good: underscore prefix for private", Severity.INFO),
            (r"[A-Z_][A-Z_0-9]+\s*=", "Constant naming (UPPER_SNAKE)", "Good: UPPER_SNAKE for constants", Severity.INFO),
            (r"[a-z_][a-z_0-9]+\s*=", "Variable naming (snake_case)", "Good: snake_case for variables", Severity.INFO),
            (r"self\.[a-z_]\w*\s*=", "Instance variable (snake_case)", "Good: snake_case for instance vars", Severity.INFO),
            (r"_[a-z_]\w*\s*=", "Private variable (underscore prefix)", "Good: underscore prefix for private", Severity.INFO),
            (r"__\w+__\s*=", "Dunder attribute", "Good: dunder attributes", Severity.INFO),
            (r"[a-z][a-zA-Z0-9]+\s*\(", "camelCase function", "Consider snake_case for Python", Severity.INFO),
            (r"[A-Z][a-zA-Z0-9]+\s*\(", "PascalCase function", "Consider snake_case for Python", Severity.INFO),
            # JavaScript naming
            (r"function\s+[a-z]\w*\(", "Function naming (camelCase)", "Good: camelCase for functions", Severity.INFO),
            (r"const\s+[a-z]\w*\s*=", "Variable naming (camelCase)", "Good: camelCase for variables", Severity.INFO),
            (r"let\s+[a-z]\w*\s*=", "Variable naming (camelCase)", "Good: camelCase for variables", Severity.INFO),
            (r"var\s+[a-z]\w*\s*=", "Variable naming (camelCase)", "Good: camelCase for variables", Severity.INFO),
            (r"class\s+[A-Z]\w+", "Class naming (PascalCase)", "Good: PascalCase for classes", Severity.INFO),
            (r"[A-Z][A-Z_0-9]+\s*=", "Constant naming (UPPER_SNAKE)", "Good: UPPER_SNAKE for constants", Severity.INFO),
            (r"_[a-z]\w*\s*=", "Private variable (underscore prefix)", "Good: underscore prefix for private", Severity.INFO),
            (r"\$\w+", "jQuery/Angular variable ($)", "Good: $ prefix", Severity.INFO),
            (r"[a-z_][a-z_0-9]+\s*=", "snake_case variable", "Consider camelCase for JS", Severity.INFO),
            (r"[A-Z][a-zA-Z0-9]+\s*\(", "PascalCase function", "Consider camelCase for JS", Severity.INFO),
            # Java naming
            (r"class\s+[A-Z]\w+", "Class naming (PascalCase)", "Good: PascalCase for classes", Severity.INFO),
            (r"interface\s+[A-Z]\w+", "Interface naming (PascalCase)", "Good: PascalCase for interfaces", Severity.INFO),
            (r"enum\s+[A-Z]\w+", "Enum naming (PascalCase)", "Good: PascalCase for enums", Severity.INFO),
            (r"(?:public|private|protected|static|final)\s+\w+\s+[a-z]\w*\s*=", "Field naming (camelCase)", "Good: camelCase for fields", Severity.INFO),
            (r"[A-Z][A-Z_0-9]+\s*=", "Constant naming (UPPER_SNAKE)", "Good: UPPER_SNAKE for constants", Severity.INFO),
            (r"void\s+[a-z]\w*\(", "Method naming (camelCase)", "Good: camelCase for methods", Severity.INFO),
            (r"[a-z_][a-z_0-9]+\s*\(", "snake_case method", "Consider camelCase for Java", Severity.INFO),
            (r"[A-Z][a-zA-Z0-9]+\s*\(", "PascalCase method", "Consider camelCase for Java", Severity.INFO),
            # C/C++ naming
            (r"typedef\s+struct\s+[A-Z]\w+", "Typedef struct (PascalCase)", "Good: PascalCase for typedefs", Severity.INFO),
            (r"struct\s+[A-Z]\w+", "Struct naming (PascalCase)", "Good: PascalCase for structs", Severity.INFO),
            (r"enum\s+[A-Z]\w+", "Enum naming (PascalCase)", "Good: PascalCase for enums", Severity.INFO),
            (r"void\s+[a-z_]\w*\(", "Function naming (snake_case)", "Good: snake_case for functions", Severity.INFO),
            (r"[A-Z][A-Z_0-9]+\s*=", "Macro naming (UPPER_SNAKE)", "Good: UPPER_SNAKE for macros", Severity.INFO),
            (r"[a-z_][a-z_0-9]+\s*=", "Variable naming (snake_case)", "Good: snake_case for variables", Severity.INFO),
            (r"[a-z][a-zA-Z0-9]+\s*=", "camelCase variable", "Consider snake_case for C", Severity.INFO),
            # Go naming
            (r"func\s+[A-Z]\w*\(", "Exported function (PascalCase)", "Good: PascalCase for exported", Severity.INFO),
            (r"func\s+[a-z]\w*\(", "Unexported function (camelCase)", "Good: camelCase for unexported", Severity.INFO),
            (r"type\s+[A-Z]\w+\s+struct", "Exported type (PascalCase)", "Good: PascalCase for exported types", Severity.INFO),
            (r"type\s+[a-z]\w+\s+struct", "Unexported type (camelCase)", "Good: camelCase for unexported types", Severity.INFO),
            (r"[A-Z][A-Z_0-9]+\s*=", "Constant naming (UPPER_SNAKE)", "Good: UPPER_SNAKE for constants", Severity.INFO),
            (r"[a-z][a-zA-Z0-9]+\s*=", "Variable naming (camelCase)", "Good: camelCase for variables", Severity.INFO),
            (r"[a-z_][a-z_0-9]+\s*=", "snake_case variable", "Consider camelCase for Go", Severity.INFO),
            # Rust naming
            (r"fn\s+[a-z_]\w*\(", "Function naming (snake_case)", "Good: snake_case for functions", Severity.INFO),
            (r"struct\s+[A-Z]\w+", "Struct naming (PascalCase)", "Good: PascalCase for structs", Severity.INFO),
            (r"enum\s+[A-Z]\w+", "Enum naming (PascalCase)", "Good: PascalCase for enums", Severity.INFO),
            (r"trait\s+[A-Z]\w+", "Trait naming (PascalCase)", "Good: PascalCase for traits", Severity.INFO),
            (r"type\s+[A-Z]\w+", "Type alias (PascalCase)", "Good: PascalCase for type aliases", Severity.INFO),
            (r"[A-Z][A-Z_0-9]+\s*=", "Constant naming (UPPER_SNAKE)", "Good: UPPER_SNAKE for constants", Severity.INFO),
            (r"static\s+[A-Z][A-Z_0-9]+\s*=", "Static constant (UPPER_SNAKE)", "Good: UPPER_SNAKE for statics", Severity.INFO),
            (r"[a-z_][a-z_0-9]+\s*=", "Variable naming (snake_case)", "Good: snake_case for variables", Severity.INFO),
            (r"[a-z][a-zA-Z0-9]+\s*=", "camelCase variable", "Consider snake_case for Rust", Severity.INFO),
            # TypeScript naming
            (r"interface\s+[A-Z]\w+", "Interface naming (PascalCase)", "Good: PascalCase for interfaces", Severity.INFO),
            (r"type\s+[A-Z]\w+\s*=", "Type alias (PascalCase)", "Good: PascalCase for type aliases", Severity.INFO),
            (r"enum\s+[A-Z]\w+", "Enum naming (PascalCase)", "Good: PascalCase for enums", Severity.INFO),
            (r"function\s+[a-z]\w*\(", "Function naming (camelCase)", "Good: camelCase for functions", Severity.INFO),
            (r"const\s+[a-z]\w*\s*=", "Variable naming (camelCase)", "Good: camelCase for variables", Severity.INFO),
            (r"[A-Z][A-Z_0-9]+\s*=", "Constant naming (UPPER_SNAKE)", "Good: UPPER_SNAKE for constants", Severity.INFO),
            (r"_[a-z]\w*\s*=", "Private variable (underscore prefix)", "Good: underscore prefix for private", Severity.INFO),
            # SQL naming
            (r"CREATE\s+TABLE\s+[a-z_]\w+", "Table naming (snake_case)", "Good: snake_case for tables", Severity.INFO),
            (r"CREATE\s+TABLE\s+[A-Z]\w+", "Table naming (PascalCase)", "Consider snake_case for tables", Severity.INFO),
            (r"CREATE\s+INDEX\s+[a-z_]\w+", "Index naming (snake_case)", "Good: snake_case for indexes", Severity.INFO),
            (r"ALTER\s+TABLE\s+[a-z_]\w+", "Table reference (snake_case)", "Good: snake_case for tables", Severity.INFO),
            (r"SELECT\s+\w+\s+FROM\s+[a-z_]\w+", "Table reference (snake_case)", "Good: snake_case for tables", Severity.INFO),
            (r"INSERT\s+INTO\s+[a-z_]\w+", "Table reference (snake_case)", "Good: snake_case for tables", Severity.INFO),
            (r"UPDATE\s+[a-z_]\w+", "Table reference (snake_case)", "Good: snake_case for tables", Severity.INFO),
            (r"DELETE\s+FROM\s+[a-z_]\w+", "Table reference (snake_case)", "Good: snake_case for tables", Severity.INFO),
            # HTML/CSS naming
            (r"class\s*=\s*\"[a-z][a-z0-9-]*\"", "Class naming (kebab-case)", "Good: kebab-case for classes", Severity.INFO),
            (r"id\s*=\s*\"[a-z][a-z0-9-]*\"", "ID naming (kebab-case)", "Good: kebab-case for IDs", Severity.INFO),
            (r"\.[a-z][a-z0-9-]*\s*\{", "CSS selector (kebab-case)", "Good: kebab-case for CSS", Severity.INFO),
            (r"#[a-z][a-z0-9-]*\s*\{", "CSS ID selector (kebab-case)", "Good: kebab-case for CSS IDs", Severity.INFO),
            # React naming
            (r"function\s+[A-Z]\w+", "Component naming (PascalCase)", "Good: PascalCase for components", Severity.INFO),
            (r"const\s+[A-Z]\w*\s*=\s*(?:\(|function)", "Component naming (PascalCase)", "Good: PascalCase for components", Severity.INFO),
            (r"export\s+(?:default\s+)?(?:function|const)\s+[A-Z]\w+", "Exported component (PascalCase)", "Good: PascalCase for exported components", Severity.INFO),
            (r"export\s+default\s+[A-Z]\w+", "Default export (PascalCase)", "Good: PascalCase for default exports", Severity.INFO),
            # Vue naming
            (r"export\s+(?:default\s+)?(?:function|const)\s+[A-Z]\w+", "Exported component (PascalCase)", "Good: PascalCase for exported components", Severity.INFO),
            (r"export\s+default\s+[A-Z]\w+", "Default export (PascalCase)", "Good: PascalCase for default exports", Severity.INFO),
            (r"<[A-Z]\w+", "Component usage (PascalCase)", "Good: PascalCase for component usage", Severity.INFO),
            # Angular naming
            (r"@Component\(", "Angular component", "Good: using Angular component", Severity.INFO),
            (r"@Directive\(", "Angular directive", "Good: using Angular directive", Severity.INFO),
            (r"@Pipe\(", "Angular pipe", "Good: using Angular pipe", Severity.INFO),
            (r"@Injectable\(", "Angular injectable", "Good: using Angular injectable", Severity.INFO),
            (r"@NgModule\(", "Angular module", "Good: using Angular module", Severity.INFO),
            # File naming
            (r"component\.\w+", "Component file", "Good: component file naming", Severity.INFO),
            (r"service\.\w+", "Service file", "Good: service file naming", Severity.INFO),
            (r"module\.\w+", "Module file", "Good: module file naming", Severity.INFO),
            (r"controller\.\w+", "Controller file", "Good: controller file naming", Severity.INFO),
            (r"model\.\w+", "Model file", "Good: model file naming", Severity.INFO),
            (r"view\.\w+", "View file", "Good: view file naming", Severity.INFO),
            (r"test\.\w+", "Test file", "Good: test file naming", Severity.INFO),
            (r"spec\.\w+", "Spec file", "Good: spec file naming", Severity.INFO),
            (r"helper\.\w+", "Helper file", "Good: helper file naming", Severity.INFO),
            (r"util\.\w+", "Utility file", "Good: utility file naming", Severity.INFO),
            (r"config\.\w+", "Config file", "Good: config file naming", Severity.INFO),
            (r"index\.\w+", "Index file", "Good: index file naming", Severity.INFO),
            # Variable naming
            (r"^[a-z][a-z0-9]+\s*=", "Variable naming", "Good: variable naming", Severity.INFO),
            (r"^[A-Z][A-Z_0-9]+\s*=", "Constant naming", "Good: constant naming", Severity.INFO),
            (r"^[a-z][a-zA-Z0-9]+\s*=", "camelCase naming", "Good: camelCase naming", Severity.INFO),
            (r"^[A-Z][a-zA-Z0-9]+\s*=", "PascalCase naming", "Good: PascalCase naming", Severity.INFO),
            (r"^[a-z][a-z0-9-]+\s*=", "kebab-case naming", "Good: kebab-case naming", Severity.INFO),
            (r"^[a-z][a-z0-9_]+\s*=", "snake_case naming", "Good: snake_case naming", Severity.INFO),
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
