"""
Built-in code review rules.
"""

import re
from abc import ABC, abstractmethod
from typing import Optional

from ..core.models import CodeIssue, Severity, IssueCategory


class BaseRule(ABC):
    """Base class for all code review rules."""
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Rule name."""
        ...
    
    @property
    @abstractmethod
    def description(self) -> str:
        """Rule description."""
        ...
    
    @property
    @abstractmethod
    def category(self) -> IssueCategory:
        """Rule category."""
        ...
    
    @property
    @abstractmethod
    def severity(self) -> Severity:
        """Default severity."""
        ...
    
    @abstractmethod
    def check(self, file_path: str, content: str) -> list[CodeIssue]:
        """
        Check code for issues.
        
        Args:
            file_path: Path to the file
            content: File content
            
        Returns:
            List of issues found
        """
        ...
    
    def _create_issue(
        self,
        file_path: str,
        line: int,
        message: str,
        suggestion: str = "",
        severity: Optional[Severity] = None,
        column: int = 0,
        code_snippet: str = "",
    ) -> CodeIssue:
        """Helper to create an issue."""
        return CodeIssue(
            file=file_path,
            line=line,
            column=column,
            severity=severity or self.severity,
            category=self.category,
            message=message,
            rule=self.name,
            suggestion=suggestion,
            code_snippet=code_snippet,
        )


class SecurityRules(BaseRule):
    """Security-related rules."""
    
    @property
    def name(self) -> str:
        return "security"
    
    @property
    def description(self) -> str:
        return "Security vulnerability detection"
    
    @property
    def category(self) -> IssueCategory:
        return IssueCategory.SECURITY
    
    @property
    def severity(self) -> Severity:
        return Severity.CRITICAL
    
    def check(self, file_path: str, content: str) -> list[CodeIssue]:
        issues = []
        lines = content.splitlines()
        
        # Patterns to detect
        patterns = [
            # Hardcoded secrets
            (r'(?:password|secret|api_key|apikey|token)\s*=\s*["\'][^"\']+["\']',
             "Hardcoded secret detected",
             "Use environment variables or a secrets manager"),
            
            # SQL injection
            (r'(?:execute|cursor\.execute)\s*\(\s*["\'].*%s',
             "Potential SQL injection (string formatting)",
             "Use parameterized queries"),
            
            # Eval usage
            (r'\beval\s*\(',
             "Use of eval() detected",
             "Avoid eval() - use ast.literal_eval() or safer alternatives"),
            
            # Exec usage
            (r'\bexec\s*\(',
             "Use of exec() detected",
             "Avoid exec() - refactor to use functions"),
            
            # Pickle loading
            (r'pickle\.loads?\s*\(',
             "Pickle deserialization detected",
             "Pickle can execute arbitrary code - use JSON or msgpack"),
            
            # Subprocess shell=True
            (r'subprocess\.\w+\s*\(.*shell\s*=\s*True',
             "Subprocess with shell=True",
             "Use shell=False with a list of arguments"),
            
            # Weak hashing
            (r'\b(?:md5|sha1)\s*\(',
             "Weak hash algorithm detected",
             "Use SHA-256 or stronger"),
            
            # Debug mode in production
            (r'DEBUG\s*=\s*True',
             "Debug mode enabled",
             "Disable debug mode in production"),
        ]
        
        for line_num, line in enumerate(lines, 1):
            for pattern, message, suggestion in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    issues.append(self._create_issue(
                        file_path=file_path,
                        line=line_num,
                        message=message,
                        suggestion=suggestion,
                        code_snippet=line.strip(),
                    ))
        
        return issues


class PerformanceRules(BaseRule):
    """Performance-related rules."""
    
    @property
    def name(self) -> str:
        return "performance"
    
    @property
    def description(self) -> str:
        return "Performance issue detection"
    
    @property
    def category(self) -> IssueCategory:
        return IssueCategory.PERFORMANCE
    
    @property
    def severity(self) -> Severity:
        return Severity.WARNING
    
    def check(self, file_path: str, content: str) -> list[CodeIssue]:
        issues = []
        lines = content.splitlines()
        
        patterns = [
            # N+1 query pattern (SQLAlchemy)
            (r'for\s+\w+\s+in\s+\w+\.query.*\.all\(\)',
             "Potential N+1 query pattern",
             "Use joinedload() or bulk operations"),
            
            # String concatenation in loop
            (r'for\s+.*:\s*\n\s*\w+\s*\+=\s*["\']',
             "String concatenation in loop",
             "Use join() or f-strings with a list"),
            
            # Global variable modification
            (r'global\s+\w+',
             "Global variable usage",
             "Avoid globals - use classes or dependency injection"),
            
            # Bare except
            (r'except\s*:',
             "Bare except clause",
             "Catch specific exceptions"),
            
            # len() in loop condition
            (r'while\s+len\(',
             "len() in while condition",
             "Cache the length or use a different approach"),
        ]
        
        for line_num, line in enumerate(lines, 1):
            for pattern, message, suggestion in patterns:
                if re.search(pattern, line):
                    issues.append(self._create_issue(
                        file_path=file_path,
                        line=line_num,
                        message=message,
                        suggestion=suggestion,
                        code_snippet=line.strip(),
                    ))
        
        return issues


class StyleRules(BaseRule):
    """Code style rules."""
    
    @property
    def name(self) -> str:
        return "style"
    
    @property
    def description(self) -> str:
        return "Code style and readability"
    
    @property
    def category(self) -> IssueCategory:
        return IssueCategory.STYLE
    
    @property
    def severity(self) -> Severity:
        return Severity.INFO
    
    def check(self, file_path: str, content: str) -> list[CodeIssue]:
        issues = []
        lines = content.splitlines()
        
        for line_num, line in enumerate(lines, 1):
            # Long lines
            if len(line) > 120:
                issues.append(self._create_issue(
                    file_path=file_path,
                    line=line_num,
                    message=f"Line too long ({len(line)} > 120 characters)",
                    suggestion="Break line into multiple lines",
                    severity=Severity.INFO,
                ))
            
            # Trailing whitespace
            if line != line.rstrip():
                issues.append(self._create_issue(
                    file_path=file_path,
                    line=line_num,
                    message="Trailing whitespace",
                    suggestion="Remove trailing whitespace",
                    severity=Severity.INFO,
                ))
            
            # TODO/FIXME comments
            if re.search(r'#\s*(?:TODO|FIXME|HACK|XXX)', line):
                issues.append(self._create_issue(
                    file_path=file_path,
                    line=line_num,
                    message="TODO/FIXME comment found",
                    suggestion="Address the TODO/FIXME or create an issue",
                    severity=Severity.INFO,
                ))
        
        return issues


class ComplexityRules(BaseRule):
    """Code complexity rules."""
    
    @property
    def name(self) -> str:
        return "complexity"
    
    @property
    def description(self) -> str:
        return "Code complexity detection"
    
    @property
    def category(self) -> IssueCategory:
        return IssueCategory.COMPLEXITY
    
    @property
    def severity(self) -> Severity:
        return Severity.WARNING
    
    def check(self, file_path: str, content: str) -> list[CodeIssue]:
        issues = []
        lines = content.splitlines()
        
        # Count nested depth
        max_depth = 0
        current_depth = 0
        
        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            
            # Count indentation (assuming 4 spaces)
            if stripped and not stripped.startswith('#'):
                depth = len(line) - len(line.lstrip())
                current_depth = depth // 4
                
                if current_depth > 4:
                    issues.append(self._create_issue(
                        file_path=file_path,
                        line=line_num,
                        message=f"Deeply nested code (depth: {current_depth})",
                        suggestion="Consider refactoring into smaller functions",
                    ))
        
        # Count function length
        in_function = False
        func_start = 0
        func_name = ""
        
        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            
            if re.match(r'(?:async\s+)?def\s+(\w+)', stripped):
                if in_function and (line_num - func_start) > 50:
                    issues.append(self._create_issue(
                        file_path=file_path,
                        line=func_start,
                        message=f"Function '{func_name}' is too long ({line_num - func_start} lines)",
                        suggestion="Break into smaller functions (max 50 lines)",
                    ))
                in_function = True
                func_start = line_num
                match = re.match(r'(?:async\s+)?def\s+(\w+)', stripped)
                func_name = match.group(1) if match else "unknown"
        
        return issues


class SyntaxRules(BaseRule):
    """Syntax and common error rules."""
    
    @property
    def name(self) -> str:
        return "syntax"
    
    @property
    def description(self) -> str:
        return "Syntax and common error detection"
    
    @property
    def category(self) -> IssueCategory:
        return IssueCategory.STYLE
    
    @property
    def severity(self) -> Severity:
        return Severity.ERROR
    
    def check(self, file_path: str, content: str) -> list[CodeIssue]:
        issues = []
        lines = content.splitlines()
        
        # Python common errors - patterns are Python-specific so no language detection needed
        python_errors = [
            # Case sensitivity errors
            (r'\bPrint\s*\(', "Print", "print", "Use lowercase 'print()' - Python is case-sensitive"),
            (r'\bInput\s*\(', "Input", "input", "Use lowercase 'input()' - Python is case-sensitive"),
            (r'\bLen\s*\(', "Len", "len", "Use lowercase 'len()' - Python is case-sensitive"),
            (r'\bRange\s*\(', "Range", "range", "Use lowercase 'range()' - Python is case-sensitive"),
            (r'\bType\s*\(', "Type", "type", "Use lowercase 'type()' - Python is case-sensitive"),
            (r'\bStr\s*\(', "Str", "str", "Use lowercase 'str()' - Python is case-sensitive"),
            (r'\bInt\s*\(', "Int", "int", "Use lowercase 'int()' - Python is case-sensitive"),
            (r'\bFloat\s*\(', "Float", "float", "Use lowercase 'float()' - Python is case-sensitive"),
            (r'\bBool\s*\(', "Bool", "bool", "Use lowercase 'bool()' - Python is case-sensitive"),
            (r'\bList\s*\(', "List", "list", "Use lowercase 'list()' - Python is case-sensitive"),
            (r'\bDict\s*\(', "Dict", "dict", "Use lowercase 'dict()' - Python is case-sensitive"),
            (r'\bTuple\s*\(', "Tuple", "tuple", "Use lowercase 'tuple()' - Python is case-sensitive"),
            (r'\bSet\s*\(', "Set", "set", "Use lowercase 'set()' - Python is case-sensitive"),
            (r'(?<!\.)\bPrintln\s*\(', "Println", "print", "Did you mean 'print'? 'Println' doesn't exist in Python"),
            
            # Common typos
            (r'\bpritn\s*\(', "pritn", "print", "Typo: 'pritn' should be 'print'"),
            (r'\bpirnt\s*\(', "pirnt", "print", "Typo: 'pirnt' should be 'print'"),
            (r'\bprit\(', "prit", "print", "Typo: 'prit' should be 'print'"),
            
            # Missing parentheses (Python 2 style)
            (r'^print\s+[^(]', "print statement", "print()", "Add parentheses: use 'print()' not 'print'"),
        ]
        
        # Quote errors
        quote_errors = []
        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith('#'):
                continue
            
            # Check for mismatched quotes
            in_single = False
            in_double = False
            in_triple_single = False
            in_triple_double = False
            i = 0
            
            while i < len(stripped):
                char = stripped[i]
                
                # Check for triple quotes
                if i + 2 < len(stripped):
                    triple = stripped[i:i+3]
                    if triple == "'''" and not in_double and not in_triple_double:
                        in_triple_single = not in_triple_single
                        i += 3
                        continue
                    elif triple == '"""' and not in_single and not in_triple_single:
                        in_triple_double = not in_triple_double
                        i += 3
                        continue
                
                # Skip escaped characters
                if char == '\\' and i + 1 < len(stripped):
                    i += 2
                    continue
                
                # Track quote state
                if char == "'" and not in_double and not in_triple_double:
                    in_single = not in_single
                elif char == '"' and not in_single and not in_triple_single:
                    in_double = not in_double
                
                i += 1
            
            # Check for unclosed quotes
            if in_single:
                issues.append(self._create_issue(
                    file_path=file_path,
                    line=line_num,
                    message="Unclosed single quote (')",
                    suggestion="Add a closing single quote '",
                    code_snippet=stripped,
                ))
            if in_double:
                issues.append(self._create_issue(
                    file_path=file_path,
                    line=line_num,
                    message='Unclosed double quote (")',
                    suggestion='Add a closing double quote "',
                    code_snippet=stripped,
                ))
            
            # Check for missing quotes around string arguments
            # Pattern: print(word) where word is not a variable
            match = re.match(r'(?:print|input|len|range|type|str|int|float)\s*\(\s*([a-zA-Z_]\w*)\s*\)', stripped)
            if match:
                arg = match.group(1)
                # Check if it looks like a string (not a variable/function call)
                if arg not in ('True', 'False', 'None') and not arg.startswith('_'):
                    # Check if it's likely a string that should be quoted
                    issues.append(self._create_issue(
                        file_path=file_path,
                        line=line_num,
                        message=f"'{arg}' might need quotes - is it a string?",
                        suggestion=f"Use '{arg}' or \"{arg}\" for strings, or ensure {arg} is defined as a variable",
                        code_snippet=stripped,
                        severity=Severity.WARNING,
                    ))
        
        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            
            # Skip comments and strings
            if stripped.startswith('#'):
                continue
            
            for pattern, wrong, correct, suggestion in python_errors:
                match = re.search(pattern, line)
                if match:
                    issues.append(self._create_issue(
                        file_path=file_path,
                        line=line_num,
                        message=f"'{wrong}' is not defined - did you mean '{correct}'?",
                        suggestion=suggestion,
                        code_snippet=stripped,
                    ))
        
        return issues


# Default rules
DEFAULT_RULES = [
    SecurityRules(),
    PerformanceRules(),
    StyleRules(),
    ComplexityRules(),
    SyntaxRules(),
]

# All rules - loaded lazily to avoid import issues
ALL_RULES = []

def _load_all_rules():
    """Load all rules on demand."""
    global ALL_RULES
    if not ALL_RULES:
        try:
            # Language-specific (from multilang.py)
            from ..rules.multilang import JavaScriptRules, JavaRules, CppRules, GoRules, RustRules
            # Security
            from ..rules.security_rules import InjectionRules, SecretsDetectionRules, CryptoRules, AuthenticationRules
            # Performance
            from ..rules.performance_rules import DatabasePerformanceRules, MemoryPerformanceRules, AlgorithmPerformanceRules, NetworkPerformanceRules
            # Naming/Documentation
            from ..rules.naming_rules import NamingConventionRules, DocumentationRules, CodeOrganizationRules
            # Error handling
            from ..rules.error_handling_rules import ExceptionHandlingRules, ErrorPropagationRules
            # Concurrency
            from ..rules.concurrency_rules import ThreadingRules, AsyncAwaitRules, ProcessPoolRules
            # API
            from ..rules.api_rules import RESTAPIRules, GraphQLRules, WebSocketRules
            # Design
            from ..rules.design_rules import SOLIDRules, AntiPatternRules, DesignSmellRules

            # NEW RULES - Comprehensive patterns
            from ..rules.antipattern_extended_rules import AntiPatternExtendedRules
            from ..rules.api_comprehensive_rules import APIComprehensiveRules
            from ..rules.api_design_rules import APIDesignRules
            from ..rules.architecture_comprehensive_rules import ArchitectureComprehensiveRules
            from ..rules.architecture_patterns_rules import ArchitecturePatternsRules
            from ..rules.c_cpp_rules import CPPComprehensiveRules
            from ..rules.cicd_pipeline_rules import CICDPipelineRules
            from ..rules.cli_args_rules import CLIArgsRules
            from ..rules.cloud_comprehensive_rules import CloudComprehensiveRules
            from ..rules.cloud_patterns_rules import CloudPatternsRules
            from ..rules.complexity_comprehensive_rules import ComplexityComprehensiveRules
            from ..rules.comprehensive_extra_rules import CloudDevOpsRules, DatabaseExtraRules, FrontendExtraRules
            from ..rules.comprehensive_patterns import ComprehensivePatterns
            from ..rules.concurrency_comprehensive_rules import ConcurrencyComprehensiveRules
            from ..rules.cpp_comprehensive_rules import C_CPP_ComprehensiveRules
            from ..rules.cryptography_rules import CryptographyRules
            from ..rules.data_processing_rules import DataProcessingRules
            from ..rules.database_comprehensive_rules import DatabaseComprehensiveRules
            from ..rules.database_patterns_rules import DatabasePatternsRules
            from ..rules.dependency_comprehensive_rules import DependencyComprehensiveRules
            from ..rules.design_patterns_rules import DesignPatternsRules
            from ..rules.devops_comprehensive_rules import DevOpsComprehensiveRules
            from ..rules.devops_patterns_rules import DevOpsPatternsRules
            from ..rules.docker_kubernetes_rules import DockerKubernetesRules
            from ..rules.documentation_comprehensive_rules import DocumentationComprehensiveRules
            from ..rules.email_notification_rules import EmailNotificationRules
            from ..rules.encoding_io_rules import EncodingIORules
            from ..rules.error_handling_comprehensive import ErrorHandlingComprehensiveRules
            from ..rules.frontend_comprehensive_rules import FrontendComprehensiveRules
            from ..rules.frontend_patterns_rules import FrontendPatternsRules
            from ..rules.git_commit_rules import GitCommitRules
            from ..rules.go_comprehensive_rules import GoComprehensiveRules
            from ..rules.go_rules import GoLanguageRules
            from ..rules.graphql_rest_rules import GraphQLRestRules
            from ..rules.java_comprehensive_rules import JavaComprehensiveRules
            from ..rules.java_rules import JavaLanguageRules
            from ..rules.javascript_comprehensive_rules import JavaScriptComprehensiveRules
            from ..rules.javascript_rules import JavaScriptLanguageRules
            from ..rules.kotlin_rules import KotlinRules
            from ..rules.kotlin_rules_compact import KotlinCompactRules
            from ..rules.logging_monitoring_rules import LoggingMonitoringRules
            from ..rules.memory_comprehensive_rules import MemoryComprehensiveRules
            from ..rules.naming_comprehensive_rules import NamingComprehensiveRules
            from ..rules.owasp_rules import OWASPRules
            from ..rules.performance_comprehensive_rules import PerformanceComprehensiveRules
            from ..rules.performance_extended_rules import PerformanceExtendedRules
            from ..rules.php_rules import PHPRules
            from ..rules.php_rules_compact import PHPCompactRules
            from ..rules.python_rules import PythonLanguageRules
            from ..rules.regex_patterns_rules import RegexPatternsRules
            from ..rules.rust_comprehensive_rules import RustComprehensiveRules
            from ..rules.rust_rules import RustLanguageRules
            from ..rules.security_comprehensive_rules import SecurityComprehensiveRules
            from ..rules.security_patterns_rules import SecurityPatternsRules
            from ..rules.style_comprehensive_rules import StyleComprehensiveRules
            from ..rules.swift_rules import SwiftRules
            from ..rules.swift_rules_compact import SwiftCompactRules
            from ..rules.terraform_ansible_rules import TerraformAnsibleRules
            from ..rules.testing_comprehensive_rules import TestingComprehensiveRules
            from ..rules.testing_framework_rules import TestingFrameworkRules
            from ..rules.testing_patterns_rules import TestingPatternsRules
            from ..rules.typescript_rules import TypeScriptRules
            from ..rules.typescript_rules_compact import TypeScriptCompactRules

            ALL_RULES = [
                # Language-specific (from multilang.py)
                JavaScriptRules(),
                JavaRules(),
                CppRules(),
                GoRules(),
                RustRules(),
                # Security
                InjectionRules(),
                SecretsDetectionRules(),
                CryptoRules(),
                AuthenticationRules(),
                # Performance
                DatabasePerformanceRules(),
                MemoryPerformanceRules(),
                AlgorithmPerformanceRules(),
                NetworkPerformanceRules(),
                # Naming/Documentation
                NamingConventionRules(),
                DocumentationRules(),
                CodeOrganizationRules(),
                # Error handling
                ExceptionHandlingRules(),
                ErrorPropagationRules(),
                # Concurrency
                ThreadingRules(),
                AsyncAwaitRules(),
                ProcessPoolRules(),
                # API
                RESTAPIRules(),
                GraphQLRules(),
                WebSocketRules(),
                # Design
                SOLIDRules(),
                AntiPatternRules(),
                DesignSmellRules(),
                # NEW RULES - Comprehensive patterns
                AntiPatternExtendedRules(),
                APIComprehensiveRules(),
                APIDesignRules(),
                ArchitectureComprehensiveRules(),
                ArchitecturePatternsRules(),
                CPPComprehensiveRules(),
                CICDPipelineRules(),
                CLIArgsRules(),
                CloudComprehensiveRules(),
                CloudPatternsRules(),
                ComplexityComprehensiveRules(),
                CloudDevOpsRules(),
                DatabaseExtraRules(),
                FrontendExtraRules(),
                ComprehensivePatterns(),
                ConcurrencyComprehensiveRules(),
                C_CPP_ComprehensiveRules(),
                CryptographyRules(),
                DataProcessingRules(),
                DatabaseComprehensiveRules(),
                DatabasePatternsRules(),
                DependencyComprehensiveRules(),
                DesignPatternsRules(),
                DevOpsComprehensiveRules(),
                DevOpsPatternsRules(),
                DockerKubernetesRules(),
                DocumentationComprehensiveRules(),
                EmailNotificationRules(),
                EncodingIORules(),
                ErrorHandlingComprehensiveRules(),
                FrontendComprehensiveRules(),
                FrontendPatternsRules(),
                GitCommitRules(),
                GoComprehensiveRules(),
                GoLanguageRules(),
                GraphQLRestRules(),
                JavaComprehensiveRules(),
                JavaLanguageRules(),
                JavaScriptComprehensiveRules(),
                JavaScriptLanguageRules(),
                KotlinRules(),
                KotlinCompactRules(),
                LoggingMonitoringRules(),
                MemoryComprehensiveRules(),
                NamingComprehensiveRules(),
                OWASPRules(),
                PerformanceComprehensiveRules(),
                PerformanceExtendedRules(),
                PHPRules(),
                PHPCompactRules(),
                PythonLanguageRules(),
                RegexPatternsRules(),
                RustComprehensiveRules(),
                RustLanguageRules(),
                SecurityComprehensiveRules(),
                SecurityPatternsRules(),
                StyleComprehensiveRules(),
                SwiftRules(),
                SwiftCompactRules(),
                TerraformAnsibleRules(),
                TestingComprehensiveRules(),
                TestingFrameworkRules(),
                TestingPatternsRules(),
                TypeScriptRules(),
                TypeScriptCompactRules(),
            ]
        except ImportError as e:
            print(f"Warning: Could not load some rules: {e}")
    return ALL_RULES

def get_all_rules():
    """Get all rules including multi-language."""
    return DEFAULT_RULES + _load_all_rules()
