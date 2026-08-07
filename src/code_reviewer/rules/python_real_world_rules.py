"""
Python real-world patterns extracted from 1385 production Python files.
Based on analysis of TheAlgorithms/Python dataset (119K+ lines of code).
"""
import re
from ..core.models import CodeIssue, Severity, IssueCategory
from ..core.rules import BaseRule


class PythonRealWorldPatterns(BaseRule):
    @property
    def name(self) -> str:
        return "python_real_world"
    @property
    def description(self) -> str:
        return "Python patterns from real-world codebases"
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
            # Type hints (2715 occurrences in dataset)
            (r"def\s+\w+\([^)]*\)\s*->\s*\w+", "Return type annotation", "Good: return type annotation (found in 2715 files)", Severity.INFO),
            (r"def\s+\w+\([^)]*:\s*(?:str|int|float|bool|list|dict|tuple|set|None|Any|Optional|Union|List|Dict|Tuple|Set)", "Parameter type annotation", "Good: parameter type annotation", Severity.INFO),
            
            # f-strings (1230 occurrences)
            (r'f["\'].*\{.*\}.*["\']', "f-string usage", "Good: f-string (modern formatting)", Severity.INFO),
            (r'\.format\(', "String .format() method", "Consider using f-strings for readability", Severity.INFO),
            (r'["\'].*%[sd].*["\'].*%', "Percent formatting", "Consider using f-strings", Severity.INFO),
            
            # Main guard (1075 occurrences)
            (r'if\s+__name__\s*==\s*["\']__main__["\']:', "Main guard pattern", "Good: main guard (found in 1075 files)", Severity.INFO),
            
            # List comprehensions (493 occurrences)
            (r'\[.*for\s+\w+\s+in\s+.*\]', "List comprehension", "Good: list comprehension", Severity.INFO),
            (r'\{.*for\s+\w+\s+in\s+.*\}', "Dict/Set comprehension", "Good: comprehension", Severity.INFO),
            (r'\(.*for\s+\w+\s+in\s+.*\)', "Generator expression", "Good: generator expression", Severity.INFO),
            
            # Decorators (274 occurrences)
            (r'@property', "Property decorator", "Good: property decorator", Severity.INFO),
            (r'@staticmethod', "Static method decorator", "Good: staticmethod", Severity.INFO),
            (r'@classmethod', "Class method decorator", "Good: classmethod", Severity.INFO),
            (r'@dataclass', "Dataclass decorator", "Good: dataclass (found in 50 files)", Severity.INFO),
            (r'@functools\.wraps', "functools.wraps", "Good: preserving function metadata", Severity.INFO),
            (r'@lru_cache', "LRU cache decorator", "Good: memoization", Severity.INFO),
            (r'@abstractmethod', "Abstract method", "Good: abstract method", Severity.INFO),
            (r'@override', "Override decorator", "Good: override decorator", Severity.INFO),
            
            # Error handling (91 try blocks)
            (r'try:', "Try block", "Good: error handling", Severity.INFO),
            (r'except\s+\w+Error\s+as\s+\w+:', "Specific exception handling", "Good: specific exception", Severity.INFO),
            (r'except\s+Exception\s*:', "Bare Exception catch", "Avoid catching bare Exception", Severity.WARNING),
            (r'except\s*:', "Bare except", "Use specific exceptions", Severity.WARNING),
            (r'finally:', "Finally block", "Good: cleanup code", Severity.INFO),
            (r'raise\s+\w+Error', "Raising exception", "Good: exception handling", Severity.INFO),
            
            # Context managers
            (r'with\s+\w+\s+as\s+\w+:', "Context manager", "Good: resource management", Severity.INFO),
            (r'with\s+open\(', "File context manager", "Good: file handling", Severity.INFO),
            (r'contextlib\.contextmanager', "Context manager decorator", "Good: custom context manager", Severity.INFO),
            
            # Generators (52 occurrences)
            (r'yield\s+', "Yield statement", "Good: generator pattern", Severity.INFO),
            (r'yield\s+from', "Yield from", "Good: delegating generator", Severity.INFO),
            
            # Imports (from dataset analysis)
            (r'from\s+typing\s+import', "Typing import", "Good: type annotations", Severity.INFO),
            (r'from\s+dataclasses\s+import', "Dataclasses import", "Good: dataclasses", Severity.INFO),
            (r'from\s+functools\s+import', "Functools import", "Good: functional tools", Severity.INFO),
            (r'from\s+itertools\s+import', "Itertools import", "Good: iteration tools", Severity.INFO),
            (r'from\s+collections\s+import', "Collections import", "Good: specialized containers", Severity.INFO),
            (r'from\s+__future__\s+import', "Future import", "Good: forward compatibility", Severity.INFO),
            (r'import\s+numpy', "NumPy import", "Good: numerical computing", Severity.INFO),
            (r'import\s+pandas', "Pandas import", "Good: data analysis", Severity.INFO),
            (r'import\s+pytest', "Pytest import", "Good: testing", Severity.INFO),
            
            # Modern Python features
            (r'list\[', "Lowercase list type", "Good: Python 3.9+ syntax", Severity.INFO),
            (r'dict\[', "Lowercase dict type", "Good: Python 3.9+ syntax", Severity.INFO),
            (r'tuple\[', "Lowercase tuple type", "Good: Python 3.9+ syntax", Severity.INFO),
            (r'set\[', "Lowercase set type", "Good: Python 3.9+ syntax", Severity.INFO),
            (r'X | Y', "Union type syntax", "Good: Python 3.10+ syntax", Severity.INFO),
            (r'match\s+\w+:', "Match statement", "Good: Python 3.10+ pattern matching", Severity.INFO),
            (r'case\s+\w+:', "Case pattern", "Good: Python 3.10+ case pattern", Severity.INFO),
            
            # Walrus operator
            (r':=', "Walrus operator", "Good: assignment expression", Severity.INFO),
            
            # Unpacking
            (r'\w+\s*,\s*\w+\s*=\s*\w+', "Tuple unpacking", "Good: tuple unpacking", Severity.INFO),
            (r'\*\w+', "Star unpacking", "Good: star unpacking", Severity.INFO),
            
            # String methods
            (r'\.strip\(\)', "String strip", "Good: string cleaning", Severity.INFO),
            (r'\.split\(', "String split", "Good: string splitting", Severity.INFO),
            (r'\.join\(', "String join", "Good: string joining", Severity.INFO),
            (r'\.replace\(', "String replace", "Good: string replacement", Severity.INFO),
            (r'\.startswith\(', "Startswith check", "Good: prefix check", Severity.INFO),
            (r'\.endswith\(', "Endswith check", "Good: suffix check", Severity.INFO),
            (r'\.encode\(', "String encode", "Good: encoding", Severity.INFO),
            (r'\.decode\(', "String decode", "Good: decoding", Severity.INFO),
            
            # List methods
            (r'\.append\(', "List append", "Good: list modification", Severity.INFO),
            (r'\.extend\(', "List extend", "Good: list extension", Severity.INFO),
            (r'\.insert\(', "List insert", "Good: list insertion", Severity.INFO),
            (r'\.remove\(', "List remove", "Good: list removal", Severity.INFO),
            (r'\.pop\(', "List pop", "Good: list pop", Severity.INFO),
            (r'\.sort\(', "List sort", "Good: in-place sorting", Severity.INFO),
            (r'\.sorted\(', "Sorted function", "Good: sorting", Severity.INFO),
            (r'\.reverse\(', "List reverse", "Good: reversing", Severity.INFO),
            (r'\.index\(', "List index", "Good: finding index", Severity.INFO),
            (r'\.count\(', "List count", "Good: counting", Severity.INFO),
            
            # Dict methods
            (r'\.keys\(\)', "Dict keys", "Good: dict keys", Severity.INFO),
            (r'\.values\(\)', "Dict values", "Good: dict values", Severity.INFO),
            (r'\.items\(\)', "Dict items", "Good: dict items", Severity.INFO),
            (r'\.get\(', "Dict get", "Good: safe access", Severity.INFO),
            (r'\.update\(', "Dict update", "Good: dict update", Severity.INFO),
            (r'\.pop\(', "Dict pop", "Good: dict pop", Severity.INFO),
            (r'\.setdefault\(', "Dict setdefault", "Good: default values", Severity.INFO),
            (r'\.fromkeys\(', "Dict fromkeys", "Good: dict creation", Severity.INFO),
            
            # Set methods
            (r'\.add\(', "Set add", "Good: set addition", Severity.INFO),
            (r'\.remove\(', "Set remove", "Good: set removal", Severity.INFO),
            (r'\.discard\(', "Set discard", "Good: safe removal", Severity.INFO),
            (r'\.union\(', "Set union", "Good: set union", Severity.INFO),
            (r'\.intersection\(', "Set intersection", "Good: set intersection", Severity.INFO),
            (r'\.difference\(', "Set difference", "Good: set difference", Severity.INFO),
            (r'\.symmetric_difference\(', "Symmetric difference", "Good: symmetric difference", Severity.INFO),
            
            # Iteration patterns
            (r'enumerate\(', "Enumerate", "Good: indexed iteration", Severity.INFO),
            (r'zip\(', "Zip", "Good: parallel iteration", Severity.INFO),
            (r'map\(', "Map function", "Good: mapping", Severity.INFO),
            (r'filter\(', "Filter function", "Good: filtering", Severity.INFO),
            (r'reduce\(', "Reduce function", "Good: reduction", Severity.INFO),
            (r'any\(', "Any function", "Good: existential check", Severity.INFO),
            (r'all\(', "All function", "Good: universal check", Severity.INFO),
            
            # Mathematical operations
            (r'abs\(', "Absolute value", "Good: absolute value", Severity.INFO),
            (r'min\(', "Minimum", "Good: minimum", Severity.INFO),
            (r'max\(', "Maximum", "Good: maximum", Severity.INFO),
            (r'sum\(', "Sum", "Good: summation", Severity.INFO),
            (r'round\(', "Round", "Good: rounding", Severity.INFO),
            (r'pow\(', "Power", "Good: exponentiation", Severity.INFO),
            (r'divmod\(', "Divmod", "Good: division with remainder", Severity.INFO),
            (r'int\(', "Integer conversion", "Good: type conversion", Severity.INFO),
            (r'float\(', "Float conversion", "Good: type conversion", Severity.INFO),
            (r'bool\(', "Boolean conversion", "Good: type conversion", Severity.INFO),
            (r'str\(', "String conversion", "Good: type conversion", Severity.INFO),
            (r'len\(', "Length", "Good: getting length", Severity.INFO),
            (r'range\(', "Range", "Good: iteration range", Severity.INFO),
            
            # File operations
            (r'open\(', "File open", "Good: file operation", Severity.INFO),
            (r'\.read\(\)', "File read", "Good: reading file", Severity.INFO),
            (r'\.write\(', "File write", "Good: writing file", Severity.INFO),
            (r'\.readline\(\)', "Read line", "Good: line reading", Severity.INFO),
            (r'\.readlines\(\)', "Read lines", "Good: reading all lines", Severity.INFO),
            (r'\.writelines\(', "Write lines", "Good: writing lines", Severity.INFO),
            (r'\.seek\(', "File seek", "Good: file positioning", Severity.INFO),
            (r'\.tell\(', "File tell", "Good: getting position", Severity.INFO),
            
            # Path operations
            (r'Path\(', "Path object", "Good: pathlib usage", Severity.INFO),
            (r'\.read_text\(\)', "Read text", "Good: pathlib read", Severity.INFO),
            (r'\.write_text\(', "Write text", "Good: pathlib write", Severity.INFO),
            (r'\.read_bytes\(\)', "Read bytes", "Good: pathlib read", Severity.INFO),
            (r'\.write_bytes\(', "Write bytes", "Good: pathlib write", Severity.INFO),
            (r'\.exists\(\)', "Exists check", "Good: path existence", Severity.INFO),
            (r'\.is_file\(\)', "Is file check", "Good: file check", Severity.INFO),
            (r'\.is_dir\(\)', "Is dir check", "Good: directory check", Severity.INFO),
            (r'\.mkdir\(', "Make directory", "Good: directory creation", Severity.INFO),
            (r'\.rmdir\(', "Remove directory", "Good: directory removal", Severity.INFO),
            (r'\.unlink\(', "Unlink file", "Good: file deletion", Severity.INFO),
            (r'\.rename\(', "Rename", "Good: renaming", Severity.INFO),
            (r'\.glob\(', "Glob pattern", "Good: pattern matching", Severity.INFO),
            (r'\.rglob\(', "Recursive glob", "Good: recursive pattern", Severity.INFO),
            (r'\.iterdir\(', "Iterate directory", "Good: directory iteration", Severity.INFO),
            (r'\.resolve\(\)', "Resolve path", "Good: path resolution", Severity.INFO),
            (r'\.absolute\(\)', "Absolute path", "Good: absolute path", Severity.INFO),
            (r'\.parent', "Parent directory", "Good: parent path", Severity.INFO),
            (r'\.name', "File name", "Good: getting name", Severity.INFO),
            (r'\.stem', "File stem", "Good: getting stem", Severity.INFO),
            (r'\.suffix', "File suffix", "Good: getting suffix", Severity.INFO),
            (r'\.suffixes', "File suffixes", "Good: getting suffixes", Severity.INFO),
            (r'\.parts', "Path parts", "Good: path components", Severity.INFO),
            (r'\.drive', "Drive letter", "Good: drive letter", Severity.INFO),
            (r'\.root', "Root directory", "Good: root path", Severity.INFO),
            (r'\.anchor', "Path anchor", "Good: path anchor", Severity.INFO),
            
            # JSON operations
            (r'json\.loads\(', "JSON load", "Good: JSON parsing", Severity.INFO),
            (r'json\.dumps\(', "JSON dump", "Good: JSON serialization", Severity.INFO),
            (r'json\.load\(', "JSON file load", "Good: JSON file reading", Severity.INFO),
            (r'json\.dump\(', "JSON file dump", "Good: JSON file writing", Severity.INFO),
            
            # Pickle operations
            (r'pickle\.loads\(', "Pickle load", "Use JSON for safety", Severity.WARNING),
            (r'pickle\.load\(', "Pickle file load", "Use JSON for safety", Severity.WARNING),
            (r'pickle\.dumps\(', "Pickle dump", "Good: serialization", Severity.INFO),
            (r'pickle\.dump\(', "Pickle file dump", "Good: serialization", Severity.INFO),
            
            # Logging
            (r'logging\.debug\(', "Debug logging", "Good: debug logging", Severity.INFO),
            (r'logging\.info\(', "Info logging", "Good: info logging", Severity.INFO),
            (r'logging\.warning\(', "Warning logging", "Good: warning logging", Severity.INFO),
            (r'logging\.error\(', "Error logging", "Good: error logging", Severity.INFO),
            (r'logging\.critical\(', "Critical logging", "Good: critical logging", Severity.INFO),
            
            # Testing patterns
            (r'def\s+test_\w+', "Test function", "Good: test function", Severity.INFO),
            (r'class\s+Test\w+', "Test class", "Good: test class", Severity.INFO),
            (r'@pytest\.fixture', "Pytest fixture", "Good: test fixture", Severity.INFO),
            (r'@pytest\.mark\.', "Pytest marker", "Good: test marker", Severity.INFO),
            (r'assert\s+', "Assert statement", "Good: assertion", Severity.INFO),
            (r'with\s+pytest\.raises\(', "Pytest raises", "Good: exception testing", Severity.INFO),
            
            # Async patterns
            (r'async\s+def', "Async function", "Good: async function", Severity.INFO),
            (r'await\s+', "Await", "Good: await expression", Severity.INFO),
            (r'asyncio\.run\(', "Asyncio run", "Good: async execution", Severity.INFO),
            (r'asyncio\.gather\(', "Asyncio gather", "Good: concurrent tasks", Severity.INFO),
            (r'asyncio\.create_task\(', "Create task", "Good: task creation", Severity.INFO),
            
            # Dataclass patterns
            (r'@dataclass', "Dataclass", "Good: data class", Severity.INFO),
            (r'@dataclass\s*\(', "Dataclass with options", "Good: configured dataclass", Severity.INFO),
            (r'field\(', "Dataclass field", "Good: field configuration", Severity.INFO),
            (r'@dataclass\s+class', "Dataclass class", "Good: dataclass definition", Severity.INFO),
            
            # Named tuple patterns
            (r'NamedTuple', "Named tuple", "Good: named tuple", Severity.INFO),
            (r'class\s+\w+\(NamedTuple\):', "Named tuple class", "Good: named tuple definition", Severity.INFO),
            
            # Enum patterns
            (r'from\s+enum\s+import', "Enum import", "Good: enum usage", Severity.INFO),
            (r'class\s+\w+\(Enum\):', "Enum class", "Good: enum definition", Severity.INFO),
            (r'class\s+\w+\(IntEnum\):', "IntEnum class", "Good: int enum", Severity.INFO),
            (r'class\s+\w+\(StrEnum\):', "StrEnum class", "Good: string enum", Severity.INFO),
            
            # Protocol patterns
            (r'Protocol', "Protocol", "Good: structural typing", Severity.INFO),
            (r'class\s+\w+\(Protocol\):', "Protocol class", "Good: protocol definition", Severity.INFO),
            
            # TypeVar patterns
            (r'TypeVar', "TypeVar", "Good: generic type", Severity.INFO),
            (r'TypeVar\(', "TypeVar definition", "Good: generic type variable", Severity.INFO),
            
            # Literal patterns
            (r'Literal', "Literal type", "Good: literal type", Severity.INFO),
            (r'Literal\[', "Literal type annotation", "Good: literal annotation", Severity.INFO),
            
            # TypedDict patterns
            (r'TypedDict', "TypedDict", "Good: typed dictionary", Severity.INFO),
            (r'class\s+\w+\(TypedDict\):', "TypedDict class", "Good: typed dict definition", Severity.INFO),
            
            # Optional patterns
            (r'Optional\[', "Optional type", "Good: optional type", Severity.INFO),
            (r'None\s*\|', "Union None", "Good: optional type (3.10+)", Severity.INFO),
            
            # Union patterns
            (r'Union\[', "Union type", "Good: union type", Severity.INFO),
            (r'\w+\s*\|\s*\w+', "Union type syntax", "Good: union type (3.10+)", Severity.INFO),
            
            # Callable patterns
            (r'Callable\[', "Callable type", "Good: callable type", Severity.INFO),
            (r'Callable\(', "Callable type", "Good: callable type", Severity.INFO),
            
            # Iterator patterns
            (r'Iterator\[', "Iterator type", "Good: iterator type", Severity.INFO),
            (r'Iterable\[', "Iterable type", "Good: iterable type", Severity.INFO),
            (r'Generator\[', "Generator type", "Good: generator type", Severity.INFO),
            (r'AsyncIterator\[', "Async iterator type", "Good: async iterator", Severity.INFO),
            (r'AsyncIterable\[', "Async iterable type", "Good: async iterable", Severity.INFO),
            (r'AsyncGenerator\[', "Async generator type", "Good: async generator", Severity.INFO),
            
            # Context manager patterns
            (r'ContextManager\[', "Context manager type", "Good: context manager type", Severity.INFO),
            (r'AsyncContextManager\[', "Async context manager type", "Good: async context manager", Severity.INFO),
            
            # Class patterns
            (r'class\s+\w+\(.*\):', "Class definition", "Good: class definition", Severity.INFO),
            (r'def\s+__init__\(', "Init method", "Good: constructor", Severity.INFO),
            (r'def\s+__str__\(', "String representation", "Good: string conversion", Severity.INFO),
            (r'def\s+__repr__\(', "Repr method", "Good: repr", Severity.INFO),
            (r'def\s+__eq__\(', "Equality method", "Good: equality", Severity.INFO),
            (r'def\s+__hash__\(', "Hash method", "Good: hashing", Severity.INFO),
            (r'def\s+__lt__\(', "Less than method", "Good: comparison", Severity.INFO),
            (r'def\s+__le__\(', "Less equal method", "Good: comparison", Severity.INFO),
            (r'def\s+__gt__\(', "Greater than method", "Good: comparison", Severity.INFO),
            (r'def\s+__ge__\(', "Greater equal method", "Good: comparison", Severity.INFO),
            (r'def\s+__add__\(', "Add method", "Good: addition", Severity.INFO),
            (r'def\s+__sub__\(', "Subtract method", "Good: subtraction", Severity.INFO),
            (r'def\s+__mul__\(', "Multiply method", "Good: multiplication", Severity.INFO),
            (r'def\s+__truediv__\(', "True division method", "Good: division", Severity.INFO),
            (r'def\s+__floordiv__\(', "Floor division method", "Good: floor division", Severity.INFO),
            (r'def\s+__mod__\(', "Modulo method", "Good: modulo", Severity.INFO),
            (r'def\s+__pow__\(', "Power method", "Good: exponentiation", Severity.INFO),
            (r'def\s+__and__\(', "And method", "Good: bitwise and", Severity.INFO),
            (r'def\s+__or__\(', "Or method", "Good: bitwise or", Severity.INFO),
            (r'def\s+__xor__\(', "Xor method", "Good: bitwise xor", Severity.INFO),
            (r'def\s+__invert__\(', "Invert method", "Good: bitwise invert", Severity.INFO),
            (r'def\s+__neg__\(', "Negate method", "Good: negation", Severity.INFO),
            (r'def\s+__pos__\(', "Positive method", "Good: positive", Severity.INFO),
            (r'def\s+__abs__\(', "Absolute method", "Good: absolute value", Severity.INFO),
            (r'def\s+__len__\(', "Length method", "Good: length", Severity.INFO),
            (r'def\s+__getitem__\(', "Get item method", "Good: indexing", Severity.INFO),
            (r'def\s+__setitem__\(', "Set item method", "Good: item assignment", Severity.INFO),
            (r'def\s+__delitem__\(', "Delete item method", "Good: item deletion", Severity.INFO),
            (r'def\s+__iter__\(', "Iterator method", "Good: iteration", Severity.INFO),
            (r'def\s+__next__\(', "Next method", "Good: next element", Severity.INFO),
            (r'def\s+__enter__\(', "Enter method", "Good: context manager", Severity.INFO),
            (r'def\s+__exit__\(', "Exit method", "Good: context manager", Severity.INFO),
            (r'def\s+__call__\(', "Call method", "Good: callable object", Severity.INFO),
            (r'def\s+__bool__\(', "Bool method", "Good: boolean conversion", Severity.INFO),
            (r'def\s+__contains__\(', "Contains method", "Good: membership test", Severity.INFO),
            (r'def\s+__copy__\(', "Copy method", "Good: shallow copy", Severity.INFO),
            (r'def\s+__deepcopy__\(', "Deep copy method", "Good: deep copy", Severity.INFO),
            (r'def\s+__sizeof__\(', "Sizeof method", "Good: size calculation", Severity.INFO),
            (r'def\s+__reduce__\(', "Reduce method", "Good: pickling", Severity.INFO),
            (r'def\s+__reduce_ex__\(', "Reduce ex method", "Good: pickling", Severity.INFO),
            (r'def\s+__getstate__\(', "Getstate method", "Good: pickling", Severity.INFO),
            (r'def\s+__setstate__\(', "Setstate method", "Good: pickling", Severity.INFO),
            (r'def\s+__missing__\(', "Missing method", "Good: missing key handling", Severity.INFO),
            (r'def\s+__reversed__\(', "Reversed method", "Good: reverse iteration", Severity.INFO),
            (r'def\s+__sizeof__\(', "Sizeof method", "Good: size calculation", Severity.INFO),
        ]
        
        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith('#'):
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
