"""
Python-specific comprehensive rules.
"""
import re
from ..core.models import CodeIssue, Severity, IssueCategory
from ..core.rules import BaseRule


class PythonLanguageRules(BaseRule):
    @property
    def name(self) -> str:
        return "python_language"
    @property
    def description(self) -> str:
        return "Python-specific comprehensive patterns"
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
            # Python best practices
            (r"if __name__ == .__main__.", "Main guard", "Good: main guard", Severity.INFO),
            (r"from __future__ import", "Future import", "Good: future imports", Severity.INFO),
            (r"@property|@staticmethod|@classmethod", "Decorator usage", "Good: decorators", Severity.INFO),
            (r"__init__|__str__|__repr__|__eq__|__hash__|__lt__|__le__|__gt__|__ge__|__add__|__sub__|__mul__|__truediv__|__floordiv__|__mod__|__pow__|__and__|__or__|__xor__", "Dunder methods", "Good: dunder methods", Severity.INFO),
            (r"__slots__", "Slots usage", "Good: __slots__", Severity.INFO),
            (r"__all__", "Module exports", "Good: __all__", Severity.INFO),
            (r"dataclass|@dataclass", "Dataclass", "Good: dataclass usage", Severity.INFO),
            (r"Protocol|typing.Protocol", "Protocol typing", "Good: Protocol typing", Severity.INFO),
            (r"TypedDict|typing.TypedDict", "TypedDict", "Good: TypedDict", Severity.INFO),
            (r"Literal|typing.Literal", "Literal type", "Good: Literal type", Severity.INFO),
            (r"TypeAlias|typing.TypeAlias", "TypeAlias", "Good: TypeAlias", Severity.INFO),
            (r"ParamSpec|typing.ParamSpec", "ParamSpec", "Good: ParamSpec", Severity.INFO),
            (r"TypeVar|typing.TypeVar", "TypeVar", "Good: TypeVar", Severity.INFO),
            (r"Generic|typing.Generic", "Generic type", "Good: Generic type", Severity.INFO),
            (r"Annotated|typing.Annotated", "Annotated type", "Good: Annotated type", Severity.INFO),
            (r"Self|typing.Self", "Self type", "Good: Self type", Severity.INFO),
            (r"override|typing.override", "Override decorator", "Good: override decorator", Severity.INFO),
            # Python anti-patterns
            (r"except:", "Bare except", "Use specific exceptions", Severity.WARNING),
            (r"except Exception:", "Broad except", "Use specific exceptions", Severity.WARNING),
            (r"import \*", "Wildcard import", "Use explicit imports", Severity.WARNING),
            (r"print\(", "Print statement", "Use logging instead", Severity.INFO),
            (r"exec\(", "Exec statement", "Avoid exec", Severity.WARNING),
            (r"eval\(", "Eval statement", "Avoid eval", Severity.WARNING),
            (r"globals\(\)", "Globals access", "Avoid globals", Severity.WARNING),
            (r"locals\(\)", "Locals access", "Avoid locals", Severity.WARNING),
            (r"lambda\s+\w+\s*:\s*\w+\(", "Lambda with function call", "Use list comprehension", Severity.INFO),
            (r"map\(\s*lambda", "Map with lambda", "Use list comprehension", Severity.INFO),
            (r"filter\(\s*lambda", "Filter with lambda", "Use list comprehension", Severity.INFO),
            (r"sorted\(\s*lambda", "Sorted with lambda", "Use key parameter", Severity.INFO),
            (r"reduce\(", "Reduce usage", "Consider list comprehension", Severity.INFO),
            # Python imports
            (r"from\s+\w+\s+import\s+\w+", "Relative import", "Good: relative import", Severity.INFO),
            (r"import\s+\w+\.\w+", "Package import", "Good: package import", Severity.INFO),
            (r"from\s+\w+\.\w+\s+import", "Package from import", "Good: package from import", Severity.INFO),
            # Python classes
            (r"class\s+\w+\(.*\):", "Class definition", "Good: class definition", Severity.INFO),
            (r"def\s+__init__\(self", "Init method", "Good: init method", Severity.INFO),
            (r"self\.\w+", "Self attribute", "Good: self attribute", Severity.INFO),
            (r"cls\.\w+", "Class attribute", "Good: cls attribute", Severity.INFO),
            # Python functions
            (r"def\s+\w+\(self", "Instance method", "Good: instance method", Severity.INFO),
            (r"@staticmethod", "Static method", "Good: static method", Severity.INFO),
            (r"@classmethod", "Class method", "Good: class method", Severity.INFO),
            (r"@property", "Property", "Good: property", Severity.INFO),
            # Python async
            (r"async\s+def", "Async function", "Good: async function", Severity.INFO),
            (r"await\s+", "Await", "Good: await", Severity.INFO),
            (r"asyncio\.", "asyncio usage", "Good: asyncio", Severity.INFO),
            # Python testing
            (r"import\s+unittest", "unittest import", "Good: unittest", Severity.INFO),
            (r"import\s+pytest", "pytest import", "Good: pytest", Severity.INFO),
            (r"def\s+test_", "Test function", "Good: test function", Severity.INFO),
            (r"class\s+Test", "Test class", "Good: test class", Severity.INFO),
            (r"@pytest\.fixture", "Pytest fixture", "Good: pytest fixture", Severity.INFO),
            (r"@pytest\.mark\.", "Pytest marker", "Good: pytest marker", Severity.INFO),
            (r"assert\s+", "Assert statement", "Good: assert", Severity.INFO),
            (r"assertRaises|assertEqual|assertTrue|assertFalse|assertIn|assertNotIn|assertIsNone|assertIsNotNone|assertIsInstance|assertNotIsInstance|assertAlmostEqual|assertNotAlmostEqual|assertCountEqual|assertDictEqual|assertListEqual|assertSetEqual|assertMultiLineEqual|assertRegex|assertNotRegex|assertRaisesRegex", "Unittest assert", "Good: unittest assert", Severity.INFO),
            # Python context managers
            (r"with\s+\w+\s+as\s+\w+\s*:", "Context manager", "Good: context manager", Severity.INFO),
            (r"__enter__|__exit__", "Context manager protocol", "Good: context manager", Severity.INFO),
            (r"contextmanager|@contextmanager", "Context manager decorator", "Good: contextmanager", Severity.INFO),
            (r"asynccontextmanager|@asynccontextmanager", "Async context manager", "Good: async context manager", Severity.INFO),
            # Python generators
            (r"yield\s+", "Yield", "Good: yield", Severity.INFO),
            (r"yield\s+from", "Yield from", "Good: yield from", Severity.INFO),
            (r"\(.*for\s+\w+\s+in\s+\w+.*\)", "Generator expression", "Good: generator expression", Severity.INFO),
            # Python comprehensions
            (r"\[.*for\s+\w+\s+in\s+\w+.*\]", "List comprehension", "Good: list comprehension", Severity.INFO),
            (r"\{.*for\s+\w+\s+in\s+\w+.*\}", "Dict/set comprehension", "Good: comprehension", Severity.INFO),
            # Python logging
            (r"import\s+logging", "Logging import", "Good: logging import", Severity.INFO),
            (r"logging\.getLogger", "Logger creation", "Good: logger creation", Severity.INFO),
            (r"logger\.\w+", "Logger usage", "Good: logger usage", Severity.INFO),
            (r"logging\.debug|logging\.info|logging\.warning|logging\.error|logging\.critical", "Logging level", "Good: logging levels", Severity.INFO),
            # Python pathlib
            (r"from\s+pathlib\s+import", "Pathlib import", "Good: pathlib", Severity.INFO),
            (r"Path\(", "Path usage", "Good: pathlib Path", Severity.INFO),
            (r"\.read_text\(\)|\.read_bytes\(\)|\.write_text\(\)|\.write_bytes\(\)", "Pathlib IO", "Good: pathlib IO", Severity.INFO),
            # Python typing
            (r"from\s+typing\s+import", "Typing import", "Good: typing import", Severity.INFO),
            (r"Optional\[", "Optional type", "Good: Optional type", Severity.INFO),
            (r"Union\[", "Union type", "Good: Union type", Severity.INFO),
            (r"List\[", "List type", "Good: List type", Severity.INFO),
            (r"Dict\[", "Dict type", "Good: Dict type", Severity.INFO),
            (r"Tuple\[", "Tuple type", "Good: Tuple type", Severity.INFO),
            (r"Set\[", "Set type", "Good: Set type", Severity.INFO),
            (r"Callable\[", "Callable type", "Good: Callable type", Severity.INFO),
            (r"Iterator\[", "Iterator type", "Good: Iterator type", Severity.INFO),
            (r"Iterable\[", "Iterable type", "Good: Iterable type", Severity.INFO),
            (r"Sequence\[", "Sequence type", "Good: Sequence type", Severity.INFO),
            (r"Mapping\[", "Mapping type", "Good: Mapping type", Severity.INFO),
            (r"Any", "Any type", "Good: Any type", Severity.INFO),
            (r"NoReturn", "NoReturn type", "Good: NoReturn type", Severity.INFO),
            (r"ClassVar\[", "ClassVar type", "Good: ClassVar type", Severity.INFO),
            (r"Final\[", "Final type", "Good: Final type", Severity.INFO),
            (r"Type\[", "Type type", "Good: Type type", Severity.INFO),
            # Python dataclasses
            (r"@dataclass", "Dataclass decorator", "Good: dataclass", Severity.INFO),
            (r"from\s+dataclasses\s+import", "Dataclass import", "Good: dataclass import", Severity.INFO),
            (r"field\(|Field\(", "Dataclass field", "Good: dataclass field", Severity.INFO),
            (r"asdict|astuple|fields|dataclass|replace", "Dataclass functions", "Good: dataclass functions", Severity.INFO),
            # Python enum
            (r"from\s+enum\s+import", "Enum import", "Good: enum import", Severity.INFO),
            (r"class\s+\w+\(Enum\)|class\s+\w+\(IntEnum\)|class\s+\w+\(StrEnum\)|class\s+\w+\(Flag\)|class\s+\w+\(IntFlag\)", "Enum class", "Good: enum class", Severity.INFO),
            # Python abc
            (r"from\s+abc\s+import", "ABC import", "Good: abc import", Severity.INFO),
            (r"@abstractmethod", "Abstract method", "Good: abstract method", Severity.INFO),
            (r"ABC|ABCMeta", "ABC usage", "Good: ABC", Severity.INFO),
            # Python attrs
            (r"import\s+attr|from\s+attr\s+import|from\s+attrs\s+import", "Attrs import", "Good: attrs", Severity.INFO),
            (r"@attr\.s|@attrs|@define", "Attrs decorator", "Good: attrs decorator", Severity.INFO),
            (r"attr\.ib|attrib|field", "Attrs field", "Good: attrs field", Severity.INFO),
            # Python pydantic
            (r"from\s+pydantic\s+import|import\s+pydantic", "Pydantic import", "Good: pydantic", Severity.INFO),
            (r"BaseModel|BaseSettings", "Pydantic model", "Good: pydantic model", Severity.INFO),
            (r"Field\(|validator|root_validator|model_validator|field_validator", "Pydantic field", "Good: pydantic field", Severity.INFO),
            # Python fastapi
            (r"from\s+fastapi\s+import|import\s+fastapi", "FastAPI import", "Good: FastAPI", Severity.INFO),
            (r"FastAPI\(|APIRouter\(|Depends\(|HTTPException|Query\(|Path\(|Body\(|Header\(|Cookie\(|Form\(|File\(|UploadFile", "FastAPI usage", "Good: FastAPI", Severity.INFO),
            (r"@app\.\w+|@router\.\w+", "FastAPI route", "Good: FastAPI route", Severity.INFO),
            # Python flask
            (r"from\s+flask\s+import|import\s+flask", "Flask import", "Good: Flask", Severity.INFO),
            (r"Flask\(|Blueprint\(|request|jsonify|abort|redirect|url_for|render_template|session|g\.|current_app", "Flask usage", "Good: Flask", Severity.INFO),
            (r"@app\.route|@blueprint\.route", "Flask route", "Good: Flask route", Severity.INFO),
            # Python django
            (r"from\s+django\s+import|import\s+django", "Django import", "Good: Django", Severity.INFO),
            (r"models\.Model|views\.\w+|forms\.Form|serializers\.Serializer|admin\.site", "Django usage", "Good: Django", Severity.INFO),
            (r"@login_required|@permission_required|@csrf_exempt|@cache_page|@require_http_methods", "Django decorator", "Good: Django decorator", Severity.INFO),
            # Python sqlalchemy
            (r"from\s+sqlalchemy\s+import|import\s+sqlalchemy", "SQLAlchemy import", "Good: SQLAlchemy", Severity.INFO),
            (r"Column\(|relationship\(|backref=|lazy=|cascade=|primary_key=|foreign_key=|unique=|nullable=|default=|onupdate=|server_default=", "SQLAlchemy field", "Good: SQLAlchemy field", Severity.INFO),
            # Python click
            (r"from\s+click\s+import|import\s+click", "Click import", "Good: Click", Severity.INFO),
            (r"@click\.command|@click\.option|@click\.argument|@click\.group|@click\.pass_context", "Click decorator", "Good: Click decorator", Severity.INFO),
            # Python asyncio
            (r"import\s+asyncio|from\s+asyncio\s+import", "asyncio import", "Good: asyncio", Severity.INFO),
            (r"asyncio\.run|asyncio\.gather|asyncio\.create_task|asyncio\.ensure_future|asyncio\.wait|asyncio\.wait_for", "asyncio usage", "Good: asyncio", Severity.INFO),
            (r"asyncio\.Lock|asyncio\.Event|asyncio\.Condition|asyncio\.Semaphore|asyncio\.Queue", "asyncio synchronization", "Good: asyncio sync", Severity.INFO),
            (r"asyncio\.TaskGroup|asyncio\.Task", "asyncio task", "Good: asyncio task", Severity.INFO),
            # Python typing modern
            (r"list\[", "Lowercase list", "Good: lowercase list (3.9+)", Severity.INFO),
            (r"dict\[", "Lowercase dict", "Good: lowercase dict (3.9+)", Severity.INFO),
            (r"tuple\[", "Lowercase tuple", "Good: lowercase tuple (3.9+)", Severity.INFO),
            (r"set\[", "Lowercase set", "Good: lowercase set (3.9+)", Severity.INFO),
            (r"frozenset\[", "Lowercase frozenset", "Good: lowercase frozenset (3.9+)", Severity.INFO),
            (r"type\[", "Lowercase type", "Good: lowercase type (3.9+)", Severity.INFO),
        ]
        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith('#'):
                continue
            for pattern, message, severity in patterns:
                if re.search(pattern, line):
                    issues.append(self._create_issue(
                        file_path=file_path, line=line_num, message=message,
                        suggestion=message, severity=severity, code_snippet=stripped,
                    ))
        return issues
