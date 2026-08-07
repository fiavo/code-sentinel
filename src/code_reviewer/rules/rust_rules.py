"""
Rust-specific comprehensive rules.
"""
import re
from ..core.models import CodeIssue, Severity, IssueCategory
from ..core.rules import BaseRule


class RustLanguageRules(BaseRule):
    @property
    def name(self) -> str:
        return "rust_language"
    @property
    def description(self) -> str:
        return "Rust-specific comprehensive patterns"
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
            # Rust features
            (r"fn\s+\w+", "Function definition", "Good: function definition", Severity.INFO),
            (r"pub\s+fn\s+\w+", "Public function", "Good: public function", Severity.INFO),
            (r"pub\(crate\)\s+fn", "Crate-private function", "Good: crate-private", Severity.INFO),
            (r"pub\(super\)\s+fn", "Parent module private", "Good: parent module private", Severity.INFO),
            (r"pub\(self\)\s+fn", "Module private", "Good: module private", Severity.INFO),
            (r"async\s+fn\s+\w+", "Async function", "Good: async function", Severity.INFO),
            (r"const\s+fn\s+\w+", "Const function", "Good: const function", Severity.INFO),
            (r"unsafe\s+fn\s+\w+", "Unsafe function", "Minimize unsafe code", Severity.WARNING),
            (r"extern\s+\"C\"\s+fn\s+\w+", "FFI function", "Good: FFI function", Severity.INFO),
            (r"#\[derive\(", "Derive macro", "Good: derive macros", Severity.INFO),
            (r"#\[cfg\(", "Conditional compilation", "Good: cfg attribute", Severity.INFO),
            (r"#\[test\]", "Test attribute", "Good: test attribute", Severity.INFO),
            (r"#\[bench\]", "Bench attribute", "Good: bench attribute", Severity.INFO),
            (r"#\[tokio::main\]", "Tokio main", "Good: Tokio main", Severity.INFO),
            (r"#\[tokio::test\]", "Tokio test", "Good: Tokio test", Severity.INFO),
            # Ownership
            (r"&mut\s+", "Mutable reference", "Good: mutable reference", Severity.INFO),
            (r"&\w+", "Immutable reference", "Good: immutable reference", Severity.INFO),
            (r"move\s+\|", "Move closure", "Good: move closure", Severity.INFO),
            (r"Rc::new|Arc::new|Box::new|Cell::new|RefCell::new", "Smart pointers", "Good: smart pointers", Severity.INFO),
            (r"clone\(\)|Clone", "Clone trait", "Good: Clone trait", Severity.INFO),
            (r"copy\(\)|Copy|Copy", "Copy trait", "Good: Copy trait", Severity.INFO),
            (r"into\(\)|From|Into|TryFrom|TryInto", "Conversion traits", "Good: conversion traits", Severity.INFO),
            (r"as_ref\(\)|AsRef|AsMut", "Borrowing traits", "Good: borrowing traits", Severity.INFO),
            # Error handling
            (r"Result<", "Result type", "Good: Result type", Severity.INFO),
            (r"Option<", "Option type", "Good: Option type", Severity.INFO),
            (r"?;", "Error propagation", "Good: error propagation", Severity.INFO),
            (r"unwrap\(\)", "unwrap usage", "Use expect() or match instead", Severity.WARNING),
            (r"expect\(", "expect usage", "Good: expect", Severity.INFO),
            (r"unwrap_or\(|unwrap_or_else\(|unwrap_or_default\(", "unwrap_or usage", "Good: unwrap_or", Severity.INFO),
            (r"map\(|and_then\(|or_else\(|ok_or\(|ok_or_else\(|transpose\(|flatten\(", "Combinators", "Good: combinators", Severity.INFO),
            (r"match\s+\w+\s*\{", "Match expression", "Good: match expression", Severity.INFO),
            (r"if\s+let\s+", "if let", "Good: if let", Severity.INFO),
            (r"while\s+let\s+", "while let", "Good: while let", Severity.INFO),
            # Patterns
            (r"enum\s+\w+", "Enum definition", "Good: enum definition", Severity.INFO),
            (r"struct\s+\w+", "Struct definition", "Good: struct definition", Severity.INFO),
            (r"trait\s+\w+", "Trait definition", "Good: trait definition", Severity.INFO),
            (r"impl\s+\w+", "Impl block", "Good: impl block", Severity.INFO),
            (r"impl\s+<\w+>\s+\w+", "Generic impl", "Good: generic impl", Severity.INFO),
            (r"type\s+\w+\s*=", "Type alias", "Good: type alias", Severity.INFO),
            (r"where\s+\w+\s*:", "Where clause", "Good: where clause", Severity.INFO),
            # Iterators
            (r"\.iter\(\)|\.iter_mut\(\)|\.into_iter\(\)", "Iterator", "Good: iterator", Severity.INFO),
            (r"\.map\(|\.filter\(|\.fold\(|\.reduce\(|\.collect\(|\.chain\(|\.zip\(|\.enumerate\(|\.take\(|\.skip\(|\.rev\(|\.any\(|\.all\(|\.find\(|\.position\(|\.count\(|\.sum\(|\.product\(", "Iterator method", "Good: iterator methods", Severity.INFO),
            # Concurrency
            (r"tokio::spawn|std::thread::spawn|rayon::par_iter|crossbeam::", "Concurrency", "Good: concurrency", Severity.INFO),
            (r"Mutex::new|RwLock::new|Arc::new|AtomicBool|AtomicIsize|AtomicUsize", "Thread safety", "Good: thread safety", Severity.INFO),
            (r"async\s+fn|\.await|Future|Pin|Poll|Waker|Context", "Async", "Good: async code", Severity.INFO),
            # Macros
            (r"macro_rules!", "Macro definition", "Good: macro definition", Severity.INFO),
            (r"println!\(|eprintln!\(|print!\(|eprint!\(|format!\(|vec!\(|vec!\[\]|panic!\(|assert!\(|assert_eq!\(|assert_ne!\(|debug_assert!\(|debug_assert_eq!\(|debug_assert_ne!\(|todo!\(|unimplemented!\(|unreachable!\(|dbg!\(", "Macro usage", "Good: macro usage", Severity.INFO),
            # Modules
            (r"mod\s+\w+", "Module definition", "Good: module definition", Severity.INFO),
            (r"use\s+\w+", "Use statement", "Good: use statement", Severity.INFO),
            (r"pub\s+use\s+\w+", "Re-export", "Good: re-export", Severity.INFO),
            (r"crate::", "Crate path", "Good: crate path", Severity.INFO),
            (r"super::", "Super path", "Good: super path", Severity.INFO),
            (r"self::", "Self path", "Good: self path", Severity.INFO),
            # Testing
            (r"#\[cfg\(test\)\]|#\[test\]|#\[bench\]", "Testing attributes", "Good: testing", Severity.INFO),
            (r"mod\s+tests?\s*\{", "Test module", "Good: test module", Severity.INFO),
            (r"#\[should_panic\]|#\[should_panic\(", "Panic test", "Good: panic test", Severity.INFO),
            (r"assert!\(|assert_eq!\(|assert_ne!\(|assert_matches!\(", "Assert macros", "Good: assert macros", Severity.INFO),
            # Clippy
            (r"#!\[allow\(|#!\[deny\(|#!\[warn\(|#!\[forbid\(|#!\[allow\(", "Clippy attribute", "Good: Clippy", Severity.INFO),
            (r"#!\[allow\(clippy::", "Clippy allow", "Good: Clippy", Severity.INFO),
            (r"#!\[deny\(clippy::", "Clippy deny", "Good: Clippy", Severity.INFO),
            (r"#!\[warn\(clippy::", "Clippy warn", "Good: Clippy", Severity.INFO),
            (r"#!\[forbid\(clippy::", "Clippy forbid", "Good: Clippy", Severity.INFO),
            # Cargo
            (r"Cargo\.toml|Cargo\.lock", "Cargo file", "Good: Cargo files", Severity.INFO),
            (r"\[dependencies\]|\[dev-dependencies\]|\[build-dependencies\]", "Cargo dependencies", "Good: Cargo dependencies", Severity.INFO),
            (r"cargo\s+build|cargo\s+run|cargo\s+test|cargo\s+bench|cargo\s+doc|cargo\s+clippy|cargo\s+fmt|cargo\s+update|cargo\s+install|cargo\s+new|cargo\s+init", "Cargo command", "Good: Cargo command", Severity.INFO),
            # Common traits
            (r"Display|Debug|Clone|Copy|PartialEq|Eq|PartialOrd|Ord|Hash|Default|From|Into|TryFrom|TryInto|AsRef|AsMut|Deref|DerefMut|Drop|Iterator|IntoIterator|Extend|ExactSizeIterator|DoubleEndedIterator|FusedIterator|TrustedLen|Step", "Trait", "Good: trait usage", Severity.INFO),
            # Serialization
            (r"serde|Serialize|Deserialize|serde_json|toml|yaml", "Serialization", "Good: serialization", Severity.INFO),
            # Logging
            (r"log|tracing|env_logger|log4rs|slog|fern|simplelog|tracing_subscriber", "Logging crate", "Good: logging", Severity.INFO),
            # Web
            (r"actix|axum|warp|rocket|tide|hyper|reqwest|surf|isahc|ureq|attohttpc", "Web framework", "Good: web frameworks", Severity.INFO),
            # Database
            (r"sqlx|diesel|sea-orm|rusqlite|postgres|mysql|redis|mongodb|tokio-postgres", "Database crate", "Good: database crates", Severity.INFO),
        ]
        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith('//'):
                continue
            for pattern, message, severity in patterns:
                if re.search(pattern, line):
                    issues.append(self._create_issue(
                        file_path=file_path, line=line_num, message=message,
                        suggestion=message, severity=severity, code_snippet=stripped,
                    ))
        return issues
