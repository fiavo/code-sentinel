"""
Comprehensive error handling patterns for all languages.
"""
import re
from ..core.models import CodeIssue, Severity, IssueCategory
from ..core.rules import BaseRule


class ErrorHandlingComprehensiveRules(BaseRule):
    @property
    def name(self) -> str:
        return "error_handling_comprehensive"
    @property
    def description(self) -> str:
        return "Comprehensive error handling patterns"
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
            # Generic error handling patterns
            (r"try\s*\{", "try block", "Good: using try-catch", Severity.INFO),
            (r"catch\s*\(", "catch block", "Good: catching errors", Severity.INFO),
            (r"except\s*\(", "except block", "Good: catching exceptions", Severity.INFO),
            (r"except\s*:", "bare except", "Avoid bare except; catch specific exceptions", Severity.WARNING),
            (r"catch\s*\(\s*\.\.\.\s*\)", "catch-all", "Avoid catch-all; catch specific types", Severity.WARNING),
            (r"finally\s*\{", "finally block", "Good: cleanup in finally", Severity.INFO),
            (r"raise\s+\w+", "raise statement", "Good: raising exceptions", Severity.INFO),
            (r"throw\s+\w+", "throw statement", "Good: throwing exceptions", Severity.INFO),
            (r"panic!\(", "panic call", "Avoid panic in production", Severity.WARNING),
            (r"process\.exit\(", "process.exit()", "Avoid abrupt exit; use proper cleanup", Severity.WARNING),
            (r"System\.exit\(", "System.exit()", "Avoid System.exit in library code", Severity.WARNING),
            (r"abort\(\)", "abort() call", "Avoid abort; use proper error handling", Severity.CRITICAL),
            (r"exit\(\d+\)", "exit() call", "Avoid exit; return error code", Severity.WARNING),
            (r"assert\s*\(", "assert statement", "Good: using assertions", Severity.INFO),
            (r"assert!\(", "assert! macro", "Good: using assert!", Severity.INFO),
            (r"assert_eq!\(", "assert_eq! macro", "Good: using assert_eq!", Severity.INFO),
            (r"abort\(", "abort call", "Avoid abort", Severity.CRITICAL),
            (r"_exit\(", "_exit call", "Avoid _exit; use exit", Severity.WARNING),
            (r"_Exit\(", "_Exit call", "Avoid _Exit; use exit", Severity.WARNING),
            (r"raise\s+NotImplementedError", "NotImplementedError", "Good: marking abstract methods", Severity.INFO),
            (r"raise\s+ValueError\(", "ValueError", "Good: validating input", Severity.INFO),
            (r"raise\s+TypeError\(", "TypeError", "Good: type checking", Severity.INFO),
            (r"raise\s+KeyError\(", "KeyError", "Good: key validation", Severity.INFO),
            (r"raise\s+IndexError\(", "IndexError", "Good: index validation", Severity.INFO),
            (r"raise\s+AttributeError\(", "AttributeError", "Good: attribute validation", Severity.INFO),
            (r"raise\s+RuntimeError\(", "RuntimeError", "Good: runtime errors", Severity.INFO),
            (r"raise\s+IOError\(", "IOError", "Good: I/O errors", Severity.INFO),
            (r"raise\s+OSError\(", "OSError", "Good: OS errors", Severity.INFO),
            (r"raise\s+FileNotFoundError\(", "FileNotFoundError", "Good: file errors", Severity.INFO),
            (r"raise\s+PermissionError\(", "PermissionError", "Good: permission errors", Severity.INFO),
            (r"raise\s+ConnectionError\(", "ConnectionError", "Good: connection errors", Severity.INFO),
            (r"raise\s+TimeoutError\(", "TimeoutError", "Good: timeout errors", Severity.INFO),
            (r"raise\s+MemoryError\(", "MemoryError", "Good: memory errors", Severity.INFO),
            (r"raise\s+ImportError\(", "ImportError", "Good: import errors", Severity.INFO),
            (r"raise\s+ModuleNotFoundError\(", "ModuleNotFoundError", "Good: module errors", Severity.INFO),
            (r"raise\s+SyntaxError\(", "SyntaxError", "Good: syntax errors", Severity.INFO),
            (r"raise\s+UnboundLocalError\(", "UnboundLocalError", "Good: variable errors", Severity.INFO),
            (r"raise\s+StopIteration\(", "StopIteration", "Good: iterator completion", Severity.INFO),
            (r"raise\s+GeneratorExit\(", "GeneratorExit", "Good: generator cleanup", Severity.INFO),
            (r"raise\s+KeyboardInterrupt\(", "KeyboardInterrupt", "Good: interrupt handling", Severity.INFO),
            (r"raise\s+SystemExit\(", "SystemExit", "Good: system exit", Severity.INFO),
            (r"raise\s+ArithmeticError\(", "ArithmeticError", "Good: arithmetic errors", Severity.INFO),
            (r"raise\s+LookupError\(", "LookupError", "Good: lookup errors", Severity.INFO),
            (r"raise\s+EncodingError\(", "EncodingError", "Good: encoding errors", Severity.INFO),
            (r"raise\s+UnicodeError\(", "UnicodeError", "Good: Unicode errors", Severity.INFO),
            (r"raise\s+UnicodeDecodeError\(", "UnicodeDecodeError", "Good: decode errors", Severity.INFO),
            (r"raise\s+UnicodeEncodeError\(", "UnicodeEncodeError", "Good: encode errors", Severity.INFO),
            (r"raise\s+UnicodeTranslateError\(", "UnicodeTranslateError", "Good: translate errors", Severity.INFO),
            (r"raise\s+ConnectionRefusedError\(", "ConnectionRefusedError", "Good: connection errors", Severity.INFO),
            (r"raise\s+ConnectionAbortedError\(", "ConnectionAbortedError", "Good: connection errors", Severity.INFO),
            (r"raise\s+ConnectionResetError\(", "ConnectionResetError", "Good: connection errors", Severity.INFO),
            (r"raise\s+BrokenPipeError\(", "BrokenPipeError", "Good: pipe errors", Severity.INFO),
            (r"raise\s+FileExistsError\(", "FileExistsError", "Good: file errors", Severity.INFO),
            (r"raise\s+IsADirectoryError\(", "IsADirectoryError", "Good: directory errors", Severity.INFO),
            (r"raise\s+NotADirectoryError\(", "NotADirectoryError", "Good: directory errors", Severity.INFO),
            (r"raise\s+ProcessLookupError\(", "ProcessLookupError", "Good: process errors", Severity.INFO),
            (r"raise\s+BlockingIOError\(", "BlockingIOError", "Good: I/O errors", Severity.INFO),
            (r"raise\s+InterruptedError\(", "InterruptedError", "Good: interrupt errors", Severity.INFO),
            (r"raise\s+RecursionError\(", "RecursionError", "Good: recursion errors", Severity.INFO),
            (r"raise\s+IndentationError\(", "IndentationError", "Good: indent errors", Severity.INFO),
            (r"raise\s+TabError\(", "TabError", "Good: tab errors", Severity.INFO),
            (r"raise\s+ReferenceError\(", "ReferenceError", "Good: reference errors", Severity.INFO),
            (r"raise\s+UnboundLocalError\(", "UnboundLocalError", "Good: variable errors", Severity.INFO),
            (r"raise\s+MemoryError\(", "MemoryError", "Good: memory errors", Severity.INFO),
            (r"raise\s+OverflowError\(", "OverflowError", "Good: overflow errors", Severity.INFO),
            (r"raise\s+ZeroDivisionError\(", "ZeroDivisionError", "Good: division errors", Severity.INFO),
            (r"raise\s+AssertionError\(", "AssertionError", "Good: assertion errors", Severity.INFO),
            (r"raise\s+NotImplementedError\(", "NotImplementedError", "Good: not implemented", Severity.INFO),
            (r"raise\s+SyntaxError\(", "SyntaxError", "Good: syntax errors", Severity.INFO),
            (r"raise\s+RuntimeError\(", "RuntimeError", "Good: runtime errors", Severity.INFO),
            (r"raise\s+SystemError\(", "SystemError", "Good: system errors", Severity.INFO),
            (r"raise\s+Exception\(", "Exception", "Good: raising exceptions", Severity.INFO),
            (r"raise\s+BaseException\(", "BaseException", "Good: base exceptions", Severity.INFO),
            (r"try!\(", "try! macro", "Avoid try!; use proper error handling", Severity.WARNING),
            (r"unwrap\(", "unwrap()", "Use .unwrap_or() or proper error handling", Severity.WARNING),
            (r"expect\(", "expect()", "Good: using expect with message", Severity.INFO),
            (r"\.unwrap_or\(", "unwrap_or()", "Good: providing default", Severity.INFO),
            (r"\.unwrap_or_else\(", "unwrap_or_else()", "Good: providing default closure", Severity.INFO),
            (r"\.unwrap_or_default\(\)", "unwrap_or_default()", "Good: using default", Severity.INFO),
            (r"\.map_err\(\|", "map_err()", "Good: mapping errors", Severity.INFO),
            (r"\?;", "operator?", "Good: using ? operator", Severity.INFO),
            (r"todo!\(\)", "todo!() call", "Replace with implementation", Severity.WARNING),
            (r"unimplemented!\(\)", "unimplemented!() call", "Replace with implementation", Severity.WARNING),
            (r"unreachable!\(\)", "unreachable!() call", "Good: marking unreachable", Severity.INFO),
            (r"onerror\s+goto", "on error goto", "Use structured error handling", Severity.WARNING),
            (r"On Error Resume Next", "VBA error handling", "Use proper error handling", Severity.WARNING),
            (r"rescue\s*\(", "rescue block", "Good: rescuing exceptions", Severity.INFO),
            (r"ensure\s*\{", "ensure block", "Good: ensuring cleanup", Severity.INFO),
            (r"raise\s+rescue\s*\(", "raise rescue", "Good: re-raising exceptions", Severity.INFO),
            (r"rethrow\s*\(", "rethrow call", "Good: re-throwing exceptions", Severity.INFO),
            (r"rethrow_exception\s*\(", "rethrow_exception", "Good: re-throwing exceptions", Severity.INFO),
            (r"catch\(\.\.\.\)", "C++ catch-all", "Good: catching all exceptions", Severity.INFO),
            (r"catch\s*\(\s*const\s+std::exception", "C++ catch exception", "Good: catching std::exception", Severity.INFO),
            (r"catch\s*\(\s*const\s+std::runtime_error", "C++ catch runtime_error", "Good: catching runtime_error", Severity.INFO),
            (r"catch\s*\(\s*const\s+std::logic_error", "C++ catch logic_error", "Good: catching logic_error", Severity.INFO),
            (r"catch\s*\(\s*const\s+std::invalid_argument", "C++ catch invalid_argument", "Good: catching invalid_argument", Severity.INFO),
            (r"catch\s*\(\s*const\s+std::out_of_range", "C++ catch out_of_range", "Good: catching out_of_range", Severity.INFO),
            (r"catch\s*\(\s*const\s+std::overflow_error", "C++ catch overflow_error", "Good: catching overflow_error", Severity.INFO),
            (r"catch\s*\(\s*const\s+std::underflow_error", "C++ catch underflow_error", "Good: catching underflow_error", Severity.INFO),
            (r"catch\s*\(\s*const\s+std::range_error", "C++ catch range_error", "Good: catching range_error", Severity.INFO),
            (r"catch\s*\(\s*const\s+std::domain_error", "C++ catch domain_error", "Good: catching domain_error", Severity.INFO),
            (r"catch\s*\(\s*const\s+std::length_error", "C++ catch length_error", "Good: catching length_error", Severity.INFO),
            (r"catch\s*\(\s*const\s+std::bad_alloc", "C++ catch bad_alloc", "Good: catching bad_alloc", Severity.INFO),
            (r"catch\s*\(\s*const\s+std::bad_cast", "C++ catch bad_cast", "Good: catching bad_cast", Severity.INFO),
            (r"catch\s*\(\s*const\s+std::bad_typeid", "C++ catch bad_typeid", "Good: catching bad_typeid", Severity.INFO),
            (r"catch\s*\(\s*const\s+std::bad_exception", "C++ catch bad_exception", "Good: catching bad_exception", Severity.INFO),
            (r"catch\s*\(\s*const\s+std::bad_function_call", "C++ catch bad_function_call", "Good: catching bad_function_call", Severity.INFO),
            (r"catch\s*\(\s*const\s+std::bad_weak_ptr", "C++ catch bad_weak_ptr", "Good: catching bad_weak_ptr", Severity.INFO),
            (r"catch\s*\(\s*const\s+std::system_error", "C++ catch system_error", "Good: catching system_error", Severity.INFO),
            (r"catch\s*\(\s*const\s+std::ios_base::failure", "C++ catch ios_base::failure", "Good: catching ios_base::failure", Severity.INFO),
            (r"catch\s*\(\s*const\s+std::future_error", "C++ catch future_error", "Good: catching future_error", Severity.INFO),
            (r"catch\s*\(\s*const\s+std::regex_error", "C++ catch regex_error", "Good: catching regex_error", Severity.INFO),
            (r"catch\s*\(\s*const\s+std::filesystem::filesystem_error", "C++ catch filesystem_error", "Good: catching filesystem_error", Severity.INFO),
            (r"catch\s*\(\s*const\s+std::format_error", "C++ catch format_error", "Good: catching format_error", Severity.INFO),
            (r"catch\s*\(\s*const\s+std::out_of_range", "C++ catch out_of_range", "Good: catching out_of_range", Severity.INFO),
            (r"catch\s*\(\s*const\s+std::overflow_error", "C++ catch overflow_error", "Good: catching overflow_error", Severity.INFO),
            (r"catch\s*\(\s*const\s+std::underflow_error", "C++ catch underflow_error", "Good: catching underflow_error", Severity.INFO),
            (r"catch\s*\(\s*const\s+std::range_error", "C++ catch range_error", "Good: catching range_error", Severity.INFO),
            (r"catch\s*\(\s*const\s+std::domain_error", "C++ catch domain_error", "Good: catching domain_error", Severity.INFO),
            (r"catch\s*\(\s*const\s+std::length_error", "C++ catch length_error", "Good: catching length_error", Severity.INFO),
            (r"catch\s*\(\s*const\s+std::bad_alloc", "C++ catch bad_alloc", "Good: catching bad_alloc", Severity.INFO),
            (r"catch\s*\(\s*const\s+std::bad_cast", "C++ catch bad_cast", "Good: catching bad_cast", Severity.INFO),
            (r"catch\s*\(\s*const\s+std::bad_typeid", "C++ catch bad_typeid", "Good: catching bad_typeid", Severity.INFO),
            (r"catch\s*\(\s*const\s+std::bad_exception", "C++ catch bad_exception", "Good: catching bad_exception", Severity.INFO),
            (r"catch\s*\(\s*const\s+std::bad_function_call", "C++ catch bad_function_call", "Good: catching bad_function_call", Severity.INFO),
            (r"catch\s*\(\s*const\s+std::bad_weak_ptr", "C++ catch bad_weak_ptr", "Good: catching bad_weak_ptr", Severity.INFO),
            (r"catch\s*\(\s*const\s+std::system_error", "C++ catch system_error", "Good: catching system_error", Severity.INFO),
            (r"catch\s*\(\s*const\s+std::ios_base::failure", "C++ catch ios_base::failure", "Good: catching ios_base::failure", Severity.INFO),
            (r"catch\s*\(\s*const\s+std::future_error", "C++ catch future_error", "Good: catching future_error", Severity.INFO),
            (r"catch\s*\(\s*const\s+std::regex_error", "C++ catch regex_error", "Good: catching regex_error", Severity.INFO),
            (r"catch\s*\(\s*const\s+std::filesystem::filesystem_error", "C++ catch filesystem_error", "Good: catching filesystem_error", Severity.INFO),
            (r"catch\s*\(\s*const\s+std::format_error", "C++ catch format_error", "Good: catching format_error", Severity.INFO),
        ]
        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith('#') or stripped.startswith('//'):
                continue
            for pattern, message, severity in patterns:
                if re.search(pattern, line):
                    issues.append(self._create_issue(
                        file_path=file_path, line=line_num, message=message,
                        suggestion=message, severity=severity, code_snippet=stripped,
                    ))
        return issues
