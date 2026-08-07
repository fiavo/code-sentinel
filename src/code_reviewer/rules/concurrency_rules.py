"""
Comprehensive concurrency and async rules for code analysis.
Covers threading, async/await, race conditions, and deadlocks.
"""

import re
from typing import Optional

from ..core.models import CodeIssue, Severity, IssueCategory
from ..core.rules import BaseRule


class ThreadingRules(BaseRule):
    """Threading and multiprocessing issues."""

    @property
    def name(self) -> str:
        return "threading"

    @property
    def description(self) -> str:
        return "Threading and multiprocessing issue detection"

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
            # Race conditions
            (r'(?:self\.)?\w+\s*=\s*\w+\s*\+\s*1\s*$', "Non-atomic increment - race condition",
             "Use threading.Lock() or atomic operations", Severity.WARNING),
            (r'(?:self\.)?\w+\s*\+=\s*\d+\s*$', "Non-atomic increment - race condition",
             "Use threading.Lock() or atomic operations", Severity.WARNING),
            (r'(?:self\.)?\w+\s*-=\s*\d+\s*$', "Non-atomic decrement - race condition",
             "Use threading.Lock() or atomic operations", Severity.WARNING),
            (r'global\s+\w+', "Global variable in threaded code",
             "Use thread-local storage or synchronization", Severity.WARNING),

            # Missing locks
            (r'thread\.start\s*\(\s*\)', "Thread started without synchronization",
             "Ensure shared state is protected", Severity.INFO),
            (r'Thread\s*\(\s*target\s*=', "Thread created without synchronization",
             "Ensure shared state is protected", Severity.INFO),
            (r'(?:threading|multiprocessing)\.Thread', "Thread created",
             "Ensure shared state is synchronized", Severity.INFO),

            # Lock issues
            (r'\.acquire\s*\(\s*\)', "Lock acquired without timeout",
             "Use timeout to prevent deadlocks", Severity.INFO),
            (r'\.release\s*\(\s*\)', "Lock released manually",
             "Use context manager (with lock:) instead", Severity.INFO),
            (r'Lock\s*\(\s*\)', "Lock created",
             "Consider using RLock for reentrant access", Severity.INFO),

            # Deadlock patterns
            (r'(?:acquire|lock)\s*\([^)]*\).*\n.*(?:acquire|lock)\s*\(', "Nested lock acquisition",
             "Risk of deadlock; use consistent lock ordering", Severity.WARNING),
            (r'with\s+\w+.*:\s*\n\s*with\s+\w+.*:', "Nested context managers with locks",
             "Risk of deadlock; ensure consistent lock ordering", Severity.INFO),

            # Thread safety
            (r'(?:dict|list|set)\s*\(\s*\)\s*$', "Shared mutable object in threaded code",
             "Use thread-safe alternatives (Queue, deque)", Severity.INFO),
            (r'(?:queue\.Queue|collections\.deque)', "Thread-safe data structure used",
             "Good: using thread-safe data structure", Severity.INFO),

            # Daemon threads
            (r'\.daemon\s*=\s*True', "Daemon thread",
             "Daemon threads are killed on exit; ensure cleanup", Severity.INFO),
            (r'daemon\s*=\s*True', "Daemon thread",
             "Daemon threads are killed on exit; ensure cleanup", Severity.INFO),
        ]

        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith('#') or stripped.startswith('//'):
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


class AsyncAwaitRules(BaseRule):
    """Async/await pattern detection."""

    @property
    def name(self) -> str:
        return "async_await"

    @property
    def description(self) -> str:
        return "Async/await pattern detection"

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
            # Missing await
            (r'async\s+def\s+\w+.*:\s*\n.*(?<!await\s)\b(?:requests\.|http\.|fetch\()', "Async function without await",
             "Add await for async operations", Severity.WARNING),
            (r'(?:const|let|var)\s+\w+\s*=\s*(?:fetch|axios)\s*\(', "Async operation without await",
             "Add await before async operation", Severity.WARNING),
            (r'async\s+function\s+\w+.*\{[^}]*(?:fetch|axios)[^}]*\}', "Async function without await (JS)",
             "Add await before async operations", Severity.WARNING),

            # Async in loop
            (r'for\s+\w+\s+in.*:\s*\n\s*await\s+', "Sequential await in loop",
             "Use asyncio.gather() or Promise.all() for parallel execution", Severity.WARNING),
            (r'for\s+\w+\s+in.*:\s*\n\s*(?:\s+.*\n)*?\s*await\s+', "Sequential await in loop",
             "Use asyncio.gather() or Promise.all() for parallel execution", Severity.WARNING),

            # Blocking in async
            (r'async\s+def\s+\w+.*:\s*\n.*(?:time\.sleep|os\.system)', "Blocking call in async function",
             "Use asyncio.sleep() or async alternatives", Severity.WARNING),
            (r'async\s+function.*\{[^}]*(?:setTimeout|setInterval)', "Blocking timer in async (JS)",
             "Use Promise-based alternatives", Severity.INFO),
            (r'async\s+function.*\{[^}]*\.then\s*\(', "Using .then() in async function",
             "Use await instead of .then()", Severity.INFO),

            # Missing error handling in async
            (r'await\s+\w+\s*\(', "Await without try/except",
             "Wrap await in try/except for error handling", Severity.INFO),
            (r'await\s+\w+\.json\s*\(\s*\)', "await response.json() without error handling",
             "Add try/except for JSON parsing errors", Severity.INFO),

            # Async context managers
            (r'async\s+with\s+\w+\s+as\s+\w+:', "Async context manager",
             "Good: using async context manager", Severity.INFO),
            (r'with\s+\w+.*(?:open|connect)', "Sync context manager in async code",
             "Consider using async context manager (aiofiles, aiohttp)", Severity.INFO),

            # Race conditions in async
            (r'(?:self\.)?\w+\s*=\s*await\s+', "Async state mutation",
             "Ensure atomic state updates with locks", Severity.INFO),
            (r'asyncio\.create_task\s*\(', "Task created without tracking",
             "Store task reference to prevent GC", Severity.INFO),

            # Generator issues
            (r'async\s+def\s+\w+.*yield', "Async generator",
             "Ensure proper async iteration with 'async for'", Severity.INFO),
            (r'for\s+\w+\s+in\s+.*(?:async|await)', "Sync loop over async generator",
             "Use 'async for' to iterate async generators", Severity.WARNING),
        ]

        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith('#') or stripped.startswith('//'):
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


class ProcessPoolRules(BaseRule):
    """Multiprocessing and process pool issues."""

    @property
    def name(self) -> str:
        return "process_pool"

    @property
    def description(self) -> str:
        return "Multiprocessing and process pool detection"

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
            # Pickling issues
            (r'(?:Pool|Process)\s*\(\s*\)', "Default pool/process count",
             "Consider specifying pool size explicitly", Severity.INFO),
            (r'map\s*\(\s*\w+\s*,', "Using map() in multiprocessing",
             "Consider using map() with chunksize for large datasets", Severity.INFO),
            (r'(?:Pool|ProcessPool)\s*\(\s*\)', "Pool created without size limit",
             "Limit pool size to prevent resource exhaustion", Severity.INFO),

            # Shared state
            (r'(?:Value|Array|Manager)\s*\(', "Shared memory object",
             "Ensure proper synchronization when accessing shared state", Severity.INFO),
            (r'multiprocessing\.Queue\s*\(\s*\)', "Multiprocessing Queue created",
             "Ensure proper cleanup and draining", Severity.INFO),

            # Process leak
            (r'(?:Pool|Process)\s*\([^)]*\)\s*\.apply', "Process task without timeout",
             "Add timeout to prevent hanging", Severity.INFO),
            (r'\.join\s*\(\s*\)', "Process join without timeout",
             "Add timeout to prevent hanging", Severity.INFO),
            (r'\.terminate\s*\(\s*\)', "Process terminated forcefully",
             "Use .close() and .join() for graceful shutdown", Severity.INFO),

            # Serialization
            (r'(?:pickle|marshal)\.(?:dump|load)\s*\(', "Untrusted deserialization",
             "Use safe serialization formats (JSON, MessagePack)", Severity.WARNING),
            (r'yaml\.load\s*\(\s*[^)]*\)', "YAML load without safe_load",
             "Use yaml.safe_load() to prevent code execution", Severity.WARNING),
            (r'yaml\.load\s*\(\s*[^)]*,\s*Loader\s*=\s*yaml\.Loader', "YAML load with unsafe Loader",
             "Use yaml.safe_load() instead", Severity.WARNING),
        ]

        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith('#') or stripped.startswith('//'):
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
