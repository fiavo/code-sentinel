# AI Code Reviewer

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/)
[![Version](https://img.shields.io/badge/version-0.1.0-orange.svg)](https://github.com/fiavo/ai-code-reviewer)

🔍 **AI-Powered Code Review Tool**

A professional-grade code reviewer that uses AI to analyze code quality, security, performance, and style. Supports multiple languages and integrates with GitHub for PR reviews.

## Features

### 🛡️ Security Analysis
- Hardcoded secrets detection
- SQL injection vulnerabilities
- Unsafe eval/exec usage
- Weak hashing algorithms
- Debug mode in production

### ⚡ Performance Detection
- N+1 query patterns
- String concatenation in loops
- Global variable usage
- Bare except clauses

### 🎨 Style Checking
- Line length limits
- Trailing whitespace
- TODO/FIXME comments
- Code formatting

### 🧠 Complexity Analysis
- Deep nesting detection
- Function length limits
- Code complexity metrics

### 🤖 AI-Powered Analysis
- Deep code understanding
- Context-aware suggestions
- Best practice recommendations
- Architecture analysis

### 🔧 Auto-Fix
- Automatic issue fixing
- Diff generation
- Dry-run mode
- Safe refactoring

### 🐙 GitHub Integration
- PR review automation
- Inline comments
- Review summaries
- Status checks

## Installation

```bash
# Install from source
git clone https://github.com/fiavo/ai-code-reviewer.git
cd ai-code-reviewer
pip install -e .

# Or install with dev dependencies
pip install -e ".[dev]"
```

## Usage

### CLI Commands

```bash
# Review a file
code-reviewer review src/main.py

# Review a directory
code-reviewer review ./src

# Review with AI analysis
code-reviewer review src/ --ai

# Auto-fix issues
code-reviewer review src/ --fix

# Show diff without applying
code-reviewer review src/ --fix --dry-run

# Analyze code string
code-reviewer analyze "print('hello')" --language python

# Show statistics
code-reviewer stats ./src
```

### Options

```
--ai              Use AI for deeper analysis
--provider        AI provider (openai, local)
--model           AI model (gpt-4, gpt-3.5-turbo)
--fix             Auto-fix issues
--dry-run         Show fixes without applying
--verbose, -v     Verbose output
--output, -o      Save results to file
```

### Python API

```python
from code_reviewer import CodeAnalyzer

# Analyze a file
analyzer = CodeAnalyzer()
result = analyzer.analyze_path("src/main.py")

print(f"Score: {result.score}")
print(f"Issues: {len(result.issues)}")

# Analyze code string
result = analyzer.analyze_code(
    code="eval(user_input)",
    language="python"
)

# Custom rules
from code_reviewer.core.rules import BaseRule

class MyRule(BaseRule):
    name = "my-rule"
    description = "My custom rule"
    category = IssueCategory.BEST_PRACTICE
    severity = Severity.WARNING
    
    def check(self, file_path: str, content: str) -> list[CodeIssue]:
        # Your rule logic here
        return []

analyzer.add_rule(MyRule())
```

### GitHub Integration

```python
import asyncio
from code_reviewer.github import GitHubPRReviewer

async def review_pr():
    reviewer = GitHubPRReviewer(token="ghp_...")
    
    # Review PR
    result = await reviewer.review_pr("owner/repo", 123)
    
    # Post review comment
    await reviewer.post_review("owner/repo", 123, result)

asyncio.run(review_pr())
```

## Supported Languages

- Python
- JavaScript/TypeScript
- Java
- Go
- Rust
- C/C++
- C#
- Ruby
- PHP
- Swift
- Kotlin
- And more...

## Rules

### Built-in Rules

| Rule | Category | Description |
|------|----------|-------------|
| `security` | Security | Detects security vulnerabilities |
| `performance` | Performance | Finds performance issues |
| `style` | Style | Checks code style |
| `complexity` | Complexity | Analyzes code complexity |

### Custom Rules

Create custom rules by extending `BaseRule`:

```python
from code_reviewer.core.rules import BaseRule
from code_reviewer.core.models import CodeIssue, Severity, IssueCategory

class NoPrintRule(BaseRule):
    @property
    def name(self) -> str:
        return "no-print"
    
    @property
    def description(self) -> str:
        return "Disallow print statements"
    
    @property
    def category(self) -> IssueCategory:
        return IssueCategory.BEST_PRACTICE
    
    @property
    def severity(self) -> Severity:
        return Severity.WARNING
    
    def check(self, file_path: str, content: str) -> list[CodeIssue]:
        issues = []
        for line_num, line in enumerate(content.splitlines(), 1):
            if "print(" in line:
                issues.append(self._create_issue(
                    file_path=file_path,
                    line=line_num,
                    message="Print statement found",
                    suggestion="Use logging instead",
                ))
        return issues
```

## Configuration

### Environment Variables

```bash
# AI Provider
export OPENAI_API_KEY="sk-..."

# GitHub Integration
export GITHUB_TOKEN="ghp_..."
```

### Config File

Create `.code-reviewer.toml`:

```toml
[rules]
max_line_length = 120
max_function_length = 50

[ai]
provider = "openai"
model = "gpt-4"
temperature = 0.3

[github]
auto_comment = true
```

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# Run linting
ruff check src/
ruff format src/

# Run type checking
mypy src/
```

## License

MIT License - see [LICENSE](LICENSE) for details.
