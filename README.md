# 🛡️ CodeSentinel

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/)
[![Version](https://img.shields.io/badge/version-0.1.0-orange.svg)](https://github.com/fiavo/code-sentinel)

**AI-Powered Code Review Tool**

Smart code analysis, security scanning, auto-fix, and GitHub PR integration.

## Features

- 🛡️ **Security Analysis** - Detect vulnerabilities and secrets
- ⚡ **Performance Detection** - Find optimization opportunities
- 🎨 **Style Checking** - Enforce code standards
- 🧠 **Complexity Analysis** - Measure code complexity
- 🤖 **AI-Powered** - Deep understanding with OpenAI
- 🔧 **Auto-Fix** - Automatically fix common issues
- 🐙 **GitHub Integration** - PR review automation
- 📱 **Telegram Bot** - Review code from Telegram

## Installation

```bash
# Basic installation
pip install -e .

# With Telegram bot support
pip install -e ".[telegram]"

# With all optional dependencies
pip install -e ".[all]"
```

## Usage

### CLI

```bash
# Review a file
code-sentinel review src/main.py

# Review with AI
code-sentinel review src/ --ai

# Auto-fix issues
code-sentinel review src/ --fix

# Analyze code string
code-sentinel analyze "print('hello')"

# Show statistics
code-sentinel stats ./src
```

### Python API

```python
from code_reviewer import CodeAnalyzer

analyzer = CodeAnalyzer()
result = analyzer.analyze_code('password = "secret123"', "python")

print(f"Score: {result.score}")
print(f"Issues: {len(result.issues)}")
```

## 📱 Telegram Bot

### Setup

1. Create a bot with [@BotFather](https://t.me/BotFather)
2. Get your bot token
3. Set the token:

```bash
export TELEGRAM_BOT_TOKEN="your-bot-token"
```

### Run the Bot

```bash
# Method 1: Using the entry point
sentinel-bot

# Method 2: Using Python module
python -m code_reviewer.telegram.bot

# Method 3: With token argument
python -m code_reviewer.telegram.bot --token "your-token"
```

### Bot Commands

| Command | Description |
|---------|-------------|
| `/start` | Show welcome message |
| `/help` | Show help and commands |
| `/review` | Review code or file |
| `/analyze` | Quick code analysis |
| `/fix` | Auto-fix issues |
| `/stats` | Code statistics |

### How to Use

**Option 1: Code Block**
```
/review
```python
def hello():
    password = "secret123"
    eval(user_input)
```
```

**Option 2: File Upload**
1. Upload a code file (.py, .js, .ts, etc.)
2. Type `/review`

**Option 3: Inline Code**
Just paste code and add `/analyze`

### Bot Features

- ✅ Supports 10+ programming languages
- ✅ Analyzes code blocks automatically
- ✅ File upload support
- ✅ Auto-fix with diff display
- ✅ Works in groups and private chats
- ✅ Detailed statistics

## GitHub Integration

```python
from code_reviewer.github import GitHubPRReviewer

async def review_pr():
    reviewer = GitHubPRReviewer(token="ghp_...")
    result = await reviewer.review_pr("owner/repo", 123)
    await reviewer.post_review("owner/repo", 123, result)
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

## Rules

### Built-in Rules

| Rule | Category | Description |
|------|----------|-------------|
| `security` | Security | Detects security vulnerabilities |
| `performance` | Performance | Finds performance issues |
| `style` | Style | Checks code style |
| `complexity` | Complexity | Analyzes code complexity |

### Custom Rules

```python
from code_reviewer.core.rules import BaseRule
from code_reviewer.core.models import CodeIssue, Severity, IssueCategory

class MyRule(BaseRule):
    @property
    def name(self) -> str:
        return "my-rule"
    
    @property
    def description(self) -> str:
        return "My custom rule"
    
    @property
    def category(self) -> IssueCategory:
        return IssueCategory.BEST_PRACTICE
    
    @property
    def severity(self) -> Severity:
        return Severity.WARNING
    
    def check(self, file_path: str, content: str) -> list[CodeIssue]:
        issues = []
        for line_num, line in enumerate(content.splitlines(), 1):
            if "TODO" in line:
                issues.append(self._create_issue(
                    file_path=file_path,
                    line=line_num,
                    message="TODO found",
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

# Telegram Bot
export TELEGRAM_BOT_TOKEN="your-bot-token"
```

## Development

```bash
# Install dev dependencies
pip install -e ".[all]"

# Run tests
pytest tests/ -v

# Run linting
ruff check src/
ruff format src/
```

## License

MIT License - see [LICENSE](LICENSE) for details.
