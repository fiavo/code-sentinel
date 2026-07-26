# 🛡️ CodeSentinel

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/)
[![Version](https://img.shields.io/badge/version-0.1.0-orange.svg)](https://github.com/fiavo/code-sentinel)
[![Telegram Bot](https://img.shields.io/badge/Telegram-Bot-26A5E4.svg)](https://t.me/code_sentinelbot)

**AI-Powered Code Review Tool**

Smart code analysis, security scanning, auto-fix, and GitHub PR integration.

---

## 🎮 Live Demo

### Try it now on Telegram!

**🤖 Bot:** [@code_sentinelbot](https://t.me/code_sentinelbot)

**Quick start:**
1. Open [@code_sentinelbot](https://t.me/code_sentinelbot) in Telegram
2. Send `/start`
3. Upload a code file or paste code
4. Use keyboard buttons for quick actions!

**Inline mode:** Type `@code_sentinelbot` in any chat followed by code:
```
@code_sentinelbot password = "secret123"
```

---

## Features

- 🛡️ **Security Analysis** - Detect vulnerabilities and secrets
- ⚡ **Performance Detection** - Find optimization opportunities
- 🎨 **Style Checking** - Enforce code standards
- 🧠 **Complexity Analysis** - Measure code complexity
- 🤖 **AI-Powered** - Deep understanding with OpenAI
- 🔧 **Auto-Fix** - Automatically fix common issues
- 🐙 **GitHub Integration** - PR review automation
- 📱 **Telegram Bot** - Review code from Telegram
- ⌨️ **Custom Keyboard** - Quick action buttons
- 📝 **Inline Mode** - Review code in any chat

---

## Installation

```bash
# Basic installation
pip install -e .

# With Telegram bot support
pip install -e ".[telegram]"

# With all optional dependencies
pip install -e ".[all]"
```

---

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

---

## 📱 Telegram Bot

### Commands

| Command | Description |
|---------|-------------|
| `/start` | Welcome message |
| `/help` | Show help |
| `/review` | Review code |
| `/analyze` | Quick analysis |
| `/fix` | Auto-fix issues |
| `/stats` | Code statistics |

### Keyboard Buttons

| Button | Description |
|--------|-------------|
| 🔍 Review | Review code |
| 🔧 Fix | Auto-fix issues |
| 📊 Stats | Code statistics |
| 📈 Analyze | Quick analysis |
| 📎 Upload | Upload instructions |
| ❓ Help | Help message |

### Inline Mode

Use in any chat:
```
@code_sentinelbot print("hello")
```

### How to Use

**Option 1: Code Block**
```
/review
```python
def hello():
    password = "secret123"
```
```

**Option 2: File Upload**
1. Upload a code file (.py, .js, .ts, etc.)
2. Use keyboard buttons or type `/review`

**Option 3: Inline**
Just type `@code_sentinelbot` + code in any chat

---

## GitHub Integration

```python
from code_reviewer.github import GitHubPRReviewer

async def review_pr():
    reviewer = GitHubPRReviewer(token="ghp_...")
    result = await reviewer.review_pr("owner/repo", 123)
    await reviewer.post_review("owner/repo", 123, result)
```

---

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

---

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

---

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

---

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

---

## License

MIT License - see [LICENSE](LICENSE) for details.

---

## 🙏 Support

If you find this project useful, please give it a ⭐ on GitHub!

**Try the bot:** [@code_sentinelbot](https://t.me/code_sentinelbot)
