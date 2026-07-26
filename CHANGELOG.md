# Changelog

All notable changes to CodeSentinel will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-01-27

### 🎉 Initial Release

#### ✨ Features

**Core Analysis**
- 🔍 Code analysis with scoring system (0-100)
- 🛡️ Security vulnerability detection
- ⚡ Performance issue identification
- 🎨 Code style checking
- 🧠 Complexity analysis

**Auto-Fix**
- 🔧 Automatic code fixes
- 📝 Diff display for changes
- ✅ One-click fix application

**Telegram Bot**
- 📱 Full Telegram bot integration
- ⌨️ Custom keyboard buttons
- 📝 Inline mode support
- 📄 File upload support
- 💾 Remember last uploaded file

**Code Generation**
- ✍️ Generate code from Persian descriptions
- 🌍 Multi-language support (Python, JavaScript, Java, C++, Go, Rust)
- 📖 Code explanation
- 🔄 Code translation

**CLI Interface**
- 💻 Rich terminal output
- 📊 Progress indicators
- 🎨 Colored output

**GitHub Integration**
- 🐙 PR review automation
- 📝 Inline comments
- 📊 Review summaries

#### 🌍 Supported Languages

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

#### 📦 Installation

```bash
# Basic installation
pip install code-sentinel

# With Telegram bot support
pip install code-sentinel[telegram]

# With all features
pip install code-sentinel[all]
```

#### 🚀 Quick Start

```bash
# Review a file
code-sentinel review src/main.py

# Run the Telegram bot
export TELEGRAM_BOT_TOKEN="your-token"
sentinel-bot
```

---

## [Unreleased]

### Planned Features

- 🌐 Web Dashboard
- 📝 VS Code Extension
- ⚡ GitHub Action
- 🤖 AI-powered analysis (OpenAI integration)
- 📊 Analytics dashboard
- 👥 Team collaboration features

---

## Version History

| Version | Date | Description |
|---------|------|-------------|
| 1.0.0 | 2025-01-27 | Initial release |
