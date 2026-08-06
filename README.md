<div align="center">

# 🛡️ CodeSentinel

**AI-Powered Code Review Bot for Telegram**

[![Python](https://img.shields.io/badge/Python-3.7+-blue?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Telegram](https://img.shields.io/badge/Telegram-Bot-26A5E4?style=for-the-badge&logo=telegram&logoColor=white)](https://t.me/code_sentinelbot)
[![PyPI](https://img.shields.io/badge/PyPI-codesentinel--bot-green?style=for-the-badge&logo=pypi&logoColor=white)](https://pypi.org/project/codesentinel-bot/)
[![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)](LICENSE)

</div>

---

## ✨ Features

- 🤖 **AI-Powered Review** — Smart code analysis using advanced AI
- 🔒 **Security Scanning** — Detect vulnerabilities and security issues
- 🔧 **Auto-Fix** — Automatically fix common code problems
- 🌐 **Inline Queries** — Review code from any Telegram chat
- ⌨️ **Custom Keyboard** — Easy navigation with built-in buttons
- 🇮🇷 **Persian Support** — Code explanations in Farsi
- 💻 **Multi-Language** — Python, C, JavaScript, Java, Go, Rust

---

## 🚀 Quick Start

### 1. Install via pip

```bash
pip install codesentinel-bot
```

### 2. Set up Telegram Bot

1. Talk to [@BotFather](https://t.me/BotFather) on Telegram
2. Create a new bot and get the token
3. Set the token as environment variable:

```bash
export TELEGRAM_BOT_TOKEN="your_token_here"
```

### 3. Run the Bot

```bash
python -m codesentinel
```

---

## 📱 Try the Bot

**👉 [@code_sentinelbot](https://t.me/code_sentinelbot)**

Just send any code snippet and get instant review!

---

## 🧰 Supported Languages

| Language | Support |
|----------|---------|
| Python | ✅ Full |
| C | ✅ Full |
| JavaScript | ✅ Full |
| Java | ✅ Full |
| Go | ✅ Full |
| Rust | ✅ Full |

---

## 🔍 What It Checks

### Code Quality
- ✅ Code style and formatting
- ✅ Naming conventions
- ✅ Code complexity
- ✅ Documentation

### Security
- ✅ Vulnerability detection
- ✅ Security best practices
- ✅ Dependency issues
- ✅ Input validation

### Performance
- ✅ Optimization suggestions
- ✅ Memory usage
- ✅ Algorithm efficiency
- ✅ Resource management

---

## 📖 Usage Examples

### Basic Review
```
/send_code
def add(a, b):
    return a + b
```

### With Language
```
/python
def fibonacci(n):
    if n <= 1:
        return n
    return fibonacci(n-1) + fibonacci(n-2)
```

### Security Scan
```
/scan
import os
os.system(input("Enter command: "))
```

---

## 🛠️ Development

### Prerequisites

- Python 3.7+
- pip

### Installation

```bash
# Clone the repository
git clone https://github.com/fiavo/code-sentinel.git
cd code-sentinel

# Install dependencies
pip install -e .

# Set environment variable
export TELEGRAM_BOT_TOKEN="your_token"

# Run
python -m codesentinel
```

### Project Structure

```
code-sentinel/
├── src/
│   └── code_sentinel/
│       ├── __init__.py
│       ├── __main__.py
│       ├── telegram/
│       │   └── bot.py
│       └── analyzer/
│           └── code_analyzer.py
├── pyproject.toml
└── README.md
```

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing`)
5. Open a Pull Request

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- Thanks to all contributors
- Built with ❤️ by [fiavo](https://github.com/fiavo)

---

<div align="center">

**🛡️ CodeSentinel — Smart Code Review, Powered by AI**

[![Star on GitHub](https://img.shields.io/github/stars/fiavo/code-sentinel?style=social)](https://github.com/fiavo/code-sentinel)
[![Follow on Twitter](https://img.shields.io/twitter/follow/fiavo_dev?style=social)](https://twitter.com/fiavo_dev)

</div>
