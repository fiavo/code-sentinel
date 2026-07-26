# Contributing to CodeSentinel

Thank you for your interest in contributing to CodeSentinel! 🎉

## How to Contribute

### 1. Fork the Repository

```bash
# Fork on GitHub, then clone
git clone https://github.com/YOUR_USERNAME/code-sentinel.git
cd code-sentinel
```

### 2. Set Up Development Environment

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or
venv\Scripts\activate  # Windows

# Install dependencies
pip install -e ".[all]"

# Install development dependencies
pip install pytest ruff black
```

### 3. Create a Branch

```bash
git checkout -b feature/your-feature-name
```

### 4. Make Your Changes

- Write clean, documented code
- Follow the existing code style
- Add tests for new features
- Update documentation if needed

### 5. Run Tests

```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=code_reviewer
```

### 6. Lint Your Code

```bash
# Check for linting issues
ruff check src/

# Format your code
ruff format src/
```

### 7. Commit Your Changes

```bash
git add .
git commit -m "feat: add new feature"
```

Use [Conventional Commits](https://www.conventionalcommits.org/):
- `feat:` for new features
- `fix:` for bug fixes
- `docs:` for documentation
- `style:` for formatting
- `refactor:` for code refactoring
- `test:` for adding tests
- `chore:` for maintenance

### 8. Push and Create PR

```bash
git push origin feature/your-feature-name
```

Then create a Pull Request on GitHub.

## Development Guidelines

### Code Style

- Use Python 3.11+ features
- Follow PEP 8
- Use type hints
- Write docstrings for all public functions

### Testing

- Write tests for all new features
- Maintain test coverage above 80%
- Test both success and error cases

### Documentation

- Update README if adding new features
- Add docstrings to new functions
- Update CHANGELOG.md

## Reporting Issues

When reporting issues, please include:

1. Python version
2. Operating system
3. Steps to reproduce
4. Expected behavior
5. Actual behavior
6. Error messages (if any)

## Code of Conduct

- Be respectful and inclusive
- Focus on constructive feedback
- Help others learn and grow
- Celebrate contributions of all sizes

## Questions?

Feel free to open an issue for any questions!

---

Thank you for contributing! 🚀
