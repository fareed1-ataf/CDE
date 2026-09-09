# Contributing to Cyber Data Engine

Thank you for your interest in contributing! This document provides everything you need to get started.

---

## Table of Contents

1. [Development Setup](#development-setup)
2. [Running Tests](#running-tests)
3. [Branch Naming](#branch-naming)
4. [Pull Request Checklist](#pull-request-checklist)
5. [Code Style](#code-style)
6. [Reporting Bugs](#reporting-bugs)

---

## Development Setup

```bash
# 1. Clone the repository
git clone https://github.com/your-org/cyber-data-engine.git
cd cyber-data-engine

# 2. Create a virtual environment
python -m venv .venv
source .venv/bin/activate       # Linux / macOS
.venv\Scripts\activate          # Windows

# 3. Install all dependencies
pip install -r requirements.txt
pip install -e .                # install shared_lib as editable package

# 4. Configure providers (NEVER commit real keys)
cp config/providers.json.example config/providers.json
# Edit config/providers.json and set ${ENV_VAR} values in your environment

# 5. Start the server
uvicorn backend.main:app --host 127.0.0.1 --port 59919 --reload
```

Navigate to `http://localhost:59919` to verify the UI loads correctly.

---

## Running Tests

```bash
# Run the full test suite
pytest tests/ -v

# Run a specific test file
pytest tests/test_classifier.py -v

# Run with coverage report
pytest tests/ --cov=backend --cov=shared_lib --cov-report=term-missing
```

All tests must pass before submitting a pull request.

---

## Branch Naming

Use the following prefixes:

| Prefix    | Purpose                                   | Example                          |
|-----------|-------------------------------------------|----------------------------------|
| `fix/`    | Bug fixes                                 | `fix/dedup-false-positive`       |
| `feat/`   | New features                              | `feat/parquet-file-support`      |
| `docs/`   | Documentation updates                     | `docs/update-api-reference`      |
| `refactor/` | Code refactoring without behaviour change | `refactor/streaming-export`    |
| `test/`   | Adding or updating tests                  | `test/validator-grounding`       |

---

## Pull Request Checklist

Before opening a pull request, verify all items below:

- [ ] All existing tests pass (`pytest tests/ -v`)
- [ ] New code has corresponding unit tests
- [ ] No hardcoded API keys or secrets anywhere in the diff
- [ ] `config/providers.json` is **not** included in the commit
- [ ] All public functions have docstrings
- [ ] Type hints are present on all new function signatures
- [ ] No `import` statements inside function bodies
- [ ] The `Known Limitations` section of relevant modules is updated if applicable

---

## Code Style

- **Python:** Follow [PEP 8](https://peps.python.org/pep-0008/). Line length limit: 120 characters.
- **Type hints:** Required for all public functions.
- **Docstrings:** Use plain-text docstrings for all public functions and classes.
- **No bare `except:`** — always catch a specific exception type.
- **Imports:** All imports at the top of the file. No `import` inside function bodies.

---

## Reporting Bugs

Open a GitHub Issue with the following template:

```
**Bug Description:**
A clear, concise description of the bug.

**Steps to Reproduce:**
1. Upload file X
2. Set training goal to Y
3. Observe Z in logs/engine.log

**Expected Behaviour:**
What should have happened.

**Actual Behaviour:**
What actually happened (include log output if possible).

**Environment:**
- OS: Windows 11 / Ubuntu 22.04
- Python version: 3.11
- Provider: Groq / Ollama / etc.
```

---

## Security Vulnerabilities

Do **not** open a public issue for security vulnerabilities. See [SECURITY.md](SECURITY.md) for the responsible disclosure process.
