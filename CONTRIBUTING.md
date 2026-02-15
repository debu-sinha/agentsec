# Contributing to agentsec

Thanks for your interest in contributing to agentsec. This guide covers everything you need to get started.

## Development Setup

```bash
# Clone the repo
git clone https://github.com/debu-sinha/agentsec.git
cd agentsec

# Create a virtual environment
python -m venv .venv
source .venv/bin/activate  # or .venv\Scripts\activate on Windows

# Install in editable mode with dev dependencies
pip install -e ".[dev]"

# Install pre-commit hooks
pre-commit install
```

## Development Commands

```bash
# Lint
ruff check src/ tests/

# Format
ruff format src/ tests/

# Type check
mypy src/agentsec/ --ignore-missing-imports

# Run all tests
pytest tests/ -v --tb=short

# Run a single test file
pytest tests/unit/test_installation_scanner.py -v

# Run tests matching a pattern
pytest tests/ -k "test_name" -v

# Self-scan
agentsec scan . --fail-on critical
```

## Before Submitting a PR

1. **Run the full check suite** - lint, format, type check, and tests must all pass
2. **Keep changes focused** - one logical change per PR
3. **Add tests** for new behavior
4. **Update docs** if you change user-facing behavior

The CI pipeline runs: lint -> type-check -> test -> self-scan. Your PR must pass all four.

## Writing a New Scanner

Scanners follow a plugin architecture. To add a new scanner:

1. Create a new module in `src/agentsec/scanners/`
2. Extend `BaseScanner` from `src/agentsec/scanners/base.py`
3. Implement the `scan(context: ScanContext) -> list[Finding]` method
4. Register it in `src/agentsec/scanners/registry.py`
5. Map findings to OWASP categories (ASI01-ASI10) defined in `src/agentsec/models/owasp.py`
6. Use check ID naming convention: `<PREFIX>-<NNN>` (e.g., CGW-001, CSK-001, CMCP-001)

See the existing scanners for reference. The `installation.py` scanner is the most comprehensive example.

## Architecture

For a high-level overview of the architecture, see [ADR-0001](docs/adr/ADR-0001-core-architecture.md).

The core flow is: CLI -> Orchestrator -> Scanners -> OWASP Scorer -> Reporter

## Code Style

- Python 3.10+ with type hints on all public functions
- Ruff for linting and formatting (config in `pyproject.toml`)
- Mypy strict mode for type checking
- Pydantic for data models
- Line length: 100 characters

## Commit Messages

Write commit messages in plain English, imperative mood:
- "Add new MCP permission scanner"
- "Fix false positive in credential detection"
- "Update OWASP scoring weights"

## Reporting Issues

Use GitHub Issues for bug reports and feature requests. For security vulnerabilities, see [SECURITY.md](SECURITY.md).
