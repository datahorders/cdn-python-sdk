# DataHorders CDN Python SDK

## Project Overview

Python SDK for the DataHorders CDN API. Published to PyPI as `datahorders-cdn`.

**PyPI**: https://pypi.org/project/datahorders-cdn/
**GitHub**: https://github.com/datahorders/cdn-python-sdk

## Installation

```bash
pip install datahorders-cdn
```

## Development Setup

```bash
git clone https://github.com/datahorders/cdn-python-sdk.git
cd cdn-python-sdk
pip install -e ".[dev]"
```

## Commands

```bash
# Run tests
pytest

# Run tests with coverage
pytest --cov=datahorders_cdn --cov-report=term-missing

# Type checking
mypy datahorders_cdn

# Linting
ruff check .

# Format code
ruff format .
```

## CI/CD

GitHub Actions workflows in `.github/workflows/`:

- **test.yml**: Runs on push to main and PRs
  - Lint (ruff check + format)
  - Type check (mypy)
  - Tests across Python 3.9, 3.10, 3.11, 3.12, 3.13

- **publish.yml**: Runs on tag push (`v*`) or GitHub release
  - Runs full test suite
  - Builds wheel and source distribution
  - Publishes to PyPI using OIDC trusted publishing (no tokens needed)

## Releasing a New Version

1. Update version in `pyproject.toml`
2. Commit the change
3. Create and push a tag:
   ```bash
   git tag v1.0.1
   git push origin v1.0.1
   ```
4. The publish workflow automatically builds and uploads to PyPI

## PyPI Trusted Publishing

Configured at https://pypi.org/manage/project/datahorders-cdn/settings/publishing/

Settings:
- Owner: `datahorders`
- Repository: `cdn-python-sdk`
- Workflow: `publish.yml`
- Environment: `pypi`

## Code Style Notes

### Python 3.9 Compatibility

- Use `Optional[X]` instead of `X | None` in `models.py` (Pydantic evaluates types at runtime)
- Use `from __future__ import annotations` in other files for deferred evaluation
- The `builtins._list` alias is used in resource classes where the `list` method shadows the builtin

### Type Checking

- Strict mypy configuration enabled
- Use `cast()` from typing when returning values from dict.get() that need specific types

## Project Structure

```
cdn-python-sdk/
├── datahorders_cdn/           # Main package
│   ├── __init__.py           # Public API exports
│   ├── client.py             # DataHordersCDN client class
│   ├── exceptions.py         # Custom exception hierarchy
│   ├── models.py             # Pydantic data models
│   └── resources/            # API resource modules
│       ├── analytics.py
│       ├── certificates.py
│       ├── domains.py
│       ├── health_checks.py
│       ├── upstream_servers.py
│       ├── waf.py
│       └── zones.py
├── tests/                    # Test suite (27 tests)
│   ├── conftest.py          # Shared fixtures
│   └── test_client.py       # Client tests
├── .github/workflows/        # CI/CD
│   ├── test.yml
│   └── publish.yml
└── pyproject.toml           # Package configuration
```

## Initial Release (v1.0.0) - December 31, 2025

Successfully published to PyPI with:
- Full API coverage for domains, zones, certificates, WAF, health checks, analytics
- Both sync and async support
- Type hints throughout
- Pydantic models for validation
- 27 tests passing across Python 3.9-3.13
