# Contributing to acidbase

Thank you for your interest in contributing!

## Getting Started

1. Fork the repository
2. Clone your fork locally
3. Set up the development environment (see README.md)
4. Create a feature branch

## Development Process

### Before Starting
- Check existing issues and PRs to avoid duplicates
- For major changes, open an issue first to discuss

### Code Standards
- Lint and format with ruff (`uv run ruff check .` and `uv run ruff format --check .`)
- Line length: 120 characters
- Use type hints for public functions
- Document all functions with docstrings
- Maintain 80% test coverage

### Testing
- Write tests for new features
- Ensure all tests pass: `uv run pytest`
- Check coverage: `uv run pytest --cov=src`

## Submission Guidelines

### Pull Request Process
1. Update documentation for any API changes
2. Add tests for new functionality
3. Ensure CI/CD checks pass
4. Request review from maintainers

### Commit Messages
Use conventional commits format:
- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation changes
- `test:` Test additions/changes
- `chore:` Maintenance tasks

## Code Review
- Be respectful and constructive
- Address all feedback before merging
- Squash commits when appropriate

## Questions?
Open an issue or contact the maintainers.