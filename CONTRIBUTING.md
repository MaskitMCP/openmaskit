# Contributing to Maskit

Thank you for your interest in contributing to Maskit! This project is in early development and we welcome contributions of all kinds.

## How to Contribute

### Reporting Issues

Found a bug or have a feature request?

1. Check the [existing issues](https://github.com/AminMal/maskit/issues) to avoid duplicates
2. Open a new issue with:
   - Clear title and description
   - Steps to reproduce (for bugs)
   - Expected vs. actual behavior
   - Relevant logs, screenshots, or config files

### Contributing Code

1. **Fork and clone** the repository
2. **Install dependencies**: `uv sync`
3. **Create a branch**: `git checkout -b feature/your-feature-name`
4. **Make your changes**
5. **Run tests**: `uv run pytest tests/ -v`
6. **Commit**: Use clear, descriptive commit messages
7. **Push** and open a pull request

### Code Style

- Follow existing code conventions (Python PEP 8, type hints where helpful)
- Add docstrings for public functions and classes
- Keep functions focused and modular
- Write tests for new features or bug fixes

### Testing

Run the test suite before submitting:

```bash
uv run pytest tests/ -v                          # All tests
uv run pytest tests/test_engine.py -v            # Specific module
uv run pytest tests/test_engine.py::TestMaskingEngine::test_mask_structured_content -v  # Single test
```

### Areas Where We Need Help

- **Test coverage**: Integration tests, fuzzing, concurrency stress tests
- **Documentation**: Examples, tutorials, architecture diagrams
- **Edge cases**: Binary data handling, large payloads, streaming responses
- **Security review**: Threat modeling, timing attack analysis
- **Production features**: Health checks, structured logging, metrics/observability
- **Marketplace**: More pre-configured MCP servers in the catalog
- **Bug fixes**: Check the issues for known bugs

### Pull Request Guidelines

- Keep PRs focused on a single feature or bug fix
- Reference related issues in the PR description
- Update documentation (README, CLAUDE.md) if your change affects usage
- Add tests for new functionality
- Be responsive to review feedback

### Communication

- Open an issue for discussion before starting large changes
- Ask questions in the issue tracker or pull request comments
- Be respectful and constructive in all interactions

## Development Setup

```bash
# Clone the repo
git clone https://github.com/AminMal/maskit.git
cd maskit

# Install dependencies
uv sync

# Run Maskit locally
uv run maskit

# Run tests
uv run pytest tests/ -v
```

## License

By contributing to Maskit, you agree that your contributions will be licensed under the MIT License.

## Questions?

Open an issue or reach out to the maintainers. We're here to help!
