# Contributing to OpenMaskit

Thanks for your interest in contributing! OpenMaskit is in early development and contributions of all kinds are welcome — bug reports, fixes, features, docs, and marketplace catalog entries.

## Reporting issues

1. Check [existing issues](https://github.com/MaskitMCP/openmaskit/issues) to avoid duplicates.
2. Open a new issue with:
   - A clear title and description
   - Steps to reproduce (for bugs)
   - Expected vs. actual behavior
   - Relevant logs, screenshots, or config

## Development setup

```bash
git clone https://github.com/MaskitMCP/openmaskit.git
cd openmaskit
uv sync
```

Run OpenMaskit locally:

```bash
uv run openmaskit                    # uses ./openmaskit.yaml if present
uv run openmaskit path/to/config.yaml
```

Then open the dashboard at `http://127.0.0.1:9473`.

## Testing

```bash
uv run pytest tests/ -v                                                   # all tests
uv run pytest tests/test_engine.py -v                                     # one module
uv run pytest tests/test_engine.py::TestMaskingEngine::test_mask_structured_content -v  # one test
```

New features and bug fixes should come with tests.

## Submitting a change

1. **Fork and branch**: `git checkout -b feature/your-feature-name`
2. **Code** — follow the conventions of the surrounding files. Python 3.12+, type hints where they clarify intent, docstrings on public APIs. Keep functions focused.
3. **Test** — run the suite above. Add cases for what you changed.
4. **Commit** with a clear message describing the *why*, not just the *what*.
5. **Push** and open a pull request. Reference any related issues.

### Pull request guidelines

- One feature or fix per PR.
- Update docs (`README.md`, `CLAUDE.md`) if your change affects how OpenMaskit is used or how it's structured.
- Be responsive to review feedback.
- For large changes, open an issue first to align on direction before writing code.

## Areas where help is wanted

- **Test coverage** — integration tests, fuzzing, concurrency stress tests
- **Documentation** — examples, tutorials, architecture diagrams
- **Edge cases** — binary data, large payloads, streaming responses
- **Security review** — threat modeling, timing attack analysis
- **Observability** — metrics, structured logging improvements
- **Marketplace** — more pre-configured MCP servers in the catalog
- **Bug fixes** — see the issue tracker

## License

By contributing, you agree that your contributions are licensed under the Apache License, Version 2.0 (see [LICENSE](LICENSE)). This includes the patent grant in §3 of that license.

## Questions?

Open an issue or start a discussion in the repo — we're happy to help.
