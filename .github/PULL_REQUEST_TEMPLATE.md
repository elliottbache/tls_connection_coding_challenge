# Pull request

## Summary
<!-- What does this change? Why? Link issues like Fixes #123 -->

## Changes
- [ ] Code
- [ ] Tests
- [ ] Docs
- [ ] CI / Tooling

## How to test
<!-- Commands or steps reviewers can run locally -->
```bash
pytest -q
sphinx-build -b html docs docs/_build/html
pre-commit run --all-files
```

## Checklist
- [ ] I ran pre-commit locally and fixed findings.
- [ ] I added/updated tests for this change.
- [ ] I updated docs where appropriate.
- [ ] I followed the project’s style (Black/Ruff/Mypy).
- [ ] Backwards compatibility considered or migration noted.