# Contributing

Thanks for your interest in improving this project! This repo contains a Python TLS
client/server, a C++ WORK helper, tests (pytest), docs (Sphinx), and Docker setups.

## Quick start

1. **Fork & clone** your fork.
2. **Create a virtualenv** (Python 3.11+):
```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
```
3. **Install deps** (dev extras included):
```bash
pip install -e .[dev]
pre-commit install
```
4. **Build docs** (optional quick check):
```bash
sphinx-build -b html docs docs/_build/html
```
5. Run tests & linters:
```bash
pytest -q
ruff check .
black --check .
mypy src
```

See "Quickstart" and "Installation" sections of [README.md](README.md) for more details.
## Branch & commit style
- **Branch names**: ```feat/<short-desc>```, ```fix/<short-desc>```, ```docs/<short-desc>```, ```chore/<short-desc>```
- **Commits**: Prefer Conventional Commits
  - Examples: ```feat(client): add timeout for WORK, fix(server): avoid EOF during handshake```

## Making changes
- Keep Python code formatted with **Black**; keep imports & lint happy with **Ruff**.
- Add **type hints** for new/changed functions (mypy runs on ```src/```).
- Add/adjust **pytest** tests (unit or integration) for behavior changes.
- Update **Sphinx docs** when applicable (```docs/```), and include short “What changed?” in PR description.

## Running integration locally
Ensure your TLS materials exist in ```certificates/``` (see [README.md](README.md) "Installation" section).
- **Direct Python** (two terminals, after `pip install -e .`):
```bash
# Terminal A
python -m src.server
# Terminal B
python -m src.client
```
- **Docker (host network)**:
```bash
docker compose up --build
```
See "Quickstart" section of [README.md](README.md) for more details.

Notes:
- By default the project runs in **secure (mTLS)** mode. For quick localhost testing you can 
add ```--insecure``` on both sides to skip certificate verification.

## C++ WORK helper
The client resolves the PoW challenge by calling an external executable that prints a line like:
`RESULT:<suffix>`

Defaults:
- Expected location: `src/tlslp/_bin/pow_challenge` (override with `--pow-binary`)
- The client also validates the binary path for basic safety (must not be a symlink, must be executable on POSIX,
  and must not be world-writable, and must live under the allowed root by default).

Build (recommended):
```bash
make build-cpp
```

If you change the binary interface/output format, update tlslp.client.handle_pow_cpp(...) and the unit tests
that mock subprocess.run.

## Test matrix & quality gates
The CI runs on every push/PR:
- `pre-commit` (format/lint/type checks as configured in `.pre-commit-config.yaml`)
- `pytest`
- `sphinx-build`

Please run these locally before opening a PR:
```bash
pre-commit run --all-files
pytest -q
sphinx-build -b html docs docs/_build/html
```

## Opening a Pull Request
- Fill in the PR template checklist.
- Link any related issues (```Fixes #123```).
- Keep PRs focused & reviewable (prefer smaller PRs).

## Reporting bugs / requesting features
- Use the ```Issue templates``` (Bug/Feature).
- For security issues, please ```do not``` open a public issue.  Send an email to elliottbache@gmail.com.

## License
By contributing, you agree your contributions are licensed under this repository’s license.
