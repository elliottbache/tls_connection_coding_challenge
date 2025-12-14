# one-time
make venv
source .venv/bin/activate
make install-dev
pre-commit run --all-files

# day-to-day
make test
make lint
make format     # if linting complains
make typecheck
make docs
make run-server
make run-client
