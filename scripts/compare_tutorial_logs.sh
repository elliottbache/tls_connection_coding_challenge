set -euo pipefail

if ! diff -u docs/tutorial/server.log ~/.local/state/tlscc/logs/server.log; then
  status=1
fi

if ! diff -u docs/tutorial/client.log ~/.local/state/tlscc/logs/client.log; then
  status=1
fi

if [[ $status -eq 0 ]]; then
  echo "All tutorial logs match expected outputs."
else
  echo "One or more tutorial logs differ from expected outputs."
fi