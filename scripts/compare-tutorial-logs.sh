#!/usr/bin/env bash
set -euo pipefail

status=0
if ! diff -u docs/tutorial/server.log ~/.local/state/tlslp/logs/server.log; then
  status=1
fi
if ! diff -u docs/tutorial/client.log ~/.local/state/tlslp/logs/client.log; then
  status=1
fi

if [[ $status -eq 0 ]]; then
  echo "All tutorial logs match expected outputs."
else
  echo "One or more tutorial logs differ from expected outputs."
fi

exit "$status"