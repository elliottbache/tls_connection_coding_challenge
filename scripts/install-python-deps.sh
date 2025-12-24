#!/usr/bin/env bash
set -euo pipefail

if [[ ! -f pyproject.toml ]]; then
  echo "Run this from the repo root (pyproject.toml not found)."
  exit 1
fi

if ! command -v apt-get >/dev/null 2>&1; then
  echo "This helper supports Debian/Ubuntu/WSL with apt-get. Install Python deps manually on your distro"
  echo "or use Docker instead (see README)."
  exit 1
fi

# if root, make SUDO empty and thus no sudo used to run commands
SUDO=""
if [[ $EUID -ne 0 ]]; then
  SUDO="sudo"
fi
$SUDO apt-get update

# this script intentionally installs ONLY Python 3.11 + venv support.
# If your distro cannot provide these packages, use Docker instead.
$SUDO apt-get install -y --no-install-recommends python3.11 python3.11-venv

# check python3.11 and its venv have been installed
rm -rf /tmp/tlscc_venv_check
python3.11 -m venv /tmp/tlscc_venv_check >/dev/null
rm -rf /tmp/tlscc_venv_check
echo -e "\n***OK: Installed python3.11 and python3.11-venv.***\n"

python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install -U pip

echo -e "\n***OK: venv created at .venv and dependencies installed.***\n"