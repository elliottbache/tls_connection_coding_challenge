#!/usr/bin/env bash
set -euo pipefail

if ! command -v apt-get >/dev/null 2>&1; then
  echo "This helper supports Debian/Ubuntu/WSL with apt-get. Install C++ deps manually on your distro."
  exit 1
fi

# if root, make SUDO empty and thus no sudo used to run commands
SUDO=""
if [[ $EUID -ne 0 ]]; then
  SUDO="sudo"
fi
$SUDO apt-get update

$SUDO apt-get install -y \
  build-essential \
  cmake \
  pkg-config \
  libssl-dev

echo "C++ build deps installed."
