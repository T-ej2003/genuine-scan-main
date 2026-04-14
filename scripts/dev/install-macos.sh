#!/usr/bin/env bash
set -euo pipefail

if ! command -v brew >/dev/null 2>&1; then
  echo "Homebrew is required. Install from https://brew.sh and re-run."
  exit 1
fi

brew update
brew install node@20 git gh openssl jq postgresql ripgrep
brew install --cask docker

echo "macOS tool install complete."
echo "Run: bash scripts/dev/doctor.sh"

