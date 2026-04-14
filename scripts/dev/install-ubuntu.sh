#!/usr/bin/env bash
set -euo pipefail

sudo apt-get update
sudo apt-get install -y \
  ca-certificates \
  curl \
  git \
  gh \
  openssl \
  jq \
  postgresql-client \
  ripgrep \
  docker.io \
  docker-compose-plugin

if ! command -v node >/dev/null 2>&1; then
  curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
  sudo apt-get install -y nodejs
fi

sudo usermod -aG docker "$USER" || true

echo "Ubuntu tool install complete."
echo "Run: bash scripts/dev/doctor.sh"
echo "If docker group was updated, log out/in before using docker without sudo."

