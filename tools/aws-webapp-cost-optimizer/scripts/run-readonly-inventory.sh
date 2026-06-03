#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "$PROJECT_DIR"
PYTHONPATH="$PROJECT_DIR/src" python -m aws_webapp_cost_optimizer.cli inventory --config examples/config.example.yml
