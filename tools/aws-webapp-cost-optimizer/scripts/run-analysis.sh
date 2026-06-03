#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: scripts/run-analysis.sh <evidence-dir>" >&2
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "$PROJECT_DIR"
PYTHONPATH="$PROJECT_DIR/src" python -m aws_webapp_cost_optimizer.cli analyze --evidence-dir "$1"
PYTHONPATH="$PROJECT_DIR/src" python -m aws_webapp_cost_optimizer.cli report --evidence-dir "$1"
