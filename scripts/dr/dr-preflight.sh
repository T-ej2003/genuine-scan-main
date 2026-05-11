#!/bin/sh
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
. "$SCRIPT_DIR/common.sh"

require_repo_root

branch="$(git branch --show-current)"
echo "Repository: $(pwd)"
echo "Branch: ${branch:-detached}"
if [ "$branch" = "main" ]; then
  echo "WARNING: you are on main. DR implementation and drills should run from aws-dr-finish or an approved feature branch." >&2
fi

echo "Latest commit: $(git rev-parse --short HEAD) $(git log -1 --pretty=%s)"
echo "Working tree:"
git status --short

echo "Running document checks..."
npm run check:documents

echo "Running guardrails..."
npm run verify:guardrails

echo "Checking whitespace..."
git diff --check

echo "Checking shell syntax..."
/bin/sh -n scripts/deploy-standby.sh
/bin/sh -n scripts/health-check-regions.sh
for file in scripts/dr/*.sh; do
  /bin/sh -n "$file"
done

echo "DR preflight completed without deploying or touching AWS."
