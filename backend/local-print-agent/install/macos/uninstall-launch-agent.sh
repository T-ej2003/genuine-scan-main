#!/bin/sh
set -eu

PLIST="$HOME/Library/LaunchAgents/com.mscqr.local-print-agent.plist"
WRAPPER="$HOME/.mscqr/local-print-agent/bin/start-local-print-agent.sh"

launchctl bootout "gui/$(id -u)" "$PLIST" >/dev/null 2>&1 || true
rm -f "$PLIST" "$WRAPPER"

echo "MSCQR local print agent removed from macOS login items."
