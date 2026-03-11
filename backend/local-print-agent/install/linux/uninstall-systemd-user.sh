#!/bin/sh
set -eu

SERVICE_FILE="$HOME/.config/systemd/user/mscqr-local-print-agent.service"
WRAPPER="$HOME/.authenticqr/local-print-agent/bin/start-local-print-agent.sh"

systemctl --user disable --now mscqr-local-print-agent.service >/dev/null 2>&1 || true
rm -f "$SERVICE_FILE" "$WRAPPER"
systemctl --user daemon-reload >/dev/null 2>&1 || true

echo "MSCQR local print agent removed from Linux user services."
