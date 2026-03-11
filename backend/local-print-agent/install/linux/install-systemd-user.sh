#!/bin/sh
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
BACKEND_DIR="$(CDPATH= cd -- "$SCRIPT_DIR/../../.." && pwd)"
NODE_BIN="$(command -v node || true)"
NPM_BIN="$(command -v npm || true)"

if [ -z "$NODE_BIN" ] || [ -z "$NPM_BIN" ]; then
  echo "node and npm must be installed before the MSCQR print agent can be installed."
  exit 1
fi

cd "$BACKEND_DIR"
"$NPM_BIN" ci
"$NPM_BIN" run build

AGENT_HOME="$HOME/.authenticqr/local-print-agent"
BIN_DIR="$AGENT_HOME/bin"
LOG_DIR="$AGENT_HOME/logs"
WRAPPER="$BIN_DIR/start-local-print-agent.sh"
SERVICE_DIR="$HOME/.config/systemd/user"
SERVICE_FILE="$SERVICE_DIR/mscqr-local-print-agent.service"

mkdir -p "$BIN_DIR" "$LOG_DIR" "$SERVICE_DIR"

cat > "$WRAPPER" <<EOF
#!/bin/sh
cd "$BACKEND_DIR"
export PRINT_AGENT_HOST="\${PRINT_AGENT_HOST:-127.0.0.1}"
export PRINT_AGENT_PORT="\${PRINT_AGENT_PORT:-17866}"
exec "$NODE_BIN" "$BACKEND_DIR/dist/local-print-agent/index.js" >> "$LOG_DIR/agent.log" 2>&1
EOF
chmod +x "$WRAPPER"

cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=MSCQR Local Print Agent
After=network-online.target

[Service]
Type=simple
ExecStart=$WRAPPER
Restart=always
RestartSec=3

[Install]
WantedBy=default.target
EOF

systemctl --user daemon-reload
systemctl --user enable --now mscqr-local-print-agent.service

echo "MSCQR local print agent installed for Linux user services."
echo "Status endpoint: http://127.0.0.1:17866/status"
