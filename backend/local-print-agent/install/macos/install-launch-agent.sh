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

AGENT_HOME="$HOME/.mscqr/local-print-agent"
BIN_DIR="$AGENT_HOME/bin"
LOG_DIR="$AGENT_HOME/logs"
ENV_FILE="$AGENT_HOME/agent.env"
WRAPPER="$BIN_DIR/start-local-print-agent.sh"
PLIST="$HOME/Library/LaunchAgents/com.mscqr.local-print-agent.plist"

mkdir -p "$BIN_DIR" "$LOG_DIR" "$HOME/Library/LaunchAgents"

cat > "$WRAPPER" <<EOF
#!/bin/sh
set -eu
AGENT_HOME="$AGENT_HOME"
ENV_FILE="$ENV_FILE"
if [ -f "\$ENV_FILE" ]; then
  set -a
  # shellcheck disable=SC1090
  . "\$ENV_FILE"
  set +a
fi
cd "$BACKEND_DIR"
export PRINT_AGENT_HOST="\${PRINT_AGENT_HOST:-127.0.0.1}"
export PRINT_AGENT_PORT="\${PRINT_AGENT_PORT:-17866}"
exec "$NODE_BIN" "$BACKEND_DIR/dist/local-print-agent/index.js" >> "$LOG_DIR/agent.log" 2>&1
EOF
chmod +x "$WRAPPER"

if [ ! -f "$ENV_FILE" ]; then
  cat > "$ENV_FILE" <<EOF
# Optional MSCQR local print agent overrides.
# Example:
# PRINT_GATEWAY_BACKEND_URL=https://mscqr.example.com/api
# PRINT_GATEWAY_ID=gw_1234567890
# PRINT_GATEWAY_SECRET=replace-with-bootstrap-secret
EOF
fi

cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
  <dict>
    <key>Label</key>
    <string>com.mscqr.local-print-agent</string>
    <key>ProgramArguments</key>
    <array>
      <string>$WRAPPER</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>$LOG_DIR/stdout.log</string>
    <key>StandardErrorPath</key>
    <string>$LOG_DIR/stderr.log</string>
  </dict>
</plist>
EOF

launchctl bootout "gui/$(id -u)" "$PLIST" >/dev/null 2>&1 || true
launchctl bootstrap "gui/$(id -u)" "$PLIST"
launchctl kickstart -k "gui/$(id -u)/com.mscqr.local-print-agent"

echo "MSCQR local print agent installed for macOS."
echo "Status endpoint: http://127.0.0.1:17866/status"
echo "Optional gateway configuration file: $ENV_FILE"
