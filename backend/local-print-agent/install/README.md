# MSCQR Local Print Agent Installer Assets

These scripts install the workstation print agent as a login-time service so manufacturers do not need to start it manually on every device.

They are maintainer and packaging assets, not end-user instructions. Production rollout should use a signed installer, MDM, or IT packaging flow so operators never run terminal commands themselves.

The repository now also includes packaged connector release output under:

```text
backend/local-print-agent/releases/
```

Build the latest packaged connector artifacts from the `backend` folder with:

```bash
npm run connector:release
```

When the Apple release credentials are configured, that single command now:

1. builds the backend and connector binaries
2. creates the macOS installer package
3. signs the macOS package with `MACOS_CONNECTOR_SIGN_IDENTITY`
4. submits it to Apple notarization
5. staples and validates the notarization ticket
6. updates `backend/local-print-agent/releases/manifest.json`

Recommended macOS release configuration:

```bash
export MACOS_CONNECTOR_SIGN_IDENTITY="Developer ID Installer: Example Company (TEAMID1234)"
export MACOS_CONNECTOR_NOTARY_PROFILE="mscqr-connector"
npm run connector:release
```

Alternative direct notarization credentials:

```bash
export MACOS_CONNECTOR_SIGN_IDENTITY="Developer ID Installer: Example Company (TEAMID1234)"
export MACOS_CONNECTOR_NOTARY_APPLE_ID="you@example.com"
export MACOS_CONNECTOR_NOTARY_TEAM_ID="TEAMID1234"
export MACOS_CONNECTOR_NOTARY_PASSWORD="app-specific-password"
npm run connector:release
```

Supported rollout paths:

- macOS LaunchAgent
- Linux systemd user service
- Windows Scheduled Task at user logon

For engineering and release packaging from the `backend` folder:

```bash
npm run print:agent:install:macos
npm run print:agent:install:linux
```

Windows PowerShell:

```powershell
npm run print:agent:install:windows
```

Uninstall scripts are also available:

```bash
npm run print:agent:uninstall:macos
npm run print:agent:uninstall:linux
```

Windows PowerShell:

```powershell
npm run print:agent:uninstall:windows
```

## What the installer does

1. Builds the backend so `dist/local-print-agent/index.js` is current.
2. Creates a small wrapper under the user profile.
3. Registers the wrapper to start automatically at login.
4. Starts the agent immediately.

The agent still depends on the workstation OS already seeing the printer.

## Optional site-gateway configuration

Each installer creates an optional `agent.env` file under the agent home:

- macOS / Linux: `~/.mscqr/local-print-agent/agent.env`
- Windows: `%LOCALAPPDATA%\MSCQR\local-print-agent\agent.env`

This file can be provisioned by MDM, installer logic, or IT automation. Supported values include:

- `PRINT_AGENT_HOST`
- `PRINT_AGENT_PORT`
- `PRINT_GATEWAY_BACKEND_URL`
- `PRINT_GATEWAY_ID`
- `PRINT_GATEWAY_SECRET`

Use that file when an installed workstation connector must act as a private-LAN site gateway for `NETWORK_IPP` printers.

## Signed package rollout

The repository now includes installer-ready service scripts, and the release script can perform signing plus notarization automatically when the Apple credentials are provided through environment variables. Those credentials and certificates still remain outside source control.

- macOS signed package path: wrap `macos/install-launch-agent.sh` with `pkgbuild` and sign with `productsign`.
- macOS notarized package path: set `MACOS_CONNECTOR_SIGN_IDENTITY` plus either `MACOS_CONNECTOR_NOTARY_PROFILE` or the Apple ID / team ID / password variables, then run `npm run connector:release`.
- Windows signed installer path: wrap `windows/install-startup-task.ps1` in MSI/Intune/Win32 packaging and sign with `signtool`.
- MDM / IT rollout: Jamf, Kandji, Intune, or similar can run these same scripts directly.
