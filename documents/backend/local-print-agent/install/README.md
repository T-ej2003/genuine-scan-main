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

Its Windows ZIP is a **non-installable inspection fixture** kept under
`.connector-build`, outside release/download directories. It is omitted from
the download manifest. Do not run its unsigned runtime or scripts. Executable
Windows testing and publication require the existing governed signed Windows
workflow. `connector:windows:publish-zip` is retired and fails before mutation;
the generic builder also rejects signed/unsigned Windows artifact-path overrides.
The approved signed publisher remains separate. A macOS manifest refresh
preserves an existing trusted Windows record for the same version.

Prepare the Windows installer scaffold from the `backend` folder with:

```bash
npm run connector:windows:build-installer
```

That command stages a non-installable development fixture and can compile it
with Inno Setup. Installation is deliberately disabled; it is not a substitute
for the protected signed candidate workflow.

When the Apple release credentials are configured, that single command now:

1. builds the backend and connector binaries
2. signs the bundled macOS executables with `MACOS_CONNECTOR_APP_SIGN_IDENTITY`
3. creates the macOS installer package
4. signs the macOS package with `MACOS_CONNECTOR_SIGN_IDENTITY`
5. submits it to Apple notarization
6. staples and validates the notarization ticket
7. updates `backend/local-print-agent/releases/manifest.json`

Recommended macOS release configuration:

```bash
export MACOS_CONNECTOR_APP_SIGN_IDENTITY="Developer ID Application: Example Company (TEAMID1234)"
export MACOS_CONNECTOR_SIGN_IDENTITY="Developer ID Installer: Example Company (TEAMID1234)"
export MACOS_CONNECTOR_NOTARY_PROFILE="mscqr-connector"
npm run connector:release
```

Alternative direct notarization credentials:

```bash
export MACOS_CONNECTOR_APP_SIGN_IDENTITY="Developer ID Application: Example Company (TEAMID1234)"
export MACOS_CONNECTOR_SIGN_IDENTITY="Developer ID Installer: Example Company (TEAMID1234)"
export MACOS_CONNECTOR_NOTARY_APPLE_ID="you@example.com"
export MACOS_CONNECTOR_NOTARY_TEAM_ID="TEAMID1234"
export MACOS_CONNECTOR_NOTARY_PASSWORD="app-specific-password"
npm run connector:release
```

Supported rollout paths:

- macOS LaunchAgent
- Linux systemd user service
- Windows per-user Startup entry at logon

For engineering and release packaging from the `backend` folder:

The installers initialize identity explicitly on a first installation and validate the existing identity before starting an installed service. Ordinary connector startup refuses a missing state file. For a standalone development run, build first, run `npm run print:agent:init` once for a new isolated profile, then run `npm run print:agent`. Never use initialization to replace a missing identity from an existing installation.

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
3. Registers the wrapper to start automatically at login for the signed-in user.
4. Starts the agent immediately.
5. On Windows packaged installs, polls the local `/status` endpoint and classifies the workstation as:
   - `READY`: connector installed and a usable online printer was verified
   - `NO_PRINTERS`: connector installed, but the OS has not exposed any printers yet
   - `PRINTER_UNAVAILABLE`: connector installed, but the resolved printer is offline or otherwise not usable yet

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
- macOS notarized package path: set `MACOS_CONNECTOR_APP_SIGN_IDENTITY`, `MACOS_CONNECTOR_SIGN_IDENTITY`, plus either `MACOS_CONNECTOR_NOTARY_PROFILE` or the Apple ID / team ID / password variables, then run `npm run connector:release`.
- Windows development scaffold: `npm run connector:windows:build-installer` creates a non-installable `DEVELOPMENT-unsigned` fixture outside the publication tree, without production maintenance configuration. Never publish it. Signed candidates use the protected existing workflow and `connector:windows:prepare-signed-candidate`, with matching explicit `MSCQR_MAINTENANCE_API_ORIGIN` and governed `MSCQR_APPROVED_MAINTENANCE_API_ORIGIN`. See [Windows build modes](windows/WINDOWS_SIGNED_RELEASE.md).
- MDM / IT rollout: Jamf, Kandji, Intune, or similar can run these same scripts directly.

See the full Windows release guide in:

```text
documents/backend/local-print-agent/install/windows/WINDOWS_SIGNED_RELEASE.md
```

By default, `npm run connector:release` now treats macOS notarization as required for public distribution. If you explicitly set `MACOS_CONNECTOR_REQUIRE_NOTARIZATION=false`, the script can still build a local test package, but it keeps that Mac artifact out of `manifest.json` so the download page does not publish a Gatekeeper-blocked installer.
