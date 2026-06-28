# Windows Connector Upgrade Lifecycle - 2026-06-27

## Purpose

MSCQR Windows Connector installation must behave like an in-place industrial upgrade. Installing a newer connector must update the active runtime, not only the Windows uninstall registry entry.

## Upgrade Contract

The Windows installer runs `Install Connector.cmd`, which invokes `install-startup-task.ps1`. The PowerShell upgrade routine must:

1. Detect existing `mscqr-local-print-agent` or local print-agent Node processes.
2. Stop them gracefully, then force-stop if needed.
3. Remove stale `%LOCALAPPDATA%\MSCQR\local-print-agent\mscqr-local-print-agent.lock` after processes are stopped.
4. Copy the packaged runtime binary into `%LOCALAPPDATA%\MSCQR\local-print-agent\bin`.
5. Rewrite installer-owned `agent.env` values:
   - `PRINT_AGENT_VERSION`
   - `PRINT_AGENT_BUILD_VERSION`
   - `PRINT_AGENT_SESSION_MODE`
   - `PRINT_GATEWAY_BACKEND_URL`
   - `PRINT_AGENT_BACKEND_URL`
6. Preserve existing safe config values such as gateway IDs/secrets, host/port overrides, state file path, and lock-dir overrides.
7. Recreate the Startup VBS launcher so it points at the canonical active runtime wrapper.
8. Start the active runtime connector.
9. Poll `http://127.0.0.1:17866/status` until `agentVersion` and `buildVersion` both match the installer version.
10. Write `%LOCALAPPDATA%\MSCQR\local-print-agent\install-result.json`.
11. Exit non-zero if status verification reports the old version or never reaches the new version.

The installer must not delete connector identity keys, device fingerprint, selected printer state, or calibration profiles unless a future security incident response explicitly requires that rotation.

## Expected Status After 2026.6.26 Upgrade

`http://127.0.0.1:17866/status` should report:

- `agentVersion: 2026.6.26`
- `buildVersion: 2026.6.26`
- `capabilities.supportsPersistentPrintSession: true`
- `capabilities.supportsOfficialMscqrZplWordmark: true`

`install-result.json` should include:

- `installedVersion`
- `previousVersion`
- `upgradedFrom`
- `runtimePath`
- `binaryPath`
- `statusCheck`
- `failureReason`

## Mac Build Commands

Build an unsigned internal Windows validation ZIP from macOS:

```sh
WEB_APP_BASE_URL=https://mscqr.com \
MACOS_CONNECTOR_REQUIRE_NOTARIZATION=false \
npm --prefix backend run connector:release
```

Smoke-check the generated connector manifest and package:

```sh
npm --prefix backend run connector:smoke
```

Build a Windows installer scaffold for signing on a Windows machine with Inno Setup:

```sh
WEB_APP_BASE_URL=https://mscqr.com \
npm --prefix backend run connector:windows:build-installer
```

Publish a signed Windows connector after signing:

```sh
WINDOWS_CONNECTOR_SIGNED_INSTALLER_PATH="C:\\path\\to\\MSCQR-Connector-Windows-2026.6.26.exe" \
WINDOWS_CONNECTOR_PUBLISHER_NAME="L&D Health Ltd" \
WINDOWS_CONNECTOR_SIGNED_AT="2026-06-27T00:00:00.000Z" \
npm --prefix backend run connector:windows:publish-signed
```

## Windows Validation Commands

Check active connector status:

```powershell
curl.exe http://127.0.0.1:17866/status
```

Check uninstall registry version:

```powershell
Get-ItemProperty HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
  Where-Object { $_.DisplayName -like "*MSCQR Connector*" } |
  Select-Object DisplayName, DisplayVersion, InstallLocation
```

Check running connector process path:

```powershell
Get-CimInstance Win32_Process |
  Where-Object { $_.Name -eq "mscqr-local-print-agent.exe" -or $_.CommandLine -match "mscqr-local-print-agent" } |
  Select-Object ProcessId, Name, ExecutablePath, CommandLine
```

Check active runtime environment:

```powershell
Get-Content "$env:LOCALAPPDATA\MSCQR\local-print-agent\agent.env"
```

Check lock file version:

```powershell
Get-Content "$env:LOCALAPPDATA\MSCQR\local-print-agent\mscqr-local-print-agent.lock"
```

Check startup launcher:

```powershell
Get-Content "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\MSCQR Connector.vbs"
```

Check install result:

```powershell
Get-Content "$env:LOCALAPPDATA\MSCQR\local-print-agent\install-result.json" | ConvertFrom-Json
```

## Troubleshooting

If `/status` still reports the previous version after install:

1. Check `install-result.json`; the installer should have failed with a status verification reason.
2. Check `logs\setup.log` for old process stop/copy/status-poll events.
3. Confirm only one connector process exists and it runs from `%LOCALAPPDATA%\MSCQR\local-print-agent\bin\mscqr-local-print-agent.exe`.
4. Confirm `agent.env` has the new `PRINT_AGENT_VERSION` and `PRINT_AGENT_BUILD_VERSION`.
5. Remove stale startup entries only through the installer/uninstaller flow.
6. Re-run the signed installer. Do not manually delete identity/state files unless MSCQR support instructs a secure re-registration.
