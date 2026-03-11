# MSCQR Local Print Agent Installer Assets

These scripts install the workstation print agent as a login-time service so manufacturers do not need to start it manually on every device.

Supported rollout paths:

- macOS LaunchAgent
- Linux systemd user service
- Windows Scheduled Task at user logon

From the `backend` folder:

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

## Signed package rollout

The repository now includes installer-ready service scripts, but actual code-signing remains an external release step because signing certificates are not stored in source control.

- macOS signed package path: wrap `macos/install-launch-agent.sh` with `pkgbuild` and sign with `productsign`.
- Windows signed installer path: wrap `windows/install-startup-task.ps1` in MSI/Intune/Win32 packaging and sign with `signtool`.
- MDM / IT rollout: Jamf, Kandji, Intune, or similar can run these same scripts directly.
