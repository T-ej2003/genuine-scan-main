# Windows signed release guide

This guide prepares the MSCQR Windows connector for a real trusted Windows release.

## 1. Build the unsigned installer scaffold

From the `backend` folder:

```bash
export WEB_APP_BASE_URL=https://mscqr.com
npm run connector:windows:build-installer
```

What this does:

1. builds the backend
2. packages the Windows connector binary
3. stages the install assets
4. renders an Inno Setup project file
5. optionally compiles an unsigned `.exe` installer on a Windows machine with Inno Setup installed

If Inno Setup is not installed yet, the command still prints:

- the staging folder
- the generated `.iss` project file
- the output folder where the installer should land

## 2. Compile the unsigned Windows installer on a Windows machine

Install:

- Inno Setup 6
- Windows SDK / SignTool for later signing

Then run:

```powershell
cd backend
$env:WEB_APP_BASE_URL="https://mscqr.com"
npm run connector:windows:build-installer
```

If `INNO_SETUP_COMPILER_PATH` is not detected automatically, set it before rerunning:

```powershell
$env:INNO_SETUP_COMPILER_PATH="C:\Program Files (x86)\Inno Setup 6\ISCC.exe"
```

## 3. Publish an unsigned internal test installer

Only for internal validation:

```bash
export WINDOWS_CONNECTOR_UNSIGNED_INSTALLER_PATH=/absolute/path/to/MSCQR-Connector-Windows-<version>-unsigned.exe
npm run connector:release
```

MSCQR will publish that artifact as:

- `Windows test installer`
- trust level: `unsigned`
- Windows trust mode: `unsigned-test`

It will never be presented as a trusted Windows customer installer.

## 4. Sign the Windows installer later

When Azure Trusted Signing or another trusted signing path is ready:

1. sign the Windows installer
2. timestamp the signature
3. verify the signature on Windows

Then publish the signed installer:

```bash
export WINDOWS_CONNECTOR_SIGNED_INSTALLER_PATH=/absolute/path/to/MSCQR-Connector-Windows-<version>.exe
export WINDOWS_CONNECTOR_PUBLISHER_NAME="Your Company Name"
export WINDOWS_CONNECTOR_SIGNED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
npm run connector:release
```

MSCQR will then publish it as:

- `Windows installer`
- trust level: `trusted`
- signature status: `signed`

## 5. Verify before customer rollout

On a Windows machine:

```powershell
cd backend
npm run connector:windows:verify -- --file "C:\path\to\installer.exe" --expect-signed --publisher-name "Your Company Name"
```

Manual checks:

1. Right-click the installer
2. Open `Properties`
3. Open `Digital Signatures`
4. Confirm the publisher name is correct
5. Confirm the signature is timestamped
6. Download the installer on a clean Windows 11 machine with Smart App Control enabled
7. Confirm the installer launches normally
