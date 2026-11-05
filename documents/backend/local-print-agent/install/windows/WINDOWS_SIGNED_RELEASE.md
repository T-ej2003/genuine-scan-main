# Windows installer build modes

The documented development command requires no maintenance credential or production origin:

```powershell
cd backend
$env:WEB_APP_BASE_URL='http://127.0.0.1:5173'
npm run connector:windows:build-installer
```

This explicitly selects --mode=development. It builds the runtime and stages an unsigned fixture under .connector-build/windows-installer-development, outside the publication tree. Inno Setup is optional for scaffolding. The compiled filename includes DEVELOPMENT-unsigned. The generated installer refuses installation before copying files, contains no maintenance API origin, and cannot compile with MSCQR_SIGNED_RELEASE. It is a development fixture, not a customer installer or Windows policy certification artifact. Do not publish it or use it to replace an installed connector.

## Governed signed candidate

Use the existing windows-connector-signed-release.yml workflow, only with authorization for its protected Azure signing identity. Candidate-only mode cannot publish or tag. The publication blocker remains effective pending certification. The workflow calls:

```powershell
npm --prefix backend run connector:windows:prepare-signed-candidate
```

This selects --mode=signed-candidate. It requires MSCQR_MAINTENANCE_API_ORIGIN (requested HTTPS origin) and MSCQR_APPROVED_MAINTENANCE_API_ORIGIN (a separately governed variable in the protected signing environment). They must match. Missing, noncanonical, HTTP, credentials, paths, queries, fragments and host substitutions fail closed. The runtime maintenance client forbids redirects. There is no production default. WEB_APP_BASE_URL and the source-matching CONNECTOR_RELEASE_VERSION remain workflow settings.

The approved workflow signs the runtime and PowerShell payload, then compiles with Inno Setup 6.7.1, the Azure SignTool hook and SignedUninstaller=yes. Do not externally sign only the final installer: that misses temporary Setup copies and the uninstaller. Do not substitute self-signed certificates. Verify the actual candidate and extracted executables, expected publisher, chain, timestamp, SHA256 and source provenance with the artifact verifier. Certify interactive/silent install, legacy upgrade and rollback under the applicable enforced Application Control policy. An unrestricted runner or mocked signature check does not satisfy that gate.

Release and production backend deployment require separate authorization. Do not raise minimum versions before a verified replacement is available. Physical Zebra certification additionally requires independently verified production isolation and reconciled connector-side work.
