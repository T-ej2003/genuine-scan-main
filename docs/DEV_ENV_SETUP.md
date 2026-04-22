# Developer Environment Setup (Web App + Backend + Codex Runtime)

Use this setup to avoid missing-tool failures during security hardening and release gates.

## Required baseline tools

- Node.js 20.x
- npm
- git
- docker + docker compose
- gh (GitHub CLI)
- openssl
- jq
- psql
- rg (ripgrep)

## 1) Install tools

### macOS

```bash
bash scripts/dev/install-macos.sh
```

### Ubuntu

```bash
bash scripts/dev/install-ubuntu.sh
```

## 2) Verify toolchain health

```bash
bash scripts/dev/doctor.sh
```

The doctor script checks:

- required binaries
- node major version
- PATH corruption patterns (for example accidental `Unknown command: "bin"` injection)

## 3) Install project dependencies

```bash
npm ci
npm --prefix backend ci
```

## 4) Validate core release checks locally

```bash
npm run verify:rc-local
npm run verify:release
```

`verify:release` is the deterministic repo-local release contract. Browser-heavy Playwright coverage stays in CI and should be run explicitly when needed:

```bash
npx playwright install --with-deps chromium
npm run verify:ci:frontend:e2e
```

## 5) Local smoke (dev only)

```bash
npm run smoke:dev-local
```

For staging/release smoke, always set `SMOKE_BASE_URL` and run:

```bash
SMOKE_BASE_URL=https://<staging-host> npm run verify:staging-smoke
```
