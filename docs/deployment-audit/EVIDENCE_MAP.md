# Deployment Audit Evidence Map

This map ties required controls to their evidence sources in CI.

| Control | Evidence | Location |
| --- | --- | --- |
| SAST (CodeQL) | SARIF results, alerts | GitHub Security > Code scanning alerts (workflow: `deployment-audit`) |
| Dependency vulnerability scan | OSV scan report | Artifact `deployment-audit-artifacts` -> `audit-artifacts/osv-results.json` |
| Secrets scan | Gitleaks SARIF report | Artifact `deployment-audit-artifacts` -> `audit-artifacts/gitleaks.sarif` |
| IaC scan (conditional) | Trivy config SARIF report | Artifact `deployment-audit-artifacts` -> `audit-artifacts/iac-trivy.sarif` |
| Container scan (conditional) | Trivy image SARIF report | Artifact `deployment-audit-artifacts` -> `audit-artifacts/container-trivy.sarif` |
| SBOM generation | SPDX JSON SBOM | Artifact `deployment-audit-artifacts` -> `audit-artifacts/sbom.spdx.json` |
| Provenance attestation | Build provenance attestation | GitHub Actions run -> Attestations for `audit-artifacts/sbom.spdx.json` |
| Release gate | Deployment blocked unless audit succeeds | Workflow `release-gate` job `deploy` |
| Migration reproducibility | `prisma migrate status` and clean DB validation logs | Release pipeline logs or deployment preflight script output |
