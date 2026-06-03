# Evidence Format

Each inventory run writes a timestamped directory:

```text
evidence/aws-webapp-cost-optimizer-<app-name>-<UTC_STAMP>/
  inventory.json
  metadata.json
  <region>/resources.json
  SHA256SUMS.txt
```

Analysis adds:

```text
analysis.json
report.md
SHA256SUMS.txt
```

The SHA256 manifest is regenerated after each write so reviewers can detect evidence drift.

No raw secrets, `.env` files, private keys, AWS client tokens, or credentials belong in evidence.
