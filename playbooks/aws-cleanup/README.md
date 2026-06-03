# AWS Cleanup Regional Inventory

This playbook gathers read-only AWS inventory evidence for regional cleanup discovery. It is intended for production-safe review only and does not approve or perform any cleanup.

Supported regions:

- Mumbai: `ap-south-1`
- Cape Town: `af-south-1`

Run from the repository root:

```bash
ansible-playbook playbooks/aws-cleanup/regional_inventory.yml
```

Each run writes timestamped evidence folders under:

```text
documents/ops/evidence/aws-regional-cleanup-<label>-<UTC_STAMP>/
```

Each regional folder contains AWS CLI JSON output, stderr, status files, target health summaries, ECS service summaries, a human-readable regional cleanup summary, and `SHA256SUMS.txt`.

Only read-only AWS CLI calls are used: `get-caller-identity`, `describe-*`, and `list-*`. The playbook does not call Secrets Manager `GetSecretValue` and does not print secrets.

Any future mutation playbooks must be separate from this inventory workflow, require explicit confirmation variables, and include screenshot evidence, resource ID/ARN, cost evidence, rollback path, backup check, and manual approval.

Never use this inventory as automatic deletion approval. Preliminary candidates are review prompts only.
