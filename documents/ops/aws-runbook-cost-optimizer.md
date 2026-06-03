# AWS Cost Optimizer Runbook

This runbook is for safe AWS cost optimization work. It is evidence-first and does not approve mutation by itself.

## Safe Workflow Pattern

1. Inventory current state.
2. Hash evidence.
3. Analyze candidates.
4. Classify risk and owner.
5. Capture rollback path.
6. Run gitleaks before commit.
7. Request explicit manual approval for any future AWS mutation.
8. Execute only the approved change in a separate controlled pass.
9. Capture post-change evidence and hashes.

## Inventory-First Rule

Never decide from billing alone. Billing points to cost pressure; inventory proves whether the resource is live, attached, routed, serving traffic, or needed for rollback/DR.

Required inventory areas:

- EC2 instances, ASGs, EIPs, ENIs, EBS volumes, EBS snapshots.
- NAT gateways, route tables, VPC endpoints.
- ALBs/NLBs, listeners, target groups, target health.
- RDS instances/clusters, backups, snapshots, valid modification targets.
- ElastiCache replication groups/clusters, node type/count, failover, Multi-AZ.
- DNS, IAM, S3/object storage, WAF, CloudWatch, and release/runner dependencies when relevant.

## Evidence Hashing Rule

Every evidence directory must include `SHA256SUMS.txt`. Regenerate hashes after adding analysis files. Do not edit raw evidence in place after hashing; create a new timestamped directory if evidence must change.

## Gitleaks Rule

Gitleaks must pass before commit:

```bash
docker run --rm \
  -v "$PWD:/repo" \
  ghcr.io/gitleaks/gitleaks:v8.24.2 \
  detect --source /repo --redact
```

Do not commit secrets, tokens, AWS client tokens, private keys, `.env` files, or raw credentials.

## AWS Mutation Gate

Cost optimizer analysis must not call mutating APIs. Forbidden without a separate approved change record:

- `delete-*`, `modify-*`, `stop-*`, `start-*`, `terminate-*`, `release-*`, `detach-*`, `deregister-*`, `put-*`, `create-*`, `update-*`.
- Route 53 changes.
- RDS/ElastiCache class changes.
- EC2 stop/resize/terminate.
- NAT route changes or gateway deletion.
- Snapshot, AMI, EBS, S3, IAM, WAF, Secrets Manager, or log retention changes.

## Rollback Gate

Before any future mutation, write an approval record with:

- Resource ID/ARN.
- Current cost evidence.
- Owner and business reason.
- Backup/snapshot/AMI evidence.
- Rollback command or console path.
- Maintenance window.
- Post-action health checks.
- DR and security impact.

## Region-by-Region Runbook

### London

1. Reconfirm ALB, target health, frontend EC2 health, RDS status, ElastiCache status, NAT route tables, and external HTTPS.
2. Treat single-NAT and one-cache-node posture as cost exceptions.
3. Do not release, delete, or resize more London resources without fresh evidence and rollback path.
4. Recheck RDS valid modifications later; do not modify if the valid-modification API returns no target.

### Mumbai

1. Rerun regional cleanup inventory.
2. Confirm two ElastiCache nodes remain healthy after the `cache.t4g.small` downsize.
3. Keep `mscqr-mumbai-dr-asg` at current capacity until DR policy changes.
4. Recheck RDS valid modifications later; do not modify if blocked.

### Cape Town

1. Rerun regional cleanup inventory.
2. Keep two `cache.t3.micro` ElastiCache nodes because no lower practical HA class was found.
3. Keep `mscqr-capetown-dr-asg` at current capacity until DR policy changes.
4. Recheck RDS valid modifications later; do not modify if blocked.

## How To Rerun Audits Later

Read-only regional inventory:

```bash
ansible-playbook playbooks/aws-cleanup/regional_inventory.yml
```

Validate the inventory playbook:

```bash
scripts/validate-aws-cleanup-ansible.sh
```

Reusable standalone tool sample flow:

```bash
cd tools/aws-webapp-cost-optimizer
PYTHONPATH=src python -m aws_webapp_cost_optimizer.cli inventory --config examples/config.example.yml
PYTHONPATH=src python -m aws_webapp_cost_optimizer.cli analyze --evidence-dir evidence/<generated-dir>
PYTHONPATH=src python -m aws_webapp_cost_optimizer.cli report --evidence-dir evidence/<generated-dir>
```

CTO recommendation: make future audits repeatable by combining Cost Explorer exports, CloudWatch metrics, and inventory in one read-only evidence pack. Add mutation automation only after approval records are machine-verifiable.
