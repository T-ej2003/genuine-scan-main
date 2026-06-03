# AWS Web App Cost Optimizer

Read-only AWS inventory and cost optimization analyzer for web applications.

The tool collects evidence, hashes it with SHA256, classifies cost optimization candidates, and writes Markdown reports. Default example commands run in sample mode and do not call AWS.

## Quick Start

```bash
python -m aws_webapp_cost_optimizer.cli inventory --config examples/config.example.yml
python -m aws_webapp_cost_optimizer.cli analyze --evidence-dir evidence/<generated-dir>
python -m aws_webapp_cost_optimizer.cli report --evidence-dir evidence/<generated-dir>
```

After packaging, the intended console script is:

```bash
aws-webapp-cost-optimizer inventory --config examples/config.example.yml
aws-webapp-cost-optimizer analyze --evidence-dir <dir>
aws-webapp-cost-optimizer report --evidence-dir <dir>
```

## What It Classifies

- EC2 instances
- Elastic IPs
- NAT gateways
- Route tables
- ALBs/NLBs
- Target groups
- RDS instances and clusters
- ElastiCache replication groups and clusters
- Auto Scaling Groups
- EBS volumes and snapshots
- ENIs
- VPC endpoints

## Safety Categories

- `unused deletion candidate`
- `used but oversized`
- `DR posture decision required`
- `blocked by AWS valid-modification API`
- `manual approval required`
- `keep`
- `observe only`

These categories are review labels only. They are not approval to change AWS.

## Safety Defaults

- Read-only by default.
- No default command mutates AWS infrastructure.
- Evidence is timestamped and hash-manifested.
- Config metadata is redacted before being written.
- Database, snapshot, DR, DNS, load balancer, and production entry-point resources default conservative.

## Development

```bash
python -m pytest tests
python -m compileall src
```

## CTO Recommendation

Treat this as the evidence layer, not the actuator. The next best development step is adding Cost Explorer and CloudWatch metric adapters that still write evidence only, then a policy engine that requires signed approval records before generating any change plan.
