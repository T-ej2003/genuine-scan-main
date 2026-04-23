# Terraform Baseline For ECS/ECR

This directory codifies the ECS/ECR production baseline so core release settings stop drifting in AWS console state.

## What It Manages

- backend and worker ECR repositories
  - immutable tags
  - scan on push
  - lifecycle retention
- ECS cluster
  - container insights
- backend and worker CloudWatch log groups
- backend and worker task definitions
  - `LINUX` + `X86_64`
- backend and worker ECS services
  - deployment circuit breaker enabled
  - automatic rollback enabled
  - steady-state waits enabled

## Why Container Definitions Are Passed In

This repo does not yet have a fully normalized source of truth for every production environment variable, secret ARN, and sidecar. To make the IaC ready without inventing unsafe values, task-definition container JSON is passed in as Terraform input.

That still gives you strong drift control for:

- repository safety settings
- ECS service deployment protections
- task-definition runtime platform
- cluster/service naming and topology

## Quick Start

1. Copy the example vars file.

```bash
cp terraform.tfvars.example terraform.tfvars
```

2. Replace the placeholder AWS IDs, ARNs, subnet IDs, and container image refs.

3. Run Terraform from this directory.

```bash
terraform init
terraform plan
terraform apply
```

## Recommended Migration Path

1. Export the current backend and worker task definitions from ECS.
2. Convert the live `containerDefinitions` arrays into the `*_container_definitions_json` values in `terraform.tfvars`.
3. Apply Terraform to bring ECR and ECS service settings under code review.
4. Move remaining AWS resources into IaC over time:
   - ALB listeners and target groups
   - security groups
   - IAM roles and policies
   - Secrets Manager refs
   - Route 53 / ACM / alarms

## Release-Safety Expectations

This Terraform baseline is designed to work with the repo-owned release rail:

- publish workflow for multi-arch signed images
- deploy workflow for backend canary then worker rollout
- automatic rollback if `/version` or `/health/ready` fails during backend canary verification
