# Stage-B current rollover observation binding

This contract applies to `FRESH_IMAGE_PARTIAL_APPLY_RECOVERY` approval.

## Authoritative domains

- Canonical broker modes come from protected `STAGE_B_MODES` configuration.
- Current predecessor ARNs come from current, non-deposed Terraform plan changes.
- ECS service and task references come from the normalized top-level audit observations.
- Per-entry rollover arrays and atomic broker proofs are derived evidence and must reconcile to those authorities.
- Terraform mutation identity is `address + deposed identity`; address alone is insufficient.

## Runtime model

The validator normalizes services, RUNNING tasks, PENDING tasks, and all repository-recorded transitional tasks into references keyed by task-definition ARN. A current predecessor is rejected if any normalized class references it. Per-entry service, RUNNING, and PENDING summaries must exactly equal the normalized top-level sets; a transitional summary, if present, is checked the same way. Equality is not sufficient: every normalized predecessor reference class must also be empty.

Broker mappings must contain exactly the protected canonical mode set. Each canonical mode independently resolves to one protected family and exactly one authenticated current plan replacement; its observed mapping ARN must equal that replacement's `beforeArn`. Each such mode requires exactly one matching current rollover entry and one atomic proof. A mismatched revision is an error, never a filtered-out observation. The proof ARN must equal both the authoritative mapping ARN and the authenticated plan predecessor ARN.

Rollback ARN is derived from the same authenticated current plan predecessor and must equal `beforeArn` exactly; family and ARN syntax checks are structural defenses only.

## Upstream contract references

- AWS ECS task lifecycle: https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-lifecycle-explanation.html
- AWS `DescribeServices`: https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_DescribeServices.html
- HashiCorp Terraform JSON format: https://developer.hashicorp.com/terraform/internals/json-format
- HashiCorp Terraform state: https://developer.hashicorp.com/terraform/language/state

AWS documents `PROVISIONING`, `PENDING`, `ACTIVATING`, `RUNNING`, `DEACTIVATING`, and `STOPPING` as task lifecycle states. The repository additionally records every observed non-`RUNNING`/`PENDING` task in `transitionalTasks`; that is an `OBSERVED_REPOSITORY_CONTRACT` and is validated as part of the same predecessor-reference closure.
