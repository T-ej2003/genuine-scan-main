# Production ECR image protection — Milestone 1

Status: source implementation only. No production policy, IAM, alarm, EventBridge rule, or ECS resource changes are authorized by this document.

## Why this change exists

At the 2026-10-26 audit, `mscqr-backend` and `mscqr-web` had an ECR lifecycle rule that expires images beyond the newest 120, regardless of tags. `mscqr-worker` had no live lifecycle policy, while Terraform declared that same unsafe rule. The registered worker image was around rank 1,243. The original backend outage proved that a task definition can outlive its image. The exact deletion mechanism remains unproven.

The source change removes automatic lifecycle policies from the Terraform root, adds a repository policy that denies image deletion, repository deletion, lifecycle-policy creation, and archiving, and makes both image publishers verify these controls before publishing. Image retirement is **disabled**. Administrators with permission to remove a repository policy remain a trust boundary; CloudTrail and monitoring detect changes but do not make that boundary impossible.

AWS lifecycle rules have no general “exclude these digests” operation. A `tagStatus:any` rule evaluates even tagged production images. A retirement tag on a multi-tag image can select the protected image. The safe Milestone 1 choice is no automatic expiration. Storage is therefore not yet bounded by automated retirement. A future retirement lane requires a complete authorization and concurrency contract, a cooling period, a fresh protected inventory, and lifecycle preview before any deletion.

## Source and control map

| Control | Source | Effect after separately approved rollout |
| --- | --- | --- |
| ECR lifecycle and deletion guard | `infra/aws/terraform/main.tf` | Backend/worker policy resources removed; backend, web, and worker repository deny policies installed |
| Publisher guard | `scripts/aws/apply-ecr-repository-controls.sh`, `scripts/aws/verify-production-ecr-repository-protection.mjs` | Manual and Stage B publishers fail closed if a lifecycle policy exists or the deny guard is absent |
| Stage B least privilege | `infra/aws/terraform/production-green-stage-b-image-publisher/permissions-policy.json` and publisher boundary | Publisher retains image upload and readback; loses lifecycle and repository-setting writes |
| Legacy manual publisher | `production-ecr-monitor.tf` | Adds only `GetRepositoryPolicy` and explicit denies for image deletion, lifecycle writes, repository deletion and archival on the three exact repositories; normal image upload remains allowed |
| Normal deployment | `.github/workflows/production-deploy.yml`, normal-deployer policy | Checks backend/web protection before publication and again before activation; existing exact-digest activation checks remain |
| Independent digest monitor | `production-ecr-image-monitor.yml`, `production-ecr-image-monitor.mjs`, `production-ecr-monitor.tf` | Quarter-hourly OIDC job checks ECS services/deployments/tasks, component state, normal receipt, historical worker `:4`, open green recovery journal and ECR digests; CloudWatch alarms use the existing production SNS topic |
| Change events | `production-ecr-monitor.tf` | EventBridge uses an exact-rule, same-account target role to publish ECR deletion and repository-control events to the existing topic with bounded, nonsecret payloads |

The inventory deduplicates repository/digest pairs while preserving reasons, owners, source SHAs, task definitions and operation IDs. It marks retirement eligibility `DISABLED`. An unreadable authoritative source is `UNKNOWN`, never healthy. `CRITICAL` means an active digest is missing; `HIGH` means a rollback, worker, or pending digest is missing. Repository-control drift is `WARNING`.

The monitor covers the known live normal receipt and green recovery journal. Stage B authorization artifacts outside that journal are **not yet enumerated by this scheduled monitor**. The blanket repository deny and absence of lifecycle policies still protect those images from ordinary ECR deletion/expiration, and the existing Stage B authorization verifies the exact digest before activation. Do not use this inventory to authorize retirement. The registered worker `:4` is an explicit reviewed retention dependency, not a rule that retains every historical task definition.

## Safe rollout after merge — separate approval required

The 2026-10-26 starting references are backend `sha256:5a84bcf035c0d73435b87f14b90ead02185f93e236af85716a187e7b13168694` on task definition `:37`, frontend `sha256:9a398bd9f98fe2e8ff3623ca8c1a5d1d5976f5f45ffa6354b4ac956a7a031906` on `:22`, and worker `sha256:be4724777b5c51557e5c61256e421db32bc1974645b8c549c914f8ca69c048c5` on `:4`. Reauthenticate these and all newer references before applying anything. At the audit, backend and web had seven-day untagged plus newest-120-any expiration; worker had no live policy. A fresh lifecycle preview and Terraform-state read are required for rollout because those observations can change.

1. Authenticate new protected main, account `368992683803`, region `eu-west-2`, current ECS and DynamoDB generation. Read back all active, pending, rollback, worker and open-journal digests. Confirm each exact digest with ECR `DescribeImages`. Record the results outside the repository.
2. Inspect Terraform state ownership and a saved plan. Require the plan to remove only the backend lifecycle policy, avoid installing a worker lifecycle policy, add three exact repository guards, the read-only monitor role, two EventBridge rules and four alarms. Reject any ECS, task, repository, tag, image or unrelated state mutation.
3. Obtain the approved infrastructure change and preview the **current** backend/web lifecycle policies with ECR lifecycle preview. If a preview selects a protected digest, treat it as urgent exposure; do not apply another expiring policy. Preview is an AWS operation and was not run during this source-only assignment.
4. Remove the unsafe backend policy through the approved Terraform plan. The web lifecycle policy is not Terraform owned; the authorized infrastructure operator must separately execute a reviewed `DeleteLifecyclePolicy` for `mscqr-web`, then authenticate `LifecyclePolicyNotFoundException`. Worker must remain without a lifecycle policy. Removing expiration only reduces exposure; no replacement policy is installed.
5. Apply the reviewed repository guards and monitor IAM/alarm/EventBridge resources through the existing Terraform governance. Include the exact-rule EventBridge target role and verify its `sns:Publish` permission. Apply the separately governed Stage B publisher policy/boundary and normal-deployer policy updates before expecting their workflows to pass the new readback guard. Include the narrow legacy publisher read policy. No publication workflow should run in the gap between source merge and those live controls.
6. Read back repository policies and prove they deny the four named ECR actions. Simulate the exact publisher and monitor principals for their scoped reads/pushes; verify publisher `PutImage` remains allowed and `BatchDeleteImage`/`PutLifecyclePolicy` remain denied. Verify OIDC trust binds the monitor to protected main and its exact workflow.
7. Run the monitor via an approved nondeploying workflow dispatch and verify exact digest findings and all four CloudWatch metric streams. Confirm the existing SNS subscription is still confirmed. Independently verify alarm and EventBridge message delivery with an approved harmless test event or alarm-state test; source code and a confirmed subscription alone are not delivery proof. Check that the alarm clears after a healthy sample.
8. Check `GetLifecyclePolicy` returns not-found on all three repositories and that the guarded publisher and normal deployment preflight pass. Preserve the saved plan, AWS readbacks, IAM simulation, monitor result, alarm receipt and approval as rollout evidence.

If a Terraform apply or CLI response is lost, read the native ECR/IAM/CloudWatch state and the Terraform state before any retry. An ambiguous write is not permission to replay. To roll back the monitor, remove its schedule/alarms only after restoring an equivalent independent check; do **not** restore the old count-based lifecycle policy. If a repository guard blocks a necessary emergency action, require a separate reviewed break-glass authorization, exact digest inventory and audit trail before changing the guard.

## Known limits and next engineering step

This milestone intentionally does not delete images or provide bounded storage. It does not authenticate every possible external administrator/SCP path or prove future alert delivery before rollout. The S3 journal reader is linear in retained journal objects; if the recovery journal grows materially, add a source-authenticated open-operation index rather than skipping older objects. The next engineering milestone should define approved rollback sets and a serialized, cooling-period retirement transaction that proves absence from ECS, component state, all open journals and Stage B authorization immediately before any image deletion.

## Hostile review record

The final source review challenged an active image at ranks 121 and 1,243, multi-tag images, manifest-list children, an unreadable repository policy, loss of the monitoring AWS response, publisher authorization, and EventBridge delivery. Count-based expiration is removed; a parent manifest and each child digest are checked; repository read failure reports `UNKNOWN`; missing metrics also alarm; the event targets use an exact-rule publish role. The remaining unproved boundary is live alert delivery, which rollout step 7 must test. The scheduled inventory does not independently enumerate Stage B artifacts outside the green recovery journal, and retirement remains disabled because that inventory cannot safely authorize deletion.
