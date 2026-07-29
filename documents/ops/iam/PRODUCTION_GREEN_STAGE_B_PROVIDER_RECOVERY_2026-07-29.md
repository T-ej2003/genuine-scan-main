# Production Green Stage B provider recovery — 2026-07-29

## Exact correction

MSCQRProductionGreenStageBProviderRecovery default version is now v2. The
canonical SHA-256 is
c3f07b334b2dd362112736a6a1d3756bac3a85b3e0c35b00e71ff39e732ae2a7.

The prior live v1 policy is preserved in
[MSCQRProductionGreenStageBProviderRecovery-v1-live.json](./MSCQRProductionGreenStageBProviderRecovery-v1-live.json).
The reviewed v2 source is
[MSCQRProductionGreenStageBProviderRecovery-v2.json](./MSCQRProductionGreenStageBProviderRecovery-v2.json).

The only changes are:

1. The three exact CloudWatch Logs tagging resources now use the required
   trailing colon-star form.
2. A separate ecs:TagResource statement permits only the eleven reviewed
   task-definition family/revision patterns.

The global iam:ListAttachedRolePolicies statement and exact DynamoDB replay
table tagging statement are unchanged.

## Validation

- Access Analyzer policy validation returned zero findings.
- Exact request-tag context allowed all three log-group and all eleven
  task-definition tagging requests.
- Unrelated log groups/task-definition families and missing/wrong tags were
  denied.
- ecs:RunTask and ecs:UpdateService remain explicit denies; ECS service
  creation, task-definition deregistration, and DynamoDB data-plane/destructive
  actions remain denied.
- The attached live v2 document was fetched after creation and its canonical
  SHA-256 matched the reviewed source.

## Fresh Stage B plan — stop before apply

The MFA-backed release session was still
arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/abhi-phase3.
Terraform refreshed state and confirmed the four partial-apply additions are
present: the replay table and three candidate object-storage inline policies.

Saved plan: .terraform-plans/production-green-stage-b.tfplan

- 22 to add, 0 to change, 0 to destroy, 0 replacements
- 12 existing resources are no-op
- No ECS service/task run, database/secret-value, ALB, DNS, CloudFront, or
  traffic resource is planned.

The ordered address/action digest is
8e64ea891e4a189230cc176dc3eea323343a95ec251905b4c94398a3a0036af5.
Reproduce it with:

    terraform -chdir=infra/aws/terraform/production-green-stage-b show -json /private/tmp/genuine-scan-stage-b-aws/.terraform-plans/production-green-stage-b.tfplan | jq -c '[.resource_changes[] | {address, actions: .change.actions}] | sort_by(.address)' | shasum -a 256

Remaining additions, in canonical order:

1. aws_cloudwatch_log_group.stage_b["backend"]
2. aws_cloudwatch_log_group.stage_b["canary"]
3. aws_cloudwatch_log_group.stage_b["worker"]
4. aws_ecs_task_definition.candidate["backend"]
5. aws_ecs_task_definition.candidate["canary"]
6. aws_ecs_task_definition.candidate["worker"]
7. aws_ecs_task_definition.executor["full-rls-admin-bootstrap"]
8. aws_ecs_task_definition.executor["full-rls-admin-ownership"]
9. aws_ecs_task_definition.executor["full-rls-capability-preflight"]
10. aws_ecs_task_definition.executor["full-rls-role-provision"]
11. aws_ecs_task_definition.executor["full-rls-role-verify"]
12. aws_ecs_task_definition.executor["full-rls-rollback"]
13. aws_ecs_task_definition.executor["full-rls-runtime-policy"]
14. aws_ecs_task_definition.executor["full-rls-verification"]
15. aws_iam_role_policy.broker
16. aws_iam_role_policy.execution["backend"]
17. aws_iam_role_policy.execution["canary"]
18. aws_iam_role_policy.execution["executor"]
19. aws_iam_role_policy.execution["worker"]
20. aws_lambda_alias.reviewed
21. aws_lambda_function.broker
22. aws_lambda_permission.release_deployer

No Terraform apply was run after this recovery plan.

## Approved-plan apply attempt — stopped

The saved plan digest, caller identity, production workspace, and all plan
action constraints were revalidated immediately before apply. Terraform then
applied the exact saved plan without replanning.

The following resources completed before the stop:

- the three Stage B CloudWatch log groups;
- the four Stage B execution-role inline policies.

Terraform then reported that it could not read each newly registered ECS task
definition by ARN. This is an unexpected post-registration read failure, not a
permission change request. Per the stop rule, no retry, re-plan, IAM change, or
post-apply cloud inspection was performed. The final registration/state status
of the eleven task definitions and all downstream resources is therefore
unverified.
