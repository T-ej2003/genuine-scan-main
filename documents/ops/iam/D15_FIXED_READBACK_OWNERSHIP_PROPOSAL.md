# D15 fixed catalog readback: proposed non-Terraform ownership

Status: **review proposal only**. It does not authorize AWS or database mutation.
Approved application source: `d15b79e4779d64be4c6c7ec905caea1e91d410f2`.
Prepared executor source: `61e00958bf8f71c5beac727c3b5d5ba3dff8e533`.
Fixed SQL SHA-256: `039b8ef435bd62da82c01086116c6129049baa10f9873632087b40768597ef80`.

## Current ownership and required decision

The accepted [green activation decision](../../security/rls-program/PRODUCTION_RLS_GREEN_ACTIVATION_DECISION.md) assigns green database, IAM, network, secret and log resources to Stage A Terraform, and fixed task definitions and the broker to Stage B Terraform. It rejects direct `ecs:RunTask` because callers can override the command and environment. The [Stage A root](../../../infra/aws/terraform/production-green-stage-a/README.md) calls itself the only Terraform root for isolated green infrastructure. A source-controlled AWS CLI IAM bootstrap exists for the web release, but it requires Terraform import and a no-op plan; it is not an independent resource lifecycle. No approved D15 non-Terraform owner exists today.

The owner has prohibited Terraform source changes and Terraform execution for D15. The following exception must be reviewed and merged into the accepted ownership decision **before** any AWS or database write. Review by the sole accountable owner and automated technical checks is sufficient as a human process; separate AWS execution and checker/KMS identities remain mandatory. Do not infer approval from this proposal or from the owner's authorization to prepare it.

## Proposed isolated lifecycle

Use one source-controlled, named AWS CloudFormation stack for **new D15-only resources**. The stack, template digest, change set, execution identity, CloudTrail events, and cleanup receipt become its ownership record. AWS CLI executes only a reviewed change set from protected `main`; no manually assembled `create-*`/`put-*` sequence and no Terraform state import. The stack must fail on preexisting names, unsupported replacements, or drift. Updates must show an exact reviewed change set. Destruction is a separate reviewed operation after proving no task, evidence retention, or dependent resource remains. An ambiguous response requires read-only stack/resource reconciliation before retry.

Names and ownership must be disjoint from both canonical Terraform states and live resources. The stack may **reference**, but must not modify, the existing Stage A executor security group, private subnet IDs, VPC endpoints, RDS instance/SG, KMS approval key, or receipt bucket. Read both state object inventories and AWS resource metadata before the first change set; an inaccessible state or unresolved ownership collision blocks execution. The existing Stage A SG already has executor-to-database and endpoint egress and the database SG has ingress from that SG; verify these live rules before using them. Set `assignPublicIp=DISABLED`. No new security-group rule is proposed.

| Proposed stack-owned object | Exact boundary |
| --- | --- |
| `mscqr-production-d15-catalog-readback` ECS task family | One container, immutable `@sha256` image, `linux/amd64`, fixed entrypoint, no ECS Exec, no volumes or customer service attachment. Register/read back exact definition before activation. |
| `mscqr-production-d15-catalog-readback-task` IAM role | ECS task trust only; no AWS API permissions. A permissions boundary must prevent later broadening. |
| `mscqr-production-d15-catalog-readback-execution` IAM role | ECS task trust only; ECR pull of the exact repository, one exact D15 secret value, and `CreateLogStream`/`PutLogEvents` only in the D15 log group. No admin secret, KMS Sign, or unrelated secret access. |
| `mscqr/production/d15/catalog-readback-database-url` Secrets Manager secret | Generated credential for only `mscqr_prod_d15_catalog_read`; encrypted, scoped to execution role, rotation/recovery policy reviewed. Secret value never enters Git, template, CLI argv, task logs, or receipt. |
| `/ecs/mscqr-production/d15-catalog-readback` CloudWatch log group | Restrictive writer/read policies, retention and export receipt. The checker reads the exact task stream and signs its canonical digest. Verify whether the existing evidence bucket supports immutable retention before claiming it. |
| Fixed D15 launcher | A separate reviewed Lambda alias or equivalent broker is the sole `ecs:RunTask` principal. It verifies the short-lived source/SQL/database/image/KMS authorization, fixes cluster/task revision/subnets/SG, passes no command or secret overrides, sets `enableExecuteCommand=false` and `assignPublicIp=DISABLED`, and returns the task ARN. Its IAM can pass only the two D15 task roles. The caller receives invoke-only permission, never `ecs:RunTask` or `iam:PassRole`. |

The dedicated database login is **not** a CloudFormation resource. Provision it through a separately reviewed, fixed-purpose private bootstrap task using the RDS-managed administrator credential solely for this one role lifecycle. Its exact SQL, image, task definition, temporary admin-secret permission, KMS approval, audit and cleanup must be separately source-controlled and reviewed. Do not use the emergency bootstrap task, RLS canary, backend ECS Exec or an interactive DBA shell. If that bootstrap cannot be authorized, the D15 readback stack cannot be activated.

The role must be `LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS NOREPLICATION`, with no membership in application/owner/admin roles, no schema ownership, no DDL or customer-table privileges, and only catalog visibility needed by the fixed query. Verify its effective privileges as that role before the readback. PostgreSQL catalog visibility, including `pg_get_functiondef`, must be tested against the exact 18.4 package. A grant to a migration or install ledger is permitted only after proving it contains no customer rows; the fixed D15 SQL currently records ledger visibility and does **not** read migration rows.

## Execution and evidence gates

1. Review and merge the ownership exception plus complete CloudFormation template, launcher, bootstrap SQL/task, exact IAM policies, cleanup code, and hostile tests. Reauthenticate protected `main` and the executor image digest. The current `61e00958` commit is preparation, not a deployable production infrastructure package.
2. Authenticate a dedicated non-root CloudFormation execution principal and exact resource permissions. The current release-deployer is authenticated for reads, but `iam:SimulatePrincipalPolicy` is denied and no D15 create authority has been established. Do not use root or enlarge an unrelated role by convenience.
3. Read both canonical Terraform state inventories and live resources, prove no overlap, and review a source-bound change set with no replacement/deletion of shared resources. Preserve the stack's change-set and CloudTrail evidence.
4. Provision the fixed database login through the approved private bootstrap, verify no customer-row/data/DDL privilege, then create/activate the D15 stack. Do not populate the D15 secret or run the executor until the credential, task definition, role policies, network, logging and KMS key policy are independently read back.
5. Have the checker-only KMS principal sign the exact D15 authorization after verifying the owner's recorded approval, source, SQL hash, image, database role, task revision and expiry. Revalidate the Stage A-owned KMS key's purpose/policy before using it for D15; otherwise provision a purpose-specific key through the reviewed stack and update the pinned executor public key in a reviewed source change.
6. Invoke only the fixed launcher. The checker reads the exact ECS task/definition, CloudWatch stream and CloudTrail launch event, reconstructs complete catalog chunks, verifies zero exit code, and signs a source-bound receipt. Preserve the signed receipt and catalog evidence in restricted storage. Reject missing, reordered, truncated, stale or conflicting evidence.
7. Obtain the separate authenticated migration/rollback receipt required by `compare-production-printing-catalog.mjs`; the D15 catalog SQL alone cannot establish the 57 applied migration states or rollback compatibility. Only then run the comparator. No application deployment is covered by this approval.

Cleanup must stop if the task is running, the database role has unexpected grants/dependencies, or evidence retention is incomplete. A reviewed cleanup removes only the D15 stack and its dedicated database login/credential after receipt retention is proved; it never deletes shared Stage A/B resources, production services, customer data, or rollback images. A successfully executed readback is not a reason to erase its audit trail.

## Review outcome required before implementation

The accepted decision must explicitly authorize this separate D15 stack, its non-Terraform owner, the fixed DB bootstrap route, the KMS signing purpose, the exact non-root provisioner, and the cleanup authority. Until that change is merged and its complete implementation passes review, `EXECUTOR_DEPLOYED=NO` and `DATABASE_COMPATIBILITY=UNVERIFIED`.
