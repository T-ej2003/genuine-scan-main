# Production Green Stage-B recovery and deployment closure

This source-only closure records the executable audit for the backend
task-definition recovery incident. It does not authorize production execution.

| Step | Identity | Required action boundary | Bound inputs | Retry / fail-closed rule |
|---|---|---|---|---|
| Protected checkout and image authorization | Administrator / release tooling | Git and ECR read | exact protected SHA and immutable digest | reject dirty, stale, or mismatched evidence |
| Canonical backend recovery | Release deployer | `ecs:ListTaskDefinitions`, `DescribeTaskDefinition`, exact backend `RegisterTaskDefinition`/`TagResource`, exact `PassRole`, exact S3 state/lock access | exact family, source SHA, image, fingerprint, lineage, serial | never adopt `:6`/`:7`; newest canonical revision resumes, any other newer revision fails closed |
| State reconciliation | Release deployer | exact Terraform state remove/import through the recovery adapter | backend candidate address only | state lineage, serial and snapshot must match each checkpoint |
| Refresh, plan and reference audit | Release deployer / administrator | Terraform read, planned provider actions, IAM simulation | fresh source/image/state bindings | unknown check, path, reference or capability fails closed |
| Stage-B apply and readback | Release deployer | reviewed saved-plan actions only | approved saved plan and signed preflight | no ad-hoc apply; post-apply no-op/readback required |
| Artifact, inventory and approval | Checker | KMS/signing and exact approval-secret publication | fresh source, image, state and evidence hashes | release deployer cannot read/write approval secret |
| Runtime, verifier and cutover | Verifier / release deployer | canonical broker, rotation and ECS Exec boundaries | fresh runtime graph, approval and image bindings | verifier MFA is the human boundary; no manual task registration/service update |
| Post-cutover and onboarding | Canonical probes | read-only health, RLS, tenant, public-verification checks | deployed source/image provenance | a failed required probe blocks onboarding |

## Closure findings

1. Recovery required `ecs:ListTaskDefinitions` but the release policy and
   capability graph omitted it. The policy permits only that AWS-required
   wildcard read in `eu-west-2`; the command fixes the family itself.
2. Backend recovery tags include `MSCQRExecTarget=production-backend`. The
   broad provider tag statement cannot be widened, so the backend moved to a
   dedicated exact tag statement in the existing task-definition-registration
   policy.
3. The journal counted registration before discovery. Version 2 distinguishes
   actual completed attempts from ambiguous outbound delivery and refuses a
   second registration after ambiguity.
4. Recovery now rejects a noncanonical Terraform root, uninitialized backend
   metadata, or non-default workspace before any mutation-capable adapter.

All later command surfaces already had source/image/approval binding and
fail-closed gates. Their required operator identities and writes remain
unchanged. The merged policy must be revalidated against the live release role
by the existing administrator/release preflight before recovery is executed.
