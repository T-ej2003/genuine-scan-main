# MSCQR Production CI/CD Phase 1: Read-only readiness

Phase 1 adds a GitHub Actions orchestration layer around the existing
repository-owned contracts. It does not deploy production and does not create
an AWS identity. The canonical local scripts remain authoritative.

## Current operator flow

1. Open **Actions → Production Deployment Readiness**.
2. Run it from protected `main` with the exact 40-character `origin/main` SHA.
3. The workflow checks out that SHA, fetches protected `origin/main`, and proves
   the checkout is complete and clean.
4. The fixed read-only orchestrator runs source guardrails, evidence and
   capability-contract verification, Stage-B pull-request closure, onboarding
   contract tests, typecheck, changed-file lint, and a diff check.
5. Inspect the bounded `mscqr-production-readiness-*` artifact.
6. Stop. The artifact's next boundary is human review and explicit Phase 2
   enablement.

The workflow has `contents: read` only, does not configure AWS credentials,
does not request GitHub OIDC, has no production environment, and contains no
mutation job. `MSCQR_DEPLOYMENT_MODE=read-only` is enforced by the executable
orchestrator; the fixed command set rejects mutation boundaries.

## Evidence and identity

The readiness artifact records the exact source SHA, source tree identity,
tooling SHA, optional image identity supplied by the runner, check statuses,
bounded output hashes, and the reason for a block. It never contains raw
command output, credentials, tokens, secrets, Terraform state, MFA material,
or signing material.

Tooling/source SHA and image-release SHA remain separate. Phase 1 does not
authorize or publish an image; image authorization remains the existing
source-bound contract and must be revalidated by the future production path.

## Existing writers and Phase 2 prerequisites

The canonical existing production writer is `release-gate.yml`, serialized by
the `production-deploy` concurrency group. `deploy-ecs-release.yml` is a
legacy direct writer with broad inputs and must be retired or constrained before
Phase 2 is enabled. `release-train.yml` dispatches gates but is not itself the
deployment writer.

Before Phase 2 adds a mutation job, a separate reviewed change must:

- define and apply a dedicated production read-only OIDC role, then separately
  verify a dedicated mutation role;
- scope GitHub OIDC trust to this repository, the protected production
  environment, and `sts.amazonaws.com` (not `repo:*` or an unrestricted branch);
- configure the `production` environment with main-only deployment restrictions,
  required reviewers, and self-review/admin-bypass controls where the GitHub
  plan supports them;
- remove competing production writers and prove the single-writer invariant;
- preserve the recovery journal, source/image provenance, Terraform state,
  approval, MFA, RLS, tenant-isolation, QR, printer-trust, and rollback
  contracts;
- prove read-only readiness, mutation-role least privilege, rollback/recovery,
  and ambiguous-write fail-closed behavior.

The existing `production-stage-b-image-publish` OIDC role is an ECR image
publisher only. It must not be reused for production infrastructure access.
No environment settings or IAM resources are changed by this Phase 1 PR.
