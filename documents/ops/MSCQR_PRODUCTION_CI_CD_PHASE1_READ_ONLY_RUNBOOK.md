# MSCQR Production CI/CD Phase 1: Read-only readiness

Phase 1 adds a GitHub Actions orchestration layer around the existing
repository-owned contracts. It does not deploy production and does not create
an AWS identity. The canonical local scripts remain authoritative.

## Current operator flow

1. Open **Actions → Production Deployment Readiness**.
2. Run it from protected `main` with the exact 40-character `origin/main` SHA.
3. A trusted `main` bootstrap checkout fetches `origin/main` and proves the
   requested SHA is exactly that full SHA before the requested tree is checked
   out or any repository code/dependency lifecycle runs.
4. The fixed read-only orchestrator runs source guardrails, evidence and
   capability-contract verification, Stage-B pull-request closure, onboarding
   contract tests, typecheck, changed-file lint, and a diff check.
5. Inspect the bounded `mscqr-production-readiness-*` artifact.
6. Stop. The artifact's next boundary is human review and explicit Phase 2
   enablement.

The workflow has `contents: read` only, does not configure AWS credentials,
does not request GitHub OIDC, has no production environment, and contains no
mutation job. `MSCQR_DEPLOYMENT_MODE=read-only` is enforced by the executable
orchestrator; the fixed command set rejects mutation boundaries. Changed-file
lint is enforcing with `ENFORCE_LINT_CHANGED=true` and uses `HEAD^` as the
exact-commit comparison base, which remains valid for merge commits because the
repository computes a merge base before diffing. The evidence
`sourceTreeSha256` is a SHA-256 digest of canonical tracked paths, modes, and
blob content digests; it is not Git's SHA-1 tree object ID.

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
the `production-deploy` concurrency group. `deploy-ecs-release.yml` is now a
fail-closed disabled tombstone; it cannot configure AWS or mutate ECS.
`release-train.yml` dispatches gates but is not itself the deployment writer.

The reviewed production writer identity migration is source-controlled by
`documents/ops/iam/MSCQR_PRODUCTION_RELEASE_DEPLOYER_TRUST_POLICY.json` and
`scripts/aws/production-release-oidc-contract.mjs`. Live IAM must converge to
that exact source before Release Gate is dispatched. The retained prerequisites
are:

- preserve the MFA-backed bootstrap path while allowing only the exact
  environment-bound GitHub OIDC subject to assume
  `mscqr-production-release-deployer`;
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
