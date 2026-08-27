# MSCQR AWS credential provenance

Every production AWS composition root selects one credential source before it spawns an AWS-capable child. Selection is never inferred from `AWS_PROFILE`, a default profile, or ambient credentials.

| Boundary | Credential source | Enforcement |
| --- | --- | --- |
| Local governed cutover, runtime preparation, Stage-B preflight/apply, release recovery | named profile | `mscqr-production-release-deployer`; session keys and profile/config overrides are removed before child execution. |
| Local root administrator preflight and pre-Stage-A checker-trust attestation | named profile | `default`; caller identity must then equal the reviewed root administrator identity. |
| Local independent-checker approval lifecycle | independently assumed checker session | the CLI must explicitly select `inherited-checker-session`; only the three session variables are forwarded, and caller identity is checked against the exact independent-checker role before signing or publication. |
| Local ECS Exec rotation verifier | independently assumed verifier session | the CLI must explicitly select `inherited-ecs-exec-verifier-session`; only the verifier STS session is forwarded, then the exact verifier role is rechecked before ECS reads or Exec. |
| GitHub `release-gate.yml` release operations | GitHub OIDC session | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and `AWS_SESSION_TOKEN` supplied by `configure-aws-credentials` are required; `AWS_PROFILE` and local config selection are removed. |
| GitHub production image-publisher workflows | workflow OIDC session | each workflow owns the role configured by `configure-aws-credentials`; no local release profile is selected. |
| Staging and DR workflows | workflow or explicitly validated staging profile | they are separate from production release-deployer composition and must retain their own source contract. |
| Unit tests | injected runner | tests must intercept AWS execution and may not execute a real AWS child process. |

The credential-source contract is implemented in `scripts/aws/production-credential-source-contract.mjs`. The release-gate workflow must pass `--credential-source github-oidc-release-deployer` to every MSCQR AWS CLI that runs after its OIDC configuration step. Local production operator commands must not use that value: they use the explicit named local release profile instead.

The direct production CLI roots are deliberately split by authority: root-admin evidence producers use named profile `default`; release planning, verification, and control-plane producers use `mscqr-production-release-deployer`; independent-checker approval producers require an inherited checker STS session; and the ECS verification CLI requires the separately derived verifier STS session. No production root may select a source implicitly or fall back from one source to another.

## Audited entrypoint inventory

The credential-source contract test inventories the complete executable AWS surface: production release/control-plane roots, production image-publisher shell roots, local root and independent-checker lifecycles, GitHub release/image OIDC workflows, and segregated staging and DR roots. The staging database-role controller remains under its existing `awsCliEnvironment()` staging contract; it is deliberately classified separately from production. The dependency-closure verifier is offline source inspection only. A new direct AWS subprocess in `scripts/aws/` must be classified by the test before it can land.

The resulting matrix is intentionally boundary-based rather than an ambient-profile list:

| Entry-point class | Explicit source | Credential substitution rejected |
| --- | --- | --- |
| governed local release/preparation/recovery | named `mscqr-production-release-deployer` profile | static session keys, default profile, EC2 metadata |
| local root preflight/attestation | named `default` profile plus exact root identity check | static session keys, default-profile override, EC2 metadata |
| local checker approval | inherited independent-checker STS session | all profiles and default profile |
| local ECS verifier | inherited ECS verifier STS session | all profiles and default profile |
| Release Gate and image workflows | `configure-aws-credentials` OIDC session | all profiles, local config selection, EC2 metadata |
| staging and DR | their separately validated staging/DR workflow or named-profile contracts | production release-profile composition |
| offline tests | injected executor only | any real AWS subprocess |

## Workflow roots

`release-gate.yml` is the production release OIDC root. After `aws-actions/configure-aws-credentials`, its AWS-capable MSCQR invocations explicitly select `github-oidc-release-deployer`; the exact session variables are retained and every profile-selection variable is removed. The production image workflows (`production-green-backend-image-publish.yml`, `production-green-stage-b-image-build.yml`, and `publish-ecs-images.yml`) are independent OIDC roots and never select a local release profile.

The DR and staging workflows are separate execution domains. Their scripts either run under the workflow OIDC session configured in that workflow or validate their documented staging profile before use. They do not compose through the production release runner.

## Offline tests

Test composition is injected-only. Tests intercept the child-process executor and use synthetic credential-shaped strings; no test is permitted to run an AWS child process. Composition tests cover the release-gate OIDC root, local named-profile root, root-admin profile root, independent checker session root, and verifier-session root.

The JIT verifier MFA code remains separate from AWS credential provenance. It is collected only at the verifier STS AssumeRole boundary and never enters runtime configuration, evidence, or a persistent environment.
