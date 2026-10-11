# Protected approval verification after broker closure

The shared closure reader must supply both credential boundaries to `createBrokerKmsAuthorizationBoundary`: the production AWS reader for historical checker signatures and the canonical authenticated, read-only GitHub runner for protected-environment approvals. Omitting `githubRun` made schema-2 terminal receipts fail despite completed broker closure.

The reader now adapts `createProductionGithubCommandRunner` to the verifier's argument interface. The established runner restricts repository/API endpoints, separates GitHub credentials from AWS credentials, and supports exact workflow, artifact and approval readback. No approval, source, repository, run, digest or reviewer check is removed.

All consumers inherit the fix: Stage-B recovery preflight, approval input, checker attestation, rotation bootstrap, Full-RLS Release Gate, and security component-state commit. Historical schema-1 KMS-signed receipts keep their existing path. Completed CAS and Terraform reconciliation remain immutable and are never rerun to authenticate them.

Regression coverage uses the real protected-authorization ZIP verifier and canonical GitHub runner with mocked network/process boundaries. It exercises Stage-B recovery authentication and the Release Gate security-state handoff, plus missing evidence, wrong source/repository, failed workflow, missing/tampered approval and artifact substitution. Existing historical receipt tests remain required.

After merge, authenticate current protected main and the existing closure. Resume only incomplete Stage-B and release prerequisites through existing production approvals. Retain this consumer regression to catch omitted verifier dependencies before hosted execution; no new deployment abstraction is required.
