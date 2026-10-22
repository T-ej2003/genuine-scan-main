# Production Release Train trusted-terminal bridge

Release Train remains the operator's GitHub Actions entry point. The trusted terminal performs the existing root, checker, and interactive MFA operations; GitHub receives no privileged terminal credential. Release Gate remains the deployment authority. This document describes the proposed implementation. It is not a production authorization.

## Before the workflow

1. Confirm protected main, the intended source SHA, ticket, rotation, image authorization, historical broker receipts, and all Stage B prerequisites independently. An approval for an earlier source SHA cannot be reused for a newer source.
2. Prepare the existing private legacy cutover inputs on the trusted terminal. Put a private JSON manifest in the existing Stage B private evidence directory. Its `commands` object contains the exact argument arrays for `root`, `runtime`, `adoption`, `successor`, and `operator`, validated by `production-release-bridge-manifest.mjs`. Keep the manifest at mode 0600. The manifest binds source, ticket, rotation, root nonce, every input path, and expected output paths. It does not contain a GitHub run ID or a release ID; the durable request supplies those after prerequisite convergence.
3. Compute the manifest digest using the repository's canonical `brokerDigest(JSON.parse(...))` implementation and record it. Do not use a raw file SHA-256 in the workflow input.
4. Start **Release Train** on the exact protected main SHA with `trusted_terminal_cutover=true`, `release_lifecycle=authenticated-initial-overlap`, `prerequisites_only=false`, the exact rotation, ticket, manifest digest, and existing signed image and runtime authorization transport. Approve the protected production environment through GitHub's established mechanism.

## Trusted-terminal action

When Release Train prints the durable request's release ID, run ID and attempt, use the exact protected-main checkout and private manifest on the trusted terminal:

```sh
node scripts/aws/run-production-release-terminal-bridge.mjs \
  --manifest /private/path/to/bridge-manifest.json \
  --release-id <request-release-id> \
  --run-id <release-train-run-id> \
  --run-attempt <release-train-run-attempt>
```

The helper authenticates the immutable request, actual GitHub environment approval, protected source, manifest, and local prerequisite files. It displays the release and signer identities, requires the operator to type the rotation ID, performs read-only runtime preparation before root issuance, then uses the existing root, checker, and MFA-backed verifier scripts. The helper takes an exclusive local `lockf` lock and a write-once coordinator claim. Its local private owner file permits the same terminal to resume after interruption while another terminal identity is rejected. Keep that file; deleting it can make recovery fail closed.

Root KMS Sign, adoption Sign, and successor Sign each have a write-once dispatch claim and captured native result. A lost Sign response without a durable result is `OUTCOME_UNKNOWN`; stop and obtain separately authorized recovery. The helper never issues another signature based on a timeout. Root age remains 900 seconds. Read-only preparation happens before issuance, and the helper stops before the final direct root-age verifier if the 120-second reserve is exhausted. Runtime materialization is authenticated and reused on retry. The verifier-owned operator is claimed before invocation; a later attempt may finalize complete local readiness without rerunning the operator, including after root expiry, but incomplete readiness requires native AWS reconciliation.

Release Train polls the encrypted evidence store, validates KMS signatures and native evidence, dispatches rotation-overlap Release Gate, authenticates its receipt and live state, dispatches the normal Gate, verifies RLS, backend, frontend, post-activation smoke and component state, then writes and reads back `RELEASE_COMPLETE`. A green child run without those proofs is insufficient.

## Recovery and stop conditions

Rerun Release Train for the same exact source, ticket, rotation, and manifest digest after a failed hosted run. The coordinator and write-once records determine the checkpoint. The same terminal can resume a pending request while it is valid and root evidence remains fresh. If a request expires before any KMS Sign dispatch, a new approved Release Train invocation can create the next authorization round. A prior operator dispatch with complete authenticated readiness can be finalized without repeating native cutover mutations. A missing Sign result, expired root before the final direct verifier, or incomplete operator output requires separate reconciliation and authorization; do not automatically sign or run the operator again. A changed protected-main head, conflicting claim, invalid receipt, unverified child Gate, or unmatched live ECS state must stop the workflow.

Do not use GitHub run conclusion as an AWS mutation receipt. Do not use the disabled conditional Stage B lane. Do not place root credentials, checker credentials, MFA secrets, or verifier STS sessions in GitHub secrets or artifacts.

## Review boundary

This code has not been exercised against production. Before a Phase 3 invocation, the exact merged SHA, IAM/KMS permissions, trusted-terminal identity, current approvals, historical receipts, and runtime materialization window must be revalidated. Native mutation ambiguity and failed child Gate recovery must be covered by tests and a clean exact-head review before this implementation is considered ready to merge.
