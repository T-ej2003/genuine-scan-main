# Production evidence continuity

## Root-drop chain of custody

`produce-production-root-drop-evidence.mjs` signs one canonical schema-v2
payload. In addition to the root caller, account, region, source, nonce, and
freshness fields, its signed bytes contain the exact rotation ID, image
authorization SHA-256, successor-recovery authorization SHA-256 (or explicit
`null` for a non-recovery rebaseline), administrator evidence file SHA-256,
and administrator signature file SHA-256. The cutover bootstrap independently
verifies the administrator signature and compares every one of those values
to its authenticated inputs before accepting the root-drop signature.

The root-only command requires these values explicitly:

```sh
npm run stage-b:produce-root-drop-evidence -- \
  --source-sha <protected-source-sha> --rotation-id <rotation-id> \
  --image-authorization-sha256 <authorization-sha256> \
  --successor-recovery-authorization-sha256 <successor-authorization-sha256|none> \
  --administrator-evidence-sha256 <administrator-evidence-file-sha256> \
  --administrator-signature-sha256 <administrator-signature-file-sha256> \
  --profile <explicit-root-profile> --output <private-root-drop-evidence>
```

The caller must not substitute a prior root-drop artifact. Schema-v1 evidence
is intentionally rejected for a current continuation.

The runtime bootstrap also requires the administrator evidence signature file
as a separate private input (`--iam-evidence-signature`); it verifies that
signature before it hashes and cross-binds the root-drop payload.

## Durable rebaseline evidence

The repository-approved durable store is a protected GitHub Actions artifact
named `production-dual-slot-rebaseline-durable-evidence`, produced only by
`.github/workflows/persist-production-dual-slot-rebaseline-evidence.yml`.
Its deterministic retrieval coordinate is its protected workflow run ID and
attempt. The resolver authenticates the workflow repository, path, event,
source SHA, run attempt, artifact digest, exact archive entries, file hashes,
and every transition binding before consumption.
The publishing workflow also rejects a submission unless its `sourceSha`
equals the protected source SHA authenticated by that same workflow run.

The artifact contains exactly:

- `manifest.json`
- `preparation.json`
- `completion.json`
- `rotation-bindings.json`

It never contains the material journal. The local canonical producer reads
that private journal only to bind its canonical journal SHA-256 and its exact
write identities into the manifest. This preserves recovery provenance without
persisting JWT material, private keys, secret values, credentials, or a
replayable secret journal in GitHub.

Produce the non-secret submission from authenticated private inputs, then send
its exact base64 bytes to the protected workflow. Do not hand-author the
submission or recover from an undocumented local file:

```sh
node scripts/aws/produce-production-dual-slot-rebaseline-durable-evidence.mjs \
  --source-sha <current-protected-source-sha> --mode successor-recovery \
  --authorization-workflow-run-id <authorization-run-id> \
  --authorization-workflow-run-attempt <authorization-run-attempt> \
  --preparation <private-preparation> --material-journal <private-journal> \
  --completion <private-completion> --rotation-bindings <private-bindings> \
  --authorization <authenticated-successor-authorization> \
  --recovery-envelope <authenticated-envelope> \
  --image-authorization <authenticated-image-authorization> \
  --output <private-non-secret-submission>
```

The protected workflow is an evidence-publication boundary, not permission to
write secrets, alter labels, prepare a rotation, register a task definition,
or update a service. A later recovery must resolve the artifact through
`resolveProductionDualSlotRebaselineDurableEvidenceArtifact()` and still
validate it against the independently authenticated authorization and live
state.
