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

The repository-approved durable store is the existing protected production
artifact bucket. The release-deployer conditionally creates exactly one object
under `production-dual-slot-rebaseline-evidence/<rotationId>/<executionSourceSha>/<authorizationSha256>/<evidenceSha256>.json`.
That immutable coordinate is the retrieval contract; there is no `latest`
pointer, list operation, GitHub Actions republishing hop, overwrite, or delete
capability. The producer sends `If-None-Match: *`, then verifies the exact
encrypted object bytes by readback before reporting success.

The object contains one canonical JSON bundle: manifest, preparation,
completion, and rotation bindings. The resolver reads only its deterministic
coordinate, requires the exact canonical bytes, hashes those retrieved bytes,
and validates every transition binding before consumption.

It never contains the material journal. The local canonical producer reads
that private journal only to bind its canonical journal SHA-256 and its exact
write identities into the manifest. This preserves recovery provenance without
persisting JWT material, private keys, secret values, credentials, or a
replayable secret journal in GitHub.

Produce and conditionally persist the non-secret bundle from authenticated
private inputs. Do not hand-author it or recover from an undocumented local
file:

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

node scripts/aws/persist-production-dual-slot-rebaseline-durable-evidence.mjs \
  --source-sha <current-protected-source-sha> \
  --input <private-non-secret-submission> \
  --profile mscqr-production-release-deployer
```

Durable publication is not permission to write secrets, alter labels, prepare
a rotation, register a task definition, or update a service. A later recovery
must resolve the object through
`resolveProductionDualSlotRebaselineDurableEvidenceArtifact()` and still
validate it against the independently authenticated authorization and live
state.
