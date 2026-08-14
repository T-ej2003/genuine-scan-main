# MSCQR Production Green Stage-B Existing-Revision Forward Recovery

This runbook covers the narrow recovery state where the historical registration journal is not
resumable, but the authoritative remote Terraform state and live ECS state prove that the
already-validated canonical revision `:9` exists and is the only eligible replacement.

The mode is `EXISTING_REVISION_ZERO_REGISTRATION_ADOPTION`. It starts from the current remote
Terraform state (lineage and reviewed serial), a complete ACTIVE ECS census, the exact `:9` ARN,
fresh task-definition readback, and current protected-main/image-reuse provenance. It is a new
incident and does not claim continuity of the legacy recovery journal.

The forward adapter has no ECS registration, deregistration, service-update, Terraform state-push,
or Terraform apply capability. Its only mutation seam is one canonical Terraform import of the
exact `:9` ARN. Before import it binds the current state, census, image authorization, source
provenance, semantic fingerprint, and incident identity. After import it verifies lineage, the
expected serial transition, exact `:9` ownership at the governed address, and that no unrelated
state changed. Both comparison states use the shared reviewed Terraform checkpoint normalizer,
limited to the approved Terraform-generated version and `check_results` metadata. The CLI validates
the reviewed S3 backend metadata and `default` workspace before
the first remote state pull and again immediately before import; it also re-reads the remote state
at that boundary. The journal remains `IMPORTING` until post-import state is verified and
deterministic evidence is durably written and read back. A completed forward journal is replay-safe
and performs no second import: its evidence is parsed, canonicalized, hash-checked against the
journal, and then treated as immutable. If the executor checkout advances after an import has
reserved the `IMPORTING` phase, replay is allowed only through the protected descendant path: the
original journal identity and image authorization remain unchanged, the original source is proven
an ancestor, and the new executor proves image-safe reuse; no new import capability is granted.
Once the journal is `COMPLETED` or `RECONCILED`, replay is terminal: a clean protected descendant
may validate the recorded incident and immutable evidence without re-running current-HEAD image
freshness checks or writing any journal/evidence bytes.

Image authorization verifies its own signed source identity, then the forward contract separately
proves the authenticated authorization-source-to-current-tooling transition and the
image-release-to-current-tooling transition through the reviewed image-reuse report. A valid
two-SHA reuse is explicit; an unrelated or image-affecting transition fails closed.

Use the existing Stage-B preflight and artifact contracts to create fresh bindings and image
authorization inputs. Before the import boundary, the evidence, journal, bindings, and image
authorization paths must be distinct, private, regular files in the reviewed private directory;
an in-progress evidence file is accepted only for authenticated replay finalization. Store the
forward journal and evidence in the private release-artifact
directory; never edit or reuse the legacy journal/evidence. Run with `--execute` only after the
reviewed production gates authorize the import. Stage-B refresh, plan, apply, approval, cutover,
and onboarding remain separate canonical phases after reconciliation.
