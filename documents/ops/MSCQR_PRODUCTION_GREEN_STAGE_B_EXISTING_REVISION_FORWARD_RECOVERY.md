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
state changed. A completed forward journal is replay-safe and performs no second import.

Use the existing Stage-B preflight and artifact contracts to create fresh bindings and image
authorization inputs. Store the forward journal and evidence in the private release-artifact
directory; never edit or reuse the legacy journal/evidence. Run with `--execute` only after the
reviewed production gates authorize the import. Stage-B refresh, plan, apply, approval, cutover,
and onboarding remain separate canonical phases after reconciliation.
