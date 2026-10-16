# MSCQR c0 verifier and rotation recovery — 16 October 2026

Protected application source: `c0eb77a67f1e6a4934c0561fb88e012ba4be7605`.

## Database verifier

The protected backend-image publisher run [38839070272](https://github.com/T-ej2003/genuine-scan-main/actions/runs/38839070272) published the source-bound `-backend-only` image at `sha256:e9a31a42df262559c3a1a854d41f0915ff95ed0257892fe391343ecf92a6fd9f`. Its source-label, vulnerability, embedded-secret, SBOM, signature, attestation, and immutable-digest checks passed. The run then failed while formatting its GitHub artifact reference: `upload-artifact@v7` supplied a bare 64-character artifact digest and the final step required the `sha256:` prefix. The image publication is a real ECR mutation; the workflow did not finish successfully.

The protected, read-only verifier preparation run [38839537520](https://github.com/T-ej2003/genuine-scan-main/actions/runs/38839537520) failed before registering or launching a verifier task. The exact fail-closed check pins the backend session-risk source file to SHA-256 `13fd24e7427f4e2cb91b6629d5b34a485ae22c8902133442c471fa8270a7c8c9`. The signed application image comes from `05653f44d82c0731b89a7a4a5a36098fc4f6c3de`, whose file is `03b8314582903b3ee209f2e6f760beddde1bec318701860d8a599fff7bd01a0e` after the reviewed environmental-MFA change in PR #611. The source still uses an 85-point default block threshold and routes environmental risk through the existing MFA path. The verifier must retain exact reviewed-source hash checking for both versions.

No PostgreSQL catalogue verification has run. The database and RLS verdict remains **unknown**. After the source corrections merge, publish the new protected-main verifier image through the same governed workflow, prepare the restricted verifier, and run its read-only catalogue workflow. Do not infer compatibility from CI or the image build.

## Rotation continuation

The preserved prepared rotation state for `rotation-20260913011819-98b062c4` has phase `overlap-deploy-required`, source and overlap deployment `0e98970b536a2414324fd64776bc7e32acf604cd`. The current-source initial-overlap gate requires both fields to equal its exact authorized source. The existing initial-migration source-advance bridge applies only before a prepared state exists. Running a new prepare for c0 would encounter populated previous slots and must not be used to relabel or repeat the historical rotation.

A safe successor contract must create a **new** source-bound state and preserve the original bytes. It must authenticate the predecessor state and configuration, protected-main ancestry, live Secrets Manager slot/version identities, exact rotation and image release, current signed approval, and a unique predecessor digest before any MFA or AWS write. It must prove restart and duplicate-invocation behavior and remain valid for a future protected-main tooling SHA. No such contract is present in c0, and no overlap readiness receipt or Release Gate result has been produced.

## Deployment boundary

The application image digests and prepared service-equivalent task definitions remain preserved under `~/Library/Application Support/MSCQR/production-continuation-2026-10-15/direct-readiness-c0eb77a/`. Backend/frontend deployment remains blocked until the restricted database verdict and authenticated rotation readiness satisfy the existing Release Gate. Do not register or update ECS application services on the basis of this document.
