# Normal production deployment

After the one-time component-state bootstrap, an ordinary backend or frontend PR is merged to `main`. GitHub Actions classifies the affected live component, builds its immutable image, deploys it, verifies health and authenticated smoke checks, rolls back automatically on failure, and records only the components that are actually live.

Approve the protected GitHub `production-normal-deploy` environment if prompted. It is reserved for `.github/workflows/production-deploy.yml` and must retain independent approval. No Codex session, Stage-B authorization, KMS evidence, JSON artifact construction, digest copying, Terraform command, or ECS command is part of a normal application release.

Security/infrastructure changes use the stronger reviewed lane. Recovery uses its dedicated recovery lane.

Backend and frontend state keep two source identities. `sourceSha` authenticates the image currently running with its digest and task definition. `establishedThroughSha` records the protected-main revision through which deployment or recovery was completed and is the baseline for the next normal change range. Normal deployment advances both to its candidate; historical-image recovery preserves the image source and advances only the authenticated reconciliation baseline.

Overlap and cleanup rotations commit the verified backend identity and security identity together. The terminal checks the deployment result against fresh ECS/ECR reads, retaining the image source separately from the rotation revision. A mismatch leaves both component records unchanged.

Legacy backend-health recovery records only the canonical `mscqr-backend` target after validating recovery evidence and fresh task/digest readback. Its artifact source and completed-recovery revision remain separate. This does not widen the green-family app-only activation boundary; legacy-to-green migration still belongs to the stronger lane.

Successful recovery/rotation terminals also atomically record their source and evidence identity in `completedEmergencyWork` in the same component-state item. Normal preparation uses these operation-specific completions only for the operation's explicit source paths in a lagging range. Later edits, unrelated emergency code, and unrelated security work still require the stronger lane. Bootstrap and normal releases cannot create these completions; no operator action is added to routine deployment.

## One-time bootstrap

Before the first normal deployment, create the protected `production-component-state-bootstrap` GitHub environment with the same independent-approval rule as production, then run **Bootstrap Production Component Deployment State** from protected `main`. The workflow reads the current backend and frontend ECS/ECR identities, proves their protected-main source tags, initializes each reconciliation baseline to that proven source, and conditionally creates the single state record. It rejects an existing record and never uses workflow history as deployment state.

## Troubleshooting

- A normal workflow that fails after a service mutation rolls the exact authenticated predecessor back and preserves its automatic journal artifact.
- A workflow that reports unknown or drifted live state stops without forcing a service update; use the reviewed recovery lane to reconcile that component.
