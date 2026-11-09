# Reviewed frontend CLI activation

This reusable route deploys a signed frontend image after the reviewed CLI tooling is merged into protected `main`. A fresh, signed current-source image authorization and the existing source-impact classifier must prove that any changes after image publication are confined to release-control or documentation files. Application, SQL, RLS, IAM, Terraform, and unknown paths stop image reuse. A newly published current-source frontend image has no source gap. The route does not deploy the backend or run Terraform.

The current production target is ECS service `mscqr-frontend-servi-euw2`, task family `mscqr-frontend`, with rolling ECS deployment. The live predecessor, backend revision and digest, signed web authorization file hash, and database probe file hash must all match the independently reviewed package. The operator is exactly `mscqr-ops-admin`. GitHub's protected `production` environment publishes the approval package only; it has no AWS credentials or ECS update step. The repository permits a recorded self-review by its configured reviewer, so the review event is independent of the CLI command but does not prove a different person approved it.

## Preparation

1. Use a clean checkout of the merged protected main. Confirm the frontend and backend live task definitions, ECS 2/2 health, and predecessor revision. Preserve the predecessor task ARN for rollback.
2. Verify the intended web publication and immutable digest. Produce the canonical root-signed web image authorization for that image source and run with `scripts/aws/produce-production-web-image-evidence.mjs`. Its existing signed image authorization is an input to that **evidence producer only**; do not execute infrastructure convergence. Root KMS signing requires its separate approval. The signed file expires after 24 hours. Obtain a signed image authorization for the final protected-main tooling SHA; the CLI rejects a stale tooling-source authorization.
3. Preserve the successful read-only catalogue probe JSON and authenticated canonical requirements artifact reference for the frontend image source, the live backend source, and the live backend digest. The CLI checks the stopped ECS task, terminal CloudWatch evidence, canonical requirements and zero catalogue deltas. No migration is part of this route.
4. Calculate SHA-256 of the signed web authorization and probe files. Dispatch `.github/workflows/authorize-production-frontend-cli-activation.yml` on protected main with its ten exact inputs: tooling source SHA, frontend image source SHA and digest, live frontend predecessor ARN, live backend ARN/digest/source SHA, the two file hashes, and the authenticated current-source image-authorization artifact reference. Obtain the recorded `production` environment review. The package expires after 30 minutes and is one-use.
5. Download the authorization artifact as an authenticated `frontendCliAuthorization` reference using the existing app-only artifact reference contract. The CLI rechecks the GitHub run, actual review event, file hashes, root signature, publication provenance, ECR digest, cosign artifacts, database proof, AWS identity, live backend and frontend predecessor before its first S3 claim.

## Execution

Create an external mode-0700 journal directory. From the clean protected-main checkout, run:

```sh
node scripts/aws/run-production-frontend-cli-activation.mjs \
  --authorization-reference '<AUTHENTICATED_ARTIFACT_REFERENCE_JSON>' \
  --web-authorization /private/tmp/<approved>/web-image-authorization.json \
  --web-authorization-sha256 '<FILE_SHA256>' \
  --database-probe /private/tmp/<approved>/schema-probe-result.json \
  --database-probe-sha256 '<FILE_SHA256>' \
  --requirements-reference '<AUTHENTICATED_REQUIREMENTS_REFERENCE_JSON>' \
  --journal-dir /private/tmp/<private-frontend-journal> \
  --aws-profile mscqr-ops-admin
```

The CLI uses AWS commands through that named profile. A conditional S3 claim consumes the approval before ECS mutation. The existing journaled frontend state machine registers only the image successor, verifies task-definition readback, checks predecessor CAS, updates only the frontend service, waits for stability, verifies both running digests and ALB target health, and writes a durable completion receipt. CloudTrail records `RegisterTaskDefinition` and `UpdateService`.

If the command stops after the claim, **do not rerun it**. Preserve the journal and reconcile the exact native ECS/S3 state before requesting a fresh approval. The prior frontend task definition is the rollback reference. Rollback is a separate production operation subject to its existing authorization and ownership checks; this command does not perform an unapproved automatic rollback.

After success, verify public browser assets and the PR #811/#812 authentication and batch behavior with safe tests. Backend revision 44 must remain healthy. Printing authorization and P2028 incidents require separate evidence and are not closed by this frontend deployment.
