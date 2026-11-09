# Reviewed backend CLI activation

This route activates either the reviewed `cbbb353` backend candidate from revision 42 or the reviewed `bb9297` candidate from revision 43 after a protected GitHub `production` environment approval. The `bb9297` source range includes one authentication TypeScript file under `rls-waves`; it remains classified as RLS impact and is admitted only for this exact candidate and exact path. SQL, grants, migrations, other RLS paths, and unknown paths remain blocked. The revision 43 predecessor must carry the exact `cbbb353` ECR source tag. GitHub publishes the approval package only. The local command performs the current-source read-only database probe and, after it passes, uses AWS CLI to register an image-only task revision and update the existing backend service. It reuses the app-only ECS predecessor CAS, health, rollback, and audit state machine. Frontend and Terraform are untouched.

## Preconditions

1. Merge and review the CLI mechanism on protected `main`. Use a clean checkout at that exact HEAD. Image authorization must bind the exact candidate digest and pass its signature and 24-hour freshness checks. The historical `cbbb353` authorization cannot authorize the `bb9297` image.
2. Produce current-main database requirements and the current-main `-backend-only` probe image tag through their existing trusted producers. The candidate image must come from the authenticated four-image publication and match its root-signed authorization. The existing backend-only publication alone does not satisfy this route.
3. Read the current backend task definition. The approval must bind its exact ARN, the candidate source and digest, current-source requirements hash, and exact publication, signed image authorization, and requirements artifact references.
4. Dispatch `authorize-production-backend-cli-activation.yml` on `main` with those inputs. The `production` reviewer must approve the pending run. The workflow has no AWS credentials or ECS commands. Authenticate its successful run and `production-backend-cli-activation-authorization` artifact, then form the six-field compact artifact reference (`sourceSha`, `runId`, `runAttempt`, `artifactId`, `artifactDigest`, `fileSha256`). The authorization expires after 30 minutes.

The configured reviewer is currently GitHub user `T-ej2003`. The environment permits self-review but disables administrator bypass. A separate recorded approval event is mandatory; it does not prove review by a different person.

## Terminal execution

From the clean protected-main checkout, after the approval artifact exists:

```sh
activation_run_id=123456789 # replace with the approved authorization run ID
mkdir -m 700 "/private/tmp/mscqr-backend-cli-activation-${activation_run_id}"
node scripts/aws/run-production-backend-cli-activation.mjs \
  --authorization-reference '<authenticated six-field JSON reference>' \
  --aws-profile mscqr-ops-admin \
  --probe-aws-profile default \
  --journal-dir "/private/tmp/mscqr-backend-cli-activation-${activation_run_id}"
```

The command authenticates the actual GitHub approval and current environment rules, image signature and ECR digests, source impact, requirements, and exact live predecessor. A conditional S3 claim consumes the approval before it runs the bounded read-only catalogue probe. A probe failure consumes the approval and requires a new review. Only `MATCH` with zero deltas for the exact candidate image permits activation. Every activation state is journaled locally and to the versioned production receipt bucket before the next ECS write. The AWS execution identity must be exactly `mscqr-ops-admin`; root is not accepted for deployment.

The command registers only the existing backend task definition with its image digest changed, waits for ECS stability, verifies the running digest and backend release SHA, checks frontend reachability, and rolls back to the captured predecessor only when ownership of the candidate deployment is proven. On an ambiguous AWS response, preserve the journal and reconcile the exact live state before any retry. The previous task definition remains the rollback target. CloudTrail and the S3 journal are the deployment audit evidence.

After a healthy activation, verify both backend targets and the 2/2 service count, bound digest, PR #808 denial-correlation event availability, and a bounded HTTP 500 rate comparison. Do not manufacture an auth failure or claim the four manufacturer incidents resolved from deployment alone. Do not run a test label until authenticated access and connector session health are confirmed.

## Status

The `cbbb353` activation completed through this route and revision 43 is the current predecessor for `bb9297`. The `bb9297` activation has not been approved or executed. The command requires a fresh current-main source-bound database probe before any production update.
