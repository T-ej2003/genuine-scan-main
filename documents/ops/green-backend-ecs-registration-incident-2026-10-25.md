# Green backend registration failure, 25 October 2026

## Authenticated boundary

Release Gate run `40222912210` checked out protected main `63cc01f1ce595ce666634a57fa80e239f4a31de6` for ticket `CHG-20261025-006`. The green recovery executor derived its candidate from task definition `mscqr-production-rls-green-backend-candidate:24` and replaced only the backend image with digest `sha256:05b1c44bf31449d77510dd21915b1f7e0cd1437969258386033b3c1b846a8164`. The signed candidate contained `tags: []`, matching the ECS readback. The executor submitted that empty list to `RegisterTaskDefinition`; ECS rejected it with `ClientException: Tags can not be empty.`

The durable S3 journal contains `BACKEND:PREDECESSOR`, `BACKEND:REGISTER:INTENT`, and `BACKEND:REGISTER:DISPATCH`, committed at 18:50:02, 18:50:35, and 18:51:33 UTC. It contains no registration completion, service update, or recovery completion. CloudTrail records one rejected registration at 18:51:34 UTC and no `UpdateService` event in the run window. A subsequent native readback shows the backend service still on revision `:24`, desired 2, running 0, pending 0. The latest active family revision, `:34`, predates this run and belongs to a different release. These facts establish that this run did not register or activate the replacement candidate. The dispatch claim remains immutable; do not replay it under the old operation identity.

## Corrected request contract

The signed candidate and its fingerprint retain `tags: []`. The single green recovery registration serializer omits the `tags` field only when the authenticated list is empty; it preserves valid nonempty tags and rejects malformed tags or response-only fields. The executor validates the exact serialized JSON with the AWS CLI ECS input model against a loopback endpoint before claiming registration dispatch, and validates it again in read-only certification. The native write still uses the existing single-attempt AWS runner and durable journal.

The actual prior candidate file, SHA-256 `883388add4fa32115af5a03f291fc088ad93fdb18933b7687fc2c7b84c11c6a2`, passed the corrected serializer and CLI model without AWS network access. The serialized request omitted only empty tags; its digest, task role, and execution role matched the signed candidate.

The downstream service update uses fixed `--cluster`, `--service`, and the journaled registered revision, with AWS CLI retries disabled. Native stabilization checks the exact revision, two healthy tasks, their image digests, and unchanged service configuration before the public readiness and component-state CAS checks. No additional malformed request was confirmed in this reachable path. A workflow contract test also now renders GitHub's `inputs.release_mode` expression before feeding the normal-release shell to local Bash; the prior test attempted to execute the raw Actions expression and failed outside GitHub.

## Recovery boundary

This source correction requires a reviewed merge to a new protected-main SHA. Reconcile the old immutable dispatch journal read-only, then obtain new source-bound ticket, image, runtime, compatibility, operator, and protected-environment evidence according to the existing green backend recovery contract. Database compatibility run `40222320585` passed all six domains for the old source, but its time-limited verdict cannot authorize a later dispatch. The existing one-routine database repair is complete and must not be repeated. No ECS, IAM, or database mutation is authorized by this document.
