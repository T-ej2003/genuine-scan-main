# Green backend compatibility verifier recovery: image tag mismatch

On 2026-10-25, protected compatibility run `40150522078` registered verifier task definition `:27` and converged its exact launcher policy, then stopped before recording a verifier execution journal. Its failed-run artifact `12582194557` authenticates both completed operations. Protected recovery run `40151064100` adopted them without another ECS registration or IAM write, but stopped before verifier task dispatch.

The recovery CLI called `authenticateProtectedMainBackendImage` in its normal app-only mode, which requires the `<source>-backend-only` ECR tag. The signed unavailable-green-backend preparation explicitly uses the exact `<source>` tag. ECR readback showed the approved digest under that exact source tag. The helper already enforces both tag contracts; the recovery caller omitted the sealed preparation's `unavailable` mode.

The correction passes `preparation.unavailable === true` to the existing helper. It preserves account, repository, source tag, digest, failed-run journal, protected-environment, and live ECS checks. It does not alter IAM, register another task definition, run a database migration, or deploy the backend. The existing recovery entry point can authenticate the old registration and launcher policy after this source correction merges, subject to fresh protected approval and its live-state checks.

The failed runs do not prove current database compatibility or backend availability. Before dispatching backend health recovery, obtain a successful read-only verifier receipt on the protected source, then reauthenticate the recovery image and all fresh deployment approvals. Preserve both failed-run journal artifacts; do not rerun their completed writes.
