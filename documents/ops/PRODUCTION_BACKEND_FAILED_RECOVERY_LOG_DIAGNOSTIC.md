# Production backend failed-recovery log diagnostic

This capability is intentionally fixed to recovery run `34223529621`, task definition `mscqr-backend:51`, log group `/ecs/mscqr-backend`, and the eight source-authenticated failed task streams encoded in `production-backend-log-diagnostic.mjs`.

1. Dispatch `authorize-production-backend-log-diagnostic.yml` from the exact protected `main` SHA and obtain an independent `production` environment approval. The one-day workflow artifact contains a 30-minute authorization.
2. Run `production-backend-log-diagnostic.mjs` with the authorization run coordinates, a governed administrator profile, the MFA-gated `mscqr-production-independent-checker` reader profile, and new private state/evidence paths outside the repository.
3. The command installs one exact inline policy, reads each named stream once, persists only bounded redacted excerpts and hashes, removes the policy, and authenticates absence before reporting `COMPLETE`.
4. If execution is interrupted or reports a revocation failure, do not read again. Revoke the exact inline policy `mscqr-backend-recovery-34223529621-log-read` from `mscqr-production-independent-checker` through a separately reviewed recovery action and authenticate absence.

The policy permits only `logs:DescribeLogStreams` on the exact backend log group and `logs:GetLogEvents` on the eight exact streams. It expires at the authorization deadline and grants no Secrets Manager, SSM, ECS, IAM, Logs Insights, or CloudWatch Logs write action. State/evidence files prevent replay; a second source/run requires a source change and new authorization.
