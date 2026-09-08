# Production backend failed-recovery log diagnostic

This capability is intentionally fixed to recovery run `34223529621`, task definition `mscqr-backend:51`, log group `/ecs/mscqr-backend`, and the eight source-authenticated failed task streams encoded in `production-backend-log-diagnostic.mjs`.

1. Dispatch `authorize-production-backend-log-diagnostic.yml` from the exact protected `main` SHA and obtain an independent `production` environment approval. Its job has only `actions: read` and `contents: read`; `actions: read` is required to authenticate the actual run approval. The one-day workflow artifact contains a 30-minute authorization.
2. Refresh and authenticate the exact account-root administrator profile used only for the authorization journal and temporary IAM install/revocation. `mscqr-production-bootstrap-mfa` is an MFA `sts:GetSessionToken` session for the IAM user `mscqr-production-bootstrap-operator`; it is not an administrator role and must not be supplied as the diagnostic administrator. The independent `mscqr-production-independent-checker` role remains the only CloudWatch Logs reader.

   ```sh
   aws login --profile default
   aws sts get-caller-identity --profile default --region eu-west-2 --output json --no-cli-pager
   aws sts get-caller-identity --profile mscqr-production-independent-checker --region eu-west-2 --output json --no-cli-pager
   ```

   The first identity must be exactly `arn:aws:iam::368992683803:root`; the second command performs the configured checker-user MFA/role chain and must return `arn:aws:sts::368992683803:assumed-role/mscqr-production-independent-checker/<session>`. Then run `production-backend-log-diagnostic.mjs` with `--admin-profile default`, `--reader-profile mscqr-production-independent-checker`, the authorization run coordinates, and new private state/evidence paths outside the repository. Every diagnostic AWS subprocess uses the canonical sanitized named-profile runner: alternate credential files, ambient sessions, role/container providers, endpoint and CA overrides, and metadata selectors are removed before either profile is used.
3. Before IAM installation, the command conditionally creates the authorization-bound S3 reservation under `production-backend-log-diagnostic/<transaction-identity>/reservation.json`. The bucket, keys, AES256 encryption, `If-None-Match: *`, two journal actions, and call ceilings are signed into the authorization. A reservation blocks every later use of that authorization, regardless of machine or local output paths.
4. The command installs one exact inline policy, performs bounded IAM policy readback, reads each exact named stream with bounded CloudWatch calls, persists only bounded redacted excerpts and hashes, removes the policy, and performs bounded absence readback.
5. After authenticated revocation, it conditionally creates one immutable terminal journal record. `COMPLETE` binds the evidence hash and the exact final AWS call census. Any post-reservation failure records `FAILED_OR_INDETERMINATE` when the terminal write is available; neither terminal state permits replay.
6. If execution is interrupted or revocation cannot be authenticated, do not read again. Revoke the exact inline policy `mscqr-backend-recovery-34223529621-log-read` from `mscqr-production-independent-checker` through a separately reviewed recovery action and authenticate absence.

The policy uses the AWS-supported backend log-stream ARN namespace for `logs:DescribeLogStreams` and exact log-stream ARNs for `logs:GetLogEvents`. It expires at the authorization deadline and grants no Secrets Manager, SSM, ECS, IAM, Logs Insights, or CloudWatch Logs write action. Local state/evidence files are operational outputs only; the S3 reservation is the durable replay boundary.

## Signed production call contract

| API | Maximum attempts | Purpose |
| --- | ---: | --- |
| `sts:GetCallerIdentity` | 2 | Authenticate the administrator and independent reader principals. |
| `iam:GetRolePolicy` | 13 | One absence precheck, up to six install readbacks, up to six revocation readbacks. |
| `iam:PutRolePolicy` | 1 | Install the exact temporary log-read policy. |
| `iam:DeleteRolePolicy` | 1 | Revoke the exact temporary policy. |
| `logs:DescribeLogStreams` | 13 | Up to six attempts for reader-policy convergence, then one exact lookup for each remaining stream. |
| `logs:GetLogEvents` | 8 | One non-paginated, bounded request for each authorized stream. |
| `s3:GetObject` | 2 | Exact readback of the reservation and terminal journal objects. |
| `s3:PutObject` | 2 | Conditional creation of the reservation and terminal objects. |

The maximum write count is four: one IAM install, one IAM revocation, and two conditional S3 journal writes. Every attempted call is counted before invocation; no retry repeats a mutation.
