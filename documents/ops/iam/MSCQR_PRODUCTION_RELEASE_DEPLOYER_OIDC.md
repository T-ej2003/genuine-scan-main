# Production Release Gate OIDC identity

Release Gate uses only
`arn:aws:iam::368992683803:role/mscqr-production-release-deployer` for its
environment-bound production job. The workflow does not accept a role ARN from
dispatch inputs, repository variables, environment variables, or secrets, and
it has no static AWS credential fallback.

The source trust policy is
[`MSCQR_PRODUCTION_RELEASE_DEPLOYER_TRUST_POLICY.json`](./MSCQR_PRODUCTION_RELEASE_DEPLOYER_TRUST_POLICY.json).
It preserves the MFA-gated bootstrap-operator handoff and adds one GitHub OIDC
statement restricted by exact equality to:

- provider `arn:aws:iam::368992683803:oidc-provider/token.actions.githubusercontent.com`;
- audience `sts.amazonaws.com`;
- subject `repo:T-ej2003/genuine-scan-main:environment:production`.

The subject is GitHub's default subject for a job bound to the `production`
environment. It intentionally does not combine the environment subject with a
branch subject. Protected deployment-branch rules and required environment
review remain GitHub-owned gates.

After protected merge, an authenticated administrator must compare the live
role trust with this source, publish this exact trust document through the
governed IAM path if it differs, and read it back before Release Gate is
dispatched. The legacy `github-actions-mscqr-deploy` role is not a valid Release
Gate principal and is not changed or deleted by this contract.
