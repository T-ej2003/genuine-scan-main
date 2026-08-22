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

## Bootstrap-safe rollout

The tracked rollout manifest starts as `PENDING_LIVE_CONVERGENCE`. In that
state every Release Gate mode exits before `configure-aws-credentials`; merging
the convergence tooling cannot strand the existing administrator path or make
an unready OIDC attempt.

From a fresh, clean protected-main checkout, the root administrator runs:

```sh
npm run production:release-oidc-trust -- \
  --mode converge \
  --admin-profile <authenticated-root-administrator-profile> \
  --source-sha <protected-main-sha> \
  --output /private/path/release-oidc-convergence.json
```

The command accepts only the exact MFA-only current trust or the exact target
trust. It performs at most one `iam:UpdateAssumeRolePolicy`, preserves the MFA
statement, calls `iam:GetRole` again, and writes private evidence only after
the live readback is semantically identical to the reviewed source. Running it
against the exact target is a zero-write no-op. Any other principal, role,
trust, partial write, or failed readback stops without activation evidence.

The administrator then converts the hash-bound private evidence into the
tracked activation manifest:

```sh
npm run production:release-oidc-trust -- \
  --mode activate \
  --source-sha <protected-main-sha> \
  --evidence /private/path/release-oidc-convergence.json \
  --evidence-sha256 <file-sha256>
```

That one generated manifest change requires protected review and merge. Only
`LIVE_TRUST_READBACK_EXACT` enables Release Gate. This ordering keeps initial
trust convergence on the existing administrator boundary and prevents the new
OIDC role from attempting to grant its own first trust.

The legacy `github-actions-mscqr-deploy` role is not a valid Release Gate
principal and is not changed or deleted by this contract.
