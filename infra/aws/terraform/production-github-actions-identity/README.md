# Production GitHub Actions identities

This isolated root source-manages two distinct GitHub OIDC roles:

- `mscqr-production-github-actions-readonly` for read-only production preflight.
- `mscqr-production-github-actions-mutation` for the canonical `release-gate.yml`
  mutation path only.

It never manages the human MFA-backed `mscqr-production-release-deployer`, the
image-publisher role, GitHub environments, the OIDC provider, ECS services, or
Terraform application state.

The root also imports the historical `github-actions-mscqr-deploy` role and
replaces its web-identity trust with an explicit deny while retaining
`prevent_destroy`. Its old attached permissions are therefore inert; a later
apply must be reviewed as the retirement boundary before CI mutation is used.

The mutation role attaches the existing reviewed Stage A/Stage B capability
policies. It is a separate principal, with a separate caller mode and exact
GitHub production environment context. The human role remains assumable only
by the MFA-gated bootstrap operator.

Before any apply, verify the `production` environment remotely has required
reviewers and exactly the `main` deployment branch policy. The repository
workflow performs this read-only check, but cannot configure the environment.

Do not apply this root until the dedicated CI caller mode, capability graph,
OIDC trust, environment configuration, rollback, and emergency-access evidence
have passed independent review.
