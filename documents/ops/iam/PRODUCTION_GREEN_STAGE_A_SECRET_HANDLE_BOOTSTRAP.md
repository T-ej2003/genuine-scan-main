# Production green Stage A secret-handle IAM bootstrap

`MSCQRProductionGreenStageAReadOnlyCanarySecretCreate-v1.json` is the one-time,
exactly scoped managed policy document for the Stage A Terraform execution path.
It allows creation of only the Phase 4 read-only-canary handle request and the
dependent tag operation for that generated ARN family. It grants no secret-value,
lifecycle, KMS, IAM, STS, or list authority.

An authorized IAM administrator must attach this policy once to
`mscqr-production-release-deployer` through the approved IAM governance path.
If no non-root IAM administrator exists, root may be used only for this one IAM
bootstrap event. Root must not initialize, plan, or apply Terraform. Root
credentials must be removed from the active/default profile immediately after
the attachment is verified.

After the attachment is verified, obtain a fresh MFA-backed
`mscqr-production-release-deployer` session and verify its assumed-role identity
before running the already reviewed Stage A plan. The empty-handle guarantee is
provided by the Stage A Terraform resource, absence of any
`aws_secretsmanager_secret_version` or value-bearing field, and the exact saved
plan; IAM does not prove that a `CreateSecret` request lacks `SecretString` or
`SecretBinary`.
