# Component broker recovery successor

This transition is a one-time, governed repair from immutable broker generation `7/8/9` to `10/11/12`. It preserves the original `4/5/6 -> 7/8/9` reservation and closure as read-only historical evidence.

## Prerequisite evidence authority

The governed initial-activation reconciler installation adds `mscqr-production-broker-recovery-successor-evidence-reader`. Its OIDC session is restricted to protected `main`, workflow `.github/workflows/authorize-component-broker-recovery-successor.yml`, environment `production-component-broker-recovery-successor-evidence`, repository `T-ej2003/genuine-scan-main`, and the solo operator identity. The attached policy permits only `s3:GetObject` for:

- `mscqr/production/component-deployment-state/broker-policy-successor.json`
- `mscqr/production/component-deployment-state/identity-bootstrap.json`

It cannot list the bucket, write evidence, invoke Lambda, mutate IAM or DynamoDB, or assume another AWS role. Install it only through the existing root-authenticated initial-activation reconciler bootstrap and its governed Terraform installation. The operational runbook requires root MFA; the historical bootstrap source contract itself proves exact root identity and must not be described as source-enforcing MFA.

## Authorization and execution order

1. Configure the GitHub environment with reviewer `T-ej2003` (user ID `183396573`), self-review allowed, no admin bypass, and exact `main` custom-branch policy.
2. Dispatch the authorization workflow only after the evidence-reader installation is authenticated. The workflow reads the two exact historical objects, authenticates the first reservation and closure, and emits the bound authorization artifact for `7/8/9 -> 10/11/12`.
3. Execute `node scripts/aws/component-broker-recovery-successor-cli.mjs execute RUN_ID TRANSITION_ID` from the exact authorized protected source. This separate command requires the established root-MFA session path and publishes only versions `10`, `11`, and `12` before installing the exact successor policies and closing the second lineage record.
4. Resume partial-activation recovery only after the second closure authenticates. Recovery accepts immutable INSTALL version `10`; version `7`, `$LATEST`, aliases, and unqualified invocation remain invalid.

Do not reuse an authorization or transition after any durable reservation. Reconcile the exact second-successor journal before retrying a partial execution.

## Retirement

The evidence reader is temporary. It is eligible for removal only after both the `7/8/9 -> 10/11/12` second successor and the component-infrastructure partial-activation recovery are durably CLOSED and authenticated. Removal is not automatic and is never part of a failure path. It requires a fresh protected-source, deletion-only capability generation, explicit governance, and an exact reviewed plan covering only the role-policy attachment, managed policy, and role.
