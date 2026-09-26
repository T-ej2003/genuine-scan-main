# Stage-A temporary executor egress cleanup

The one-time Sep 16 canary DBA bootstrap created `sg-0c00eb354e0135478` and
`sgr-0b8c789e9694d4b77`, allowing TCP/443 from the Stage-A executor security
group to the temporary `ssmmessages` endpoint. This is not part of Stage-A's
Terraform desired state. Stage-A owns only the green database, its executor,
and the reviewed endpoint security groups described in
`infra/aws/terraform/production-green-stage-a/README.md`; Stage B consumes
those groups without changing their rules. Production ECS Exec uses the
separate MFA-gated verifier/operator boundary, not this canary endpoint.

Future Stage-A AWS endpoint access must first be explicitly reviewed and
represented in the Stage-A Terraform owner (its endpoint service set and
security-group rules); the current source does not include `ssmmessages` in
that set. Do not recreate this temporary rule manually.

## Exact cleanup boundary

The cleanup is a one-rule, one-authorization operation. First dispatch
`.github/workflows/authorize-stage-a-temporary-egress-cleanup.yml` against the
exact protected-main SHA with the approved change ticket and a verification
reference. The `production` environment approval is mandatory. Then run the
current-main executor locally with the documented `mscqr-production-root`
profile and the successful authorization workflow run id/attempt. The runner
also uses the release-deployer only for the Stage-A Terraform lock and the
immutable conditional journal record; Terraform is never run and that role
does not revoke security-group rules.

The executor rechecks the exact account, region, VPC, rule id, source and
destination groups, protocol, ports, description, destination ownership tags,
endpoint identity/state/attachment, active source-group ENIs, and active ECS
task network attachments while holding the Stage-A backend lock. It confirms
the current Stage-A source still has no dependency on the temporary endpoint.
It conditionally reserves the authorization before its final identical live
read and issues only `RevokeSecurityGroupEgress` for
`sgr-0b8c789e9694d4b77`. A changed target, incomplete read, consumed
authorization, or ambiguous result fails closed. The predecessor production
artifacts policy recovery remains a separate operation and does not authorize
this cleanup.

No production mutation is performed by authorization, validation, tests, or
PR development. After a separately approved execution, independently verify
that the exact rule is absent, then discard the prior Stage-A plan and prepare
a fresh plan. The normal Stage-A drift classifier remains strict; this
runbook does not suppress arbitrary security-group drift.
